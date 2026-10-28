"""
로컬 Docker 실행기 (Phase 2).

기존 ContainerActions 를 대체한다. 바뀐 점:
  - 모든 조치가 실행 뒤 docker inspect 로 상태를 다시 확인한다. 확인되지 않으면
    SUCCESS 를 쓰지 않는다 (이전 isolate 는 네트워크를 못 찾아도 성공이었다).
  - 네트워크 이름을 하드코딩하지 않는다. inspect 로 실제 연결을 읽고, 정책이 정한
    업무 네트워크만 끊고 관리 네트워크는 보존한다. 대상이 불명확하면 실행하지 않는다.
  - 가역 조치마다 복구 조치가 있다 (UNPAUSE/RECONNECT/UNTHROTTLE). 복구는 보존한
    증거(IP·alias·쿼터)로 원래 상태를 되돌린다.

Docker 데몬이 필요한 부분은 docker SDK 호출뿐이고, 판정 로직은 순수 함수로 분리해
Mock 으로 검증한다.
"""

from __future__ import annotations

import logging

from executor.base import (
    ISOLATE,
    PAUSE,
    RECONNECT,
    RESTART,
    THROTTLE,
    UNPAUSE,
    UNTHROTTLE,
    ExecutionResult,
    Executor,
    ExecutorError,
    blocked,
    failed,
    succeeded,
)

logger = logging.getLogger(__name__)

# THROTTLE 기본값: cpu_period 100ms 중 50ms -> 코어 0.5개
DEFAULT_CPU_PERIOD = 100_000
DEFAULT_CPU_QUOTA = 50_000


# ────────────────────────────────────────────────────────────────────────────── #
# 순수 로직 (Docker 불필요 — 단위 테스트 대상)
# ────────────────────────────────────────────────────────────────────────────── #

def parse_networks(inspect: dict) -> dict:
    """
    docker inspect 결과에서 네트워크 연결 정보를 뽑는다.
    복구에 필요한 것만 남긴다: 네트워크 ID·IP·alias.
    """
    nets = (inspect.get("NetworkSettings") or {}).get("Networks") or {}
    out = {}
    for name, cfg in nets.items():
        cfg = cfg or {}
        out[name] = {
            "network_id": cfg.get("NetworkID"),
            "ip_address": cfg.get("IPAddress") or (cfg.get("IPAMConfig") or {}).get("IPv4Address"),
            "ipam_ipv4": (cfg.get("IPAMConfig") or {}).get("IPv4Address"),
            "aliases": sorted(a for a in (cfg.get("Aliases") or []) if a),
            "mac_address": cfg.get("MacAddress"),
        }
    return out


def parse_resources(inspect: dict) -> dict:
    host = inspect.get("HostConfig") or {}
    return {
        "cpu_quota": host.get("CpuQuota"),
        "cpu_period": host.get("CpuPeriod"),
        "cpu_shares": host.get("CpuShares"),
        "memory": host.get("Memory"),
        "nano_cpus": host.get("NanoCpus"),
    }


def parse_state(inspect: dict) -> dict:
    state = inspect.get("State") or {}
    return {
        "status": state.get("Status"),
        "running": bool(state.get("Running")),
        "paused": bool(state.get("Paused")),
        "started_at": state.get("StartedAt"),
        "pid": state.get("Pid"),
    }


def matches(network_name: str, patterns) -> bool:
    """
    네트워크 이름 매칭. compose 프로젝트 이름이 붙으므로 접미사로도 맞춘다
    (`graduation-project_leafy-net` 은 `leafy-net` 과 일치).
    """
    name = (network_name or "").lower()
    for raw in patterns or ():
        p = str(raw).lower()
        if not p:
            continue
        if name == p or name.endswith("_" + p) or name.endswith("-" + p):
            return True
    return False


def select_isolation_networks(networks: dict, isolate_patterns, preserve_patterns):
    """
    끊을 네트워크를 고른다. 반환: (대상 목록, 보존 목록, 거부 사유 또는 None).

    규칙:
      - 정책이 격리 대상으로 지정한 네트워크만 끊는다.
      - 보존 목록(관리 네트워크)은 절대 끊지 않는다. 관리 통신 경로를 통째로
        막으면 복구 지시조차 닿지 않는다.
      - 양쪽에 모두 걸리면 불명확 -> 실행하지 않는다.
      - 끊을 대상이 없으면 실행하지 않는다 ("아무것도 안 끊고 성공" 금지).
    """
    targets, preserved, ambiguous = [], [], []
    for name in sorted(networks):
        is_target = matches(name, isolate_patterns)
        is_preserved = matches(name, preserve_patterns)
        if is_target and is_preserved:
            ambiguous.append(name)
        elif is_preserved:
            preserved.append(name)
        elif is_target:
            targets.append(name)
    if ambiguous:
        return [], preserved, f"ambiguous_network_classification:{','.join(ambiguous)}"
    if not targets:
        attached = ",".join(sorted(networks)) or "none"
        return [], preserved, f"no_isolatable_network:attached={attached}"
    return targets, preserved, None


def verify_isolated(networks_after: dict, isolated, preserved) -> tuple[bool, str]:
    """격리 후 상태 검증: 대상은 떨어졌고 보존 대상은 남아 있어야 한다."""
    still = [n for n in isolated if n in networks_after]
    if still:
        return False, f"still_attached:{','.join(still)}"
    lost = [n for n in preserved if n not in networks_after]
    if lost:
        return False, f"preserved_network_lost:{','.join(lost)}"
    return True, "disconnected:" + ",".join(isolated)


def verify_reconnected(networks_after: dict, expected: dict) -> tuple[bool, str]:
    """
    복구 후 검증: 원래 네트워크에 다시 붙었고 IP·alias 가 복원됐는지.
    IP 가 다르면 allowlist·Zeek 관측 기준이 바뀌므로 실패로 본다.
    """
    problems = []
    for name, want in expected.items():
        got = networks_after.get(name)
        if not got:
            problems.append(f"{name}:not_attached")
            continue
        want_ip = want.get("ipam_ipv4") or want.get("ip_address")
        if want_ip and got.get("ip_address") != want_ip:
            problems.append(f"{name}:ip {got.get('ip_address')}!={want_ip}")
        want_aliases = set(want.get("aliases") or ())
        if want_aliases and not want_aliases.issubset(set(got.get("aliases") or ())):
            problems.append(f"{name}:aliases_missing")
    if problems:
        return False, "; ".join(problems)
    return True, "reconnected:" + ",".join(sorted(expected))


def restorable(evidence: dict) -> tuple[bool, str]:
    """
    격리를 되돌릴 수 있는 증거가 있는지. IP 를 모르면 재연결 시 주소가 바뀌어
    기존 정책·관측 기준이 깨진다 — 그런 격리는 하지 않는다.
    """
    nets = (evidence or {}).get("networks") or {}
    if not nets:
        return False, "evidence_missing_networks"
    for name, cfg in nets.items():
        if not (cfg.get("ipam_ipv4") or cfg.get("ip_address")):
            return False, f"evidence_missing_ip:{name}"
    return True, "ok"


# ────────────────────────────────────────────────────────────────────────────── #
# Docker 실행기 (런타임)
# ────────────────────────────────────────────────────────────────────────────── #

class LocalDockerExecutor(Executor):
    name = "local_docker"

    def __init__(self, client=None, isolate_networks=(), preserve_networks=(),
                 cpu_quota: int = DEFAULT_CPU_QUOTA, cpu_period: int = DEFAULT_CPU_PERIOD):
        # Docker 클라이언트는 생성 시점에 만든다 (지연 생성 금지).
        #
        # 지연 생성은 위험하다: 테스트가 docker.from_env 를 import 시점에만 patch 하면,
        # 나중에 처음 접근할 때 patch 가 풀려 있어 실제 Docker 데몬에 붙는다. 그러면
        # Mock 으로 검증한다고 믿는 테스트가 실제 컨테이너를 재시작·격리한다
        # (개발 중 실제로 leafy-backend 가 격리됐다). 생성 시점에 묶어 두면 주입한
        # 클라이언트나 patch 된 from_env 가 그대로 유지된다.
        self._client = client if client is not None else self._connect()
        self.isolate_networks = tuple(isolate_networks)
        self.preserve_networks = tuple(preserve_networks)
        self.cpu_quota = cpu_quota
        self.cpu_period = cpu_period

    @staticmethod
    def _connect():
        import docker
        return docker.from_env()

    # ── Docker 접근 ───────────────────────────────────────────────────────────
    @property
    def client(self):
        return self._client

    def _container(self, target: str):
        try:
            return self.client.containers.get(target)
        except Exception as exc:
            raise ExecutorError(f"container_not_found:{target} ({exc})") from exc

    def _inspect(self, target: str) -> dict:
        container = self._container(target)
        attrs = getattr(container, "attrs", None)
        if attrs is None:
            raise ExecutorError(f"inspect_failed:{target}")
        # SDK 는 attrs 를 캐시하므로 조치 후 재조회 시 reload 가 필요하다.
        return attrs

    def _reload_inspect(self, target: str) -> dict:
        container = self._container(target)
        try:
            container.reload()
        except Exception as exc:
            raise ExecutorError(f"reload_failed:{target} ({exc})") from exc
        return container.attrs or {}

    # ── 증거 수집 ─────────────────────────────────────────────────────────────
    def snapshot(self, target: str) -> dict:
        inspect = self._inspect(target)
        return {
            "target": target,
            "container_id": inspect.get("Id"),
            "container_name": (inspect.get("Name") or "").lstrip("/"),
            "image": (inspect.get("Config") or {}).get("Image"),
            "state": parse_state(inspect),
            "networks": parse_networks(inspect),
            "resources": parse_resources(inspect),
            "executor": self.name,
            "available": True,
        }

    # ── 조치 ──────────────────────────────────────────────────────────────────
    def execute(self, action: str, target: str, evidence: dict) -> ExecutionResult:
        handler = {
            RESTART: self._restart,
            PAUSE: self._pause,
            UNPAUSE: self._unpause,
            ISOLATE: self._isolate,
            RECONNECT: self._reconnect,
            THROTTLE: self._throttle,
            UNTHROTTLE: self._unthrottle,
        }.get(action)
        if handler is None:
            return blocked(action, target, f"no_executor_for_action:{action}")
        try:
            return handler(target, evidence or {})
        except ExecutorError as exc:
            return failed(action, target, str(exc))
        except Exception as exc:   # Docker API 오류 등
            logger.error("[Executor] %s %s 실패: %s", action, target, exc)
            return failed(action, target, f"{type(exc).__name__}: {exc}")

    # RESTART — 비가역. 사후 상태만 확인한다.
    def _restart(self, target: str, evidence: dict) -> ExecutionResult:
        before = evidence.get("state") or parse_state(self._inspect(target))
        self._container(target).restart()
        after = parse_state(self._reload_inspect(target))
        if not after.get("running"):
            return failed(RESTART, target, f"not_running_after_restart:{after.get('status')}",
                          before=before, after=after)
        if before.get("started_at") and after.get("started_at") == before.get("started_at"):
            # 재시작했는데 기동 시각이 그대로면 실제로 재시작되지 않았다.
            return failed(RESTART, target, "started_at_unchanged",
                          before=before, after=after)
        return succeeded(RESTART, target, f"restarted (pid {after.get('pid')})",
                         before=before, after=after)

    def _pause(self, target: str, evidence: dict) -> ExecutionResult:
        before = parse_state(self._inspect(target))
        if before.get("paused"):
            return succeeded(PAUSE, target, "already_paused", before=before, after=before)
        if not before.get("running"):
            return blocked(PAUSE, target, f"not_running:{before.get('status')}", before=before)
        self._container(target).pause()
        after = parse_state(self._reload_inspect(target))
        if not after.get("paused"):
            return failed(PAUSE, target, f"not_paused_after_call:{after.get('status')}",
                          before=before, after=after)
        return succeeded(PAUSE, target, "paused (forensic freeze)", before=before, after=after)

    def _unpause(self, target: str, evidence: dict) -> ExecutionResult:
        before = parse_state(self._inspect(target))
        if not before.get("paused"):
            return succeeded(UNPAUSE, target, "not_paused_nothing_to_do",
                             before=before, after=before)
        self._container(target).unpause()
        after = parse_state(self._reload_inspect(target))
        if after.get("paused"):
            return failed(UNPAUSE, target, "still_paused", before=before, after=after)
        return succeeded(UNPAUSE, target, "unpaused", before=before, after=after)

    # ISOLATE — 업무 네트워크만 끊고 관리 네트워크는 보존한다.
    def _isolate(self, target: str, evidence: dict) -> ExecutionResult:
        networks = (evidence.get("networks")
                    or parse_networks(self._inspect(target)))
        ok, why = restorable({"networks": networks})
        if not ok:
            return blocked(ISOLATE, target, why, before={"networks": networks})

        targets, preserved, reason = select_isolation_networks(
            networks, self.isolate_networks, self.preserve_networks)
        if reason:
            return blocked(ISOLATE, target, reason, before={"networks": networks})

        disconnected = []
        for name in targets:
            net = self.client.networks.get(name)
            net.disconnect(target)
            disconnected.append(name)

        after = parse_networks(self._reload_inspect(target))
        verified, detail = verify_isolated(after, disconnected, preserved)
        if not verified:
            return failed(ISOLATE, target, detail,
                          before={"networks": networks}, after={"networks": after})
        return succeeded(ISOLATE, target,
                         f"{detail} (preserved: {','.join(preserved) or 'none'})",
                         before={"networks": networks}, after={"networks": after})

    # RECONNECT — 보존한 IP·alias 로 원래 상태를 되돌린다.
    def _reconnect(self, target: str, evidence: dict) -> ExecutionResult:
        expected = (evidence.get("networks") or {})
        if not expected:
            return blocked(RECONNECT, target, "evidence_missing_networks")

        current = parse_networks(self._inspect(target))
        todo = {n: cfg for n, cfg in expected.items() if n not in current}
        for name, cfg in todo.items():
            ip = cfg.get("ipam_ipv4") or cfg.get("ip_address")
            if not ip:
                return blocked(RECONNECT, target, f"evidence_missing_ip:{name}")
            net = self.client.networks.get(name)
            net.connect(target, ipv4_address=ip, aliases=list(cfg.get("aliases") or ()))

        after = parse_networks(self._reload_inspect(target))
        verified, detail = verify_reconnected(after, expected)
        if not verified:
            return failed(RECONNECT, target, detail,
                          before={"networks": current}, after={"networks": after})
        return succeeded(RECONNECT, target, detail,
                         before={"networks": current}, after={"networks": after})

    def _throttle(self, target: str, evidence: dict) -> ExecutionResult:
        before = evidence.get("resources") or parse_resources(self._inspect(target))
        self._container(target).update(cpu_quota=self.cpu_quota, cpu_period=self.cpu_period)
        after = parse_resources(self._reload_inspect(target))
        if after.get("cpu_quota") != self.cpu_quota:
            return failed(THROTTLE, target,
                          f"cpu_quota_not_applied:{after.get('cpu_quota')}!={self.cpu_quota}",
                          before=before, after=after)
        return succeeded(THROTTLE, target,
                         f"cpu_quota={self.cpu_quota}/{self.cpu_period}",
                         before=before, after=after)

    def _unthrottle(self, target: str, evidence: dict) -> ExecutionResult:
        """보존한 원래 쿼터로 되돌린다. 증거가 없으면 임의 값으로 덮지 않는다."""
        want = (evidence.get("resources") or {})
        if "cpu_quota" not in want:
            return blocked(UNTHROTTLE, target, "evidence_missing_resources")
        original_quota = want.get("cpu_quota") or 0      # 0 = 제한 없음
        original_period = want.get("cpu_period") or DEFAULT_CPU_PERIOD
        before = parse_resources(self._inspect(target))
        self._container(target).update(cpu_quota=original_quota, cpu_period=original_period)
        after = parse_resources(self._reload_inspect(target))
        if after.get("cpu_quota") != original_quota:
            return failed(UNTHROTTLE, target,
                          f"cpu_quota_not_restored:{after.get('cpu_quota')}!={original_quota}",
                          before=before, after=after)
        return succeeded(UNTHROTTLE, target, f"cpu_quota restored to {original_quota}",
                         before=before, after=after)
