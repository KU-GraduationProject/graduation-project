"""
Allowlist 정책 평가기 (P3) — 목적지 허용 여부 판정.

단일 정책 소스(aiops/policy/allowlist.yml)를 로드해, 관측된 네트워크 이벤트의
목적지가 인가된 것인지 판정한다. Loki Ruler 규칙 생성(rulegen.py)과 LLM Network
Context(network_section.py)가 같은 평가기를 써서 "규칙과 LLM 설명이 일치"하게 한다.

중요:
  - per-event 판정은 "목적지가 허용되는가"만 본다. 경보(공격 단정)는 비인가 + 전송량
    임계 초과를 함께 봐야 한다 (aggregate). "dst_service=unknown" 단독으로는 공격이 아니다.
  - ip:port(endpoint) 또는 service 라벨로 허용을 표현한다. 정상 내부 peer(db/minio/
    frontend)는 service 로 허용해 오탐을 막는다.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import yaml

DEFAULT_ALLOWLIST_PATH = os.getenv("ALLOWLIST_PATH", "/app/config/allowlist.yml")

MATCH_ENDPOINT = "endpoint"
MATCH_SERVICE = "service"


@dataclass(frozen=True)
class Decision:
    """
    authorized : 목적지가 Allowlist 에 의해 허용되는가
    applicable : 이 이벤트가 정책 판정 대상인가 (src 가 sources 에 속하는가)
    matched    : 매칭된 allow 항목 설명 (없으면 None)
    reason     : 사람이 읽는 판정 근거 (LLM/로그용, GT 라벨 아님)
    """
    authorized: bool
    applicable: bool
    matched: str | None
    reason: str


class PolicyEvaluator:
    def __init__(self, policy: dict):
        self._sources = list(policy.get("sources") or [])
        self._allow = list(policy.get("allow") or [])
        thresholds = policy.get("thresholds") or {}
        self.min_transfer_bytes = int(thresholds.get("min_transfer_bytes", 0))
        self.window = str(thresholds.get("window", "5m"))
        self._validate()

    # ---- 생성 ----
    @classmethod
    def from_file(cls, path: str | None = None) -> "PolicyEvaluator":
        path = path or DEFAULT_ALLOWLIST_PATH
        with open(path, "r", encoding="utf-8") as fh:
            return cls(yaml.safe_load(fh) or {})

    @classmethod
    def from_dict(cls, policy: dict) -> "PolicyEvaluator":
        return cls(policy)

    def _validate(self):
        if not self._sources:
            raise ValueError("allowlist: sources 가 비어 있다")
        for entry in self._allow:
            match = entry.get("match")
            if match == MATCH_ENDPOINT:
                if not entry.get("ip") or entry.get("port") is None:
                    raise ValueError(f"endpoint allow 는 ip/port 필요: {entry}")
            elif match == MATCH_SERVICE:
                if not entry.get("service"):
                    raise ValueError(f"service allow 는 service 필요: {entry}")
            else:
                raise ValueError(f"allow.match 는 endpoint|service: {entry}")

    # ---- 조회 ----
    @property
    def sources(self) -> list[str]:
        return list(self._sources)

    def service_allows(self) -> list[str]:
        """service 로 허용된 목적지 서비스 이름들 (LogQL 라벨 제외용)."""
        return [e["service"] for e in self._allow if e.get("match") == MATCH_SERVICE]

    def endpoint_allows(self) -> list[tuple[str, int]]:
        """endpoint 로 허용된 (ip, port) 쌍들."""
        return [(e["ip"], int(e["port"])) for e in self._allow if e.get("match") == MATCH_ENDPOINT]

    # ---- 판정 ----
    def evaluate(self, event: dict) -> Decision:
        """canonical network event -> Decision. 목적지 허용 여부만 본다(경보 아님)."""
        src = event.get("src_service")
        applicable = src in self._sources
        dst_service = event.get("dst_service")
        dst_ip = event.get("dst_ip")
        dst_port = event.get("dst_port")

        if not applicable:
            return Decision(True, False, None,
                            f"출발지 {src!r}는 정책 대상 아님")

        for ip, port in self.endpoint_allows():
            if dst_ip == ip and dst_port == port:
                return Decision(True, True, f"endpoint {ip}:{port}",
                                f"목적지 {ip}:{port} 는 인가됨")
        for svc in self.service_allows():
            if dst_service == svc:
                return Decision(True, True, f"service {svc}",
                                f"목적지 서비스 {svc} 는 정상 내부 통신")

        where = f"{dst_ip}:{dst_port}" + (f"({dst_service})" if dst_service else "")
        return Decision(False, True, None,
                        f"목적지 {where} 가 Allowlist 에 없음 (비인가 후보)")

    def is_authorized(self, dst_service=None, dst_ip=None, dst_port=None,
                      src_service=None) -> bool:
        return self.evaluate({
            "src_service": src_service if src_service is not None else (self._sources[0] if self._sources else None),
            "dst_service": dst_service, "dst_ip": dst_ip, "dst_port": dst_port,
        }).authorized

    def violation_reason(self, event: dict) -> str | None:
        """비인가면 근거 문자열, 인가/비대상이면 None."""
        decision = self.evaluate(event)
        return None if decision.authorized else decision.reason
