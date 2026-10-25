"""
송신 오케스트레이터 — 호스트에서 실험을 지휘한다 (Step 2 / P1 · E1).

호스트 Python 은 "지휘"만 한다. 실제 DB 조회와 HTTP 전송은 backend 의 netns 를
공유하는 사이드카(s2-sender)가 수행한다. 오케스트레이터는:
  1. 송신기 이미지를 빌드하고
  2. RunSpec 에 맞는 env 로 사이드카를 1회 실행하고
  3. 사이드카 로그에서 송신 메타데이터(SENDER_META)를 파싱하고
  4. Sink /stats 로 수신 결과를 읽어 교차검증한다 (E: 송신/수신 바이트·해시 일치)

Docker 가 필요한 부분(이미지 빌드/컨테이너 실행/Sink stats HTTP)은 얇은 래퍼로 두고,
Docker 없이도 검증 가능한 로직(env 구성·로그 파싱·교차검증)은 순수 함수로 분리했다.
런타임 실행 자체는 Docker 데몬이 있어야 하므로 이 환경에서는 UNVERIFIED.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from transfer_spec import RunSpec

SENDER_IMAGE = "s2-sender:latest"
BACKEND_CONTAINER = "leafy-backend"
SENDER_META_PREFIX = "SENDER_META "


@dataclass(frozen=True)
class SinkEndpoint:
    """Sink 의 호스트측 readout 주소(전송 경로가 아니라 집계 조회용 사이드 채널)."""
    name: str
    stats_url: str  # 예: http://127.0.0.1:8091


# ----------------------------------------------------------------------------- #
# 순수 로직 (Docker 불필요 — 단위 테스트 대상)
# ----------------------------------------------------------------------------- #

def build_sender_env(run: RunSpec, db_password: str, transfer_id: str,
                     db_host: str = "db", db_port: int = 5432,
                     db_user: str = "leafy", db_name: str = "leafy",
                     db_table: str = "leaked_users") -> dict:
    """RunSpec -> 사이드카 env. 비밀번호는 env 로만, GT 라벨(should_alert)은 넣지 않는다."""
    env = {
        "DB_HOST": db_host, "DB_PORT": str(db_port), "DB_USER": db_user,
        "DB_NAME": db_name, "DB_TABLE": db_table, "DB_PASSWORD": db_password,
        "SINK_HOST": run.destination.connect_host(),
        "SINK_PORT": str(run.destination.port),
        "TARGET_BYTES": str(run.transfer.target_bytes),
        "MODE": run.transfer.mode,
        "CHUNKS": str(run.transfer.chunks),
        "TRANSFER_ID": transfer_id,
        "RUN_LABEL": run.label,
    }
    if run.transfer.rate_bps:
        env["RATE_BPS"] = str(run.transfer.rate_bps)
    return env


def parse_sender_meta(logs: str) -> dict:
    """사이드카 stdout 에서 SENDER_META 줄을 찾아 파싱한다. 여러 개면 마지막 것."""
    found = None
    for line in logs.splitlines():
        line = line.strip()
        if line.startswith(SENDER_META_PREFIX):
            found = line[len(SENDER_META_PREFIX):]
    if found is None:
        raise ValueError("SENDER_META not found in sender logs")
    return json.loads(found)


def crosscheck(sender_meta: dict, sink_stats: dict) -> dict:
    """
    송신기가 보낸 것과 Sink 가 받은 것을 transfer_id 단위로 대조한다.
    각 연결에 대해 bytes/sha256 이 일치하는지 본다.
    """
    sent = {c["transfer_id"]: c for c in sender_meta.get("connections", [])}
    recv = {r.get("transfer_id"): r for r in sink_stats.get("receipts", [])}

    per_conn = []
    all_ok = bool(sent) and set(sent) == set(recv)
    for tid, s in sent.items():
        r = recv.get(tid)
        ok = bool(r) and s["bytes_sent"] == r["bytes_received"] and s["sha256"] == r["sha256"]
        all_ok = all_ok and ok
        per_conn.append({
            "transfer_id": tid, "match": ok,
            "bytes_sent": s["bytes_sent"],
            "bytes_received": (r or {}).get("bytes_received"),
            "sha_match": bool(r) and s["sha256"] == r["sha256"],
        })

    return {
        "ok": all_ok,
        "total_bytes_sent": sender_meta.get("total_bytes_sent"),
        "total_bytes_received": sink_stats.get("total_bytes"),
        "connections": per_conn,
    }


# ----------------------------------------------------------------------------- #
# Docker/HTTP 래퍼 (런타임 — Docker 데몬 필요, UNVERIFIED)
# ----------------------------------------------------------------------------- #

def _docker_client():
    import docker  # 지연 import — 테스트/비실행 경로에서 의존성 강제하지 않는다
    return docker.from_env()


def build_sender_image(context_dir: str, tag: str = SENDER_IMAGE) -> None:
    client = _docker_client()
    client.images.build(path=context_dir, dockerfile="sender/Dockerfile", tag=tag)


def _reset_sink(stats_url: str) -> None:
    import urllib.request
    req = urllib.request.Request(stats_url.rstrip("/") + "/stats", method="DELETE")
    urllib.request.urlopen(req, timeout=5).read()


def _read_sink(stats_url: str) -> dict:
    import urllib.request
    with urllib.request.urlopen(stats_url.rstrip("/") + "/stats", timeout=5) as resp:
        return json.loads(resp.read())


def run_transfer(run: RunSpec, db_password: str, transfer_id: str,
                 sink: SinkEndpoint, reset_sink: bool = True) -> dict:
    """
    사이드카를 1회 실행해 전송하고, Sink 수신 결과와 교차검증한다.
    반환: {run, sender_meta, sink_stats, crosscheck}. Docker 데몬이 있어야 한다.
    """
    client = _docker_client()
    if reset_sink:
        _reset_sink(sink.stats_url)

    env = build_sender_env(run, db_password, transfer_id)
    logs = client.containers.run(
        SENDER_IMAGE,
        network_mode=f"container:{BACKEND_CONTAINER}",
        environment=env,
        remove=True,
        stdout=True,
        stderr=False,  # 자격증명 노출 방지: stderr 는 반환 로그에 섞지 않는다
    )
    logs = logs.decode("utf-8") if isinstance(logs, (bytes, bytearray)) else str(logs)
    sender_meta = parse_sender_meta(logs)
    sink_stats = _read_sink(sink.stats_url)
    return {
        "run_label": run.label,
        "scenario": run.scenario,
        "variant": run.variant,
        "sender_meta": sender_meta,
        "sink_stats": sink_stats,
        "crosscheck": crosscheck(sender_meta, sink_stats),
    }
