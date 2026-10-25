#!/usr/bin/env python3
"""
S2/C-a 시나리오 - 수신 Sink 서버 (P2)

Backend가 보낸 전송 파일을 받는 경량 HTTP 서버다. Sink A(허용 목적지)와
Sink B(비허용 목적지)는 같은 이미지를 역할만 다르게 띄운 것으로, 코드가 동일해야
"목적지 허용 여부"만 다른 대조 조건(E2)이 성립한다.

이 서버가 하는 일은 두 가지뿐이다.
  1. POST 본문을 끝까지 읽어 수신 바이트 수와 SHA-256 해시를 기록한다.
     (스트리밍 해시 — 10MB를 메모리에 통째로 올리지 않는다)
  2. GET /stats 로 그동안 받은 전송의 집계를 JSON으로 돌려준다. (검증기가 읽는다)

중요 — 이 서버는 자신이 공격을 받았다고 로그를 남기지 않는다.
시나리오의 핵심은 "프로그램의 자기보고"가 아니라 "Zeek가 관측한 실제 트래픽"으로
탐지하는 것이다(사용자 계획 §1). Sink의 수신 기록은 탐지 입력이 아니라, 전송이
실제로 도착했고 A/B가 같은 바이트를 받았음을 증명하는 검증용(E: payload hash 일치)이다.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SINK_ROLE = os.getenv("SINK_ROLE", "unknown")      # "A"(허용) / "B"(비허용)
SINK_NAME = os.getenv("SINK_NAME", "sink")
LISTEN_HOST = os.getenv("SINK_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("SINK_PORT", "8080"))

# 한 번에 읽는 청크 크기. 10MB 본문도 이 크기로 쪼개 읽어 스트리밍 해시한다.
_CHUNK = 64 * 1024


class Receipt:
    """한 번의 전송에 대한 수신 기록 (self-report 아님, 관측된 사실)."""

    __slots__ = ("seq", "received_at", "bytes_received", "sha256", "transfer_id")

    def __init__(self, seq, bytes_received, sha256, transfer_id):
        self.seq = seq
        self.received_at = datetime.now(timezone.utc).isoformat()
        self.bytes_received = bytes_received
        self.sha256 = sha256
        self.transfer_id = transfer_id

    def as_dict(self):
        return {
            "seq": self.seq,
            "received_at": self.received_at,
            "bytes_received": self.bytes_received,
            "sha256": self.sha256,
            "transfer_id": self.transfer_id,
        }


class SinkState:
    """수신 집계. 여러 요청이 동시에 와도 안전하도록 잠근다."""

    def __init__(self):
        self._lock = threading.Lock()
        self._receipts: list[Receipt] = []

    def record(self, bytes_received, sha256, transfer_id) -> Receipt:
        with self._lock:
            seq = len(self._receipts) + 1
            receipt = Receipt(seq, bytes_received, sha256, transfer_id)
            self._receipts.append(receipt)
            return receipt

    def snapshot(self) -> dict:
        with self._lock:
            receipts = [r.as_dict() for r in self._receipts]
        return {
            "role": SINK_ROLE,
            "name": SINK_NAME,
            "transfers": len(receipts),
            "total_bytes": sum(r["bytes_received"] for r in receipts),
            "receipts": receipts,
        }

    def reset(self) -> None:
        # 실험을 반복 실행할 때 이전 회차 수신 기록이 섞이지 않도록 비운다.
        with self._lock:
            self._receipts.clear()


STATE = SinkState()


class Handler(BaseHTTPRequestHandler):
    # 접속 로그를 stderr로만 보낸다(컨테이너 stdout 오염 최소화). 탐지 입력이 아니다.
    def log_message(self, fmt, *args):  # noqa: A003 - BaseHTTPRequestHandler 시그니처
        pass

    def _send_json(self, status, body):
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        # 본문을 청크로 읽어 스트리밍 해시한다. 전체를 메모리에 올리지 않는다.
        hasher = hashlib.sha256()
        total = 0
        remaining = self._content_length()
        if remaining is None:
            self._send_json(411, {"error": "Content-Length required"})
            return

        while remaining > 0:
            chunk = self.rfile.read(min(_CHUNK, remaining))
            if not chunk:
                break
            hasher.update(chunk)
            total += len(chunk)
            remaining -= len(chunk)

        transfer_id = self.headers.get("X-Transfer-Id")
        receipt = STATE.record(total, hasher.hexdigest(), transfer_id)
        self._send_json(200, {"ok": True, **receipt.as_dict()})

    def do_GET(self):
        if self.path.rstrip("/") == "/stats":
            self._send_json(200, STATE.snapshot())
        elif self.path.rstrip("/") in ("", "/health", "/healthz"):
            self._send_json(200, {"ok": True, "role": SINK_ROLE, "name": SINK_NAME})
        else:
            self._send_json(404, {"error": "not found"})

    def do_DELETE(self):
        # 회차 사이 초기화: DELETE /stats
        if self.path.rstrip("/") == "/stats":
            STATE.reset()
            self._send_json(200, {"ok": True, "reset": True})
        else:
            self._send_json(404, {"error": "not found"})

    def _content_length(self):
        raw = self.headers.get("Content-Length")
        if raw is None:
            return None
        try:
            value = int(raw)
            return value if value >= 0 else None
        except ValueError:
            return None


def main():
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(
        f"[sink] role={SINK_ROLE} name={SINK_NAME} listening on "
        f"{LISTEN_HOST}:{LISTEN_PORT}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
