"""
Pipeline → Remediation 서비스 인증 (송신측).

Remediation 의 /action 은 HMAC-SHA256 서명을 요구한다. 서명 대상 문자열은
Slack 규격과 같은 형태다:

    v0:<timestamp>:<raw body>

수신측 구현은 aiops/remediation/security/{signing,service_auth}.py 에 있다.
두 컨테이너는 이미지가 분리돼 코드를 공유할 수 없으므로 같은 규격을 각자 구현하고,
교차 검증 테스트로 드리프트를 막는다
(aiops/remediation/tests/test_service_auth.py::CrossImplementationTest).

표준 라이브러리만 쓴다 — 컨테이너 의존성이 늘지 않는다.
"""

from __future__ import annotations

import hashlib
import hmac
import time

SIGNATURE_VERSION = "v0"
TIMESTAMP_HEADER = "x-aiops-timestamp"
SIGNATURE_HEADER = "x-aiops-signature"


def sign(api_key: str, timestamp: str, body: bytes) -> str:
    """`v0=<hex>` 형태의 서명."""
    basestring = f"{SIGNATURE_VERSION}:{timestamp}:".encode("utf-8") + body
    digest = hmac.new(api_key.encode("utf-8"), basestring, hashlib.sha256).hexdigest()
    return f"{SIGNATURE_VERSION}={digest}"


def build_headers(api_key: str, body: bytes, now: float | None = None) -> dict:
    """서명 헤더. 본문은 실제로 전송할 바이트열과 같아야 한다."""
    timestamp = str(int(time.time() if now is None else now))
    return {
        TIMESTAMP_HEADER: timestamp,
        SIGNATURE_HEADER: sign(api_key, timestamp, body),
        "Content-Type": "application/json",
    }
