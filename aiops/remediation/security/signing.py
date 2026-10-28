"""
HMAC-SHA256 요청 서명 — Slack 서명 검증과 Pipeline→Remediation 인증의 공통 기반.

서명 대상 문자열(canonical string)은 Slack 공식 규격과 같은 형태로 둔다:

    v0:<timestamp>:<raw body>

이렇게 하면 Slack 검증과 자체 서비스 인증이 같은 코드를 쓰고, 둘 다 요청 본문
전체를 서명 범위에 넣는다 (본문이 1바이트라도 바뀌면 거부된다).

표준 라이브러리만 쓴다 — 컨테이너 의존성이 늘지 않는다.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import time

SIGNATURE_VERSION = "v0"
DEFAULT_MAX_AGE_SEC = 300  # 5분 — Slack 권고값


def canonical_string(timestamp: str, body: bytes) -> bytes:
    """서명 대상 바이트열. body 는 파싱 전 원본이어야 한다."""
    return f"{SIGNATURE_VERSION}:{timestamp}:".encode("utf-8") + body


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """`v0=<hex>` 형태의 서명을 만든다."""
    digest = hmac.new(
        secret.encode("utf-8"),
        canonical_string(timestamp, body),
        hashlib.sha256,
    ).hexdigest()
    return f"{SIGNATURE_VERSION}={digest}"


def verify(
    secret: str | None,
    timestamp: str | None,
    signature: str | None,
    body: bytes,
    now: float | None = None,
    max_age_sec: int = DEFAULT_MAX_AGE_SEC,
) -> tuple[bool, str]:
    """
    서명을 검증한다. 반환: (통과 여부, 거부 사유).

    사유는 로그·감사 기록용이며 호출자에게 그대로 돌려주지 않는다 (어떤 검사에서
    걸렸는지 알려 주면 공격자에게 단서가 된다).

    비밀키가 설정되지 않으면 거부한다 — 설정 누락 시 조치를 열어 주지 않는다
    (fail closed).
    """
    if not secret:
        return False, "secret_not_configured"
    if not signature:
        return False, "missing_signature"
    if not timestamp:
        return False, "missing_timestamp"

    try:
        ts = float(timestamp)
    except (TypeError, ValueError):
        return False, "invalid_timestamp"

    now = time.time() if now is None else now
    # 과거(리플레이)와 미래(시계 왜곡) 양쪽을 같은 창으로 제한한다.
    if not math.isfinite(ts) or abs(now - ts) > max_age_sec:
        return False, "timestamp_out_of_window"

    expected = sign(secret, timestamp, body)
    # 타이밍 공격 방지 — 길이가 달라도 compare_digest 가 안전하게 처리한다.
    if not hmac.compare_digest(expected, signature):
        return False, "signature_mismatch"
    return True, "ok"
