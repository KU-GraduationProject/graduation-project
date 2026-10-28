"""
Slack 요청 서명 검증 (Slack 공식 규격).

https://api.slack.com/authentication/verifying-requests-from-slack

  basestring = "v0:{X-Slack-Request-Timestamp}:{raw body}"
  signature  = "v0=" + HMAC_SHA256(signing_secret, basestring)

Slack 은 app 설정의 Signing Secret 으로 모든 요청에 서명한다. 이 검증이 없으면
/slack/action 에 닿을 수 있는 누구나 approve_action 을 위조해 컨테이너 조치를
실행시킬 수 있다.
"""

from __future__ import annotations

from security.signing import DEFAULT_MAX_AGE_SEC, verify

TIMESTAMP_HEADER = "x-slack-request-timestamp"
SIGNATURE_HEADER = "x-slack-signature"


def _lookup(headers, name: str) -> str | None:
    """헤더 이름은 대소문자를 구분하지 않는다 (Starlette Headers / 평범한 dict 모두 지원)."""
    get = getattr(headers, "get", None)
    if get is None:
        return None
    return headers.get(name) or headers.get(name.title()) or headers.get(name.upper())


def verify_slack_request(
    body: bytes,
    headers,
    signing_secret: str | None,
    now: float | None = None,
    max_age_sec: int = DEFAULT_MAX_AGE_SEC,
) -> tuple[bool, str]:
    """Slack 요청 서명을 검증한다. 반환: (통과 여부, 거부 사유)."""
    return verify(
        secret=signing_secret,
        timestamp=_lookup(headers, TIMESTAMP_HEADER),
        signature=_lookup(headers, SIGNATURE_HEADER),
        body=body,
        now=now,
        max_age_sec=max_age_sec,
    )
