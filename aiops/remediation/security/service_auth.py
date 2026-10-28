"""
Pipeline → Remediation 서비스 인증 (수신측).

/action 은 조치 판단의 입력을 받는 엔드포인트다. 인증이 없으면 포트에 닿는
누구나 임의의 analysis 를 넣어 조치를 유발할 수 있다. Slack 과 같은 HMAC 규격을
쓰고(signing.py), 공유키는 REMEDIATION_API_KEY 환경변수로만 주입한다.

송신측 서명은 aiops/pipeline/security/service_auth.py 에 같은 규격으로 있다.
두 구현이 어긋나지 않도록 교차 검증 테스트를 둔다
(aiops/remediation/tests/test_service_auth.py::CrossImplementationTest).
"""

from __future__ import annotations

from security.signing import DEFAULT_MAX_AGE_SEC, verify

TIMESTAMP_HEADER = "x-aiops-timestamp"
SIGNATURE_HEADER = "x-aiops-signature"


def _lookup(headers, name: str) -> str | None:
    get = getattr(headers, "get", None)
    if get is None:
        return None
    return headers.get(name) or headers.get(name.title()) or headers.get(name.upper())


def verify_service_request(
    body: bytes,
    headers,
    api_key: str | None,
    now: float | None = None,
    max_age_sec: int = DEFAULT_MAX_AGE_SEC,
) -> tuple[bool, str]:
    """Pipeline 요청 서명을 검증한다. 반환: (통과 여부, 거부 사유)."""
    return verify(
        secret=api_key,
        timestamp=_lookup(headers, TIMESTAMP_HEADER),
        signature=_lookup(headers, SIGNATURE_HEADER),
        body=body,
        now=now,
        max_age_sec=max_age_sec,
    )
