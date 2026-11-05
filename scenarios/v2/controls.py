"""
대조(controls) 공용 점검 — 주로 C-c(이미 차단된 공격) 검증용.

C-c 는 외부 도구가 만든 공격형 요청이 **입구에서 실제로 4xx 로 막히는지**(앱 미도달)와,
시나리오가 **자기신고 문자열을 남기지 않는지**를 확인해야 한다. 그 판정 로직만 여기 둔다
(요청 생성은 측정 PC 외부 도구 몫).
"""

from __future__ import annotations

BLOCKED_STATUSES = set(range(400, 500))   # 4xx = 입구 차단(앱 미도달)

# 로그·경로·헤더에 있으면 안 되는 자기신고/정답 암시 표식(점검용 예시 집합).
SELF_REPORT_MARKERS = ("[ATTACK]", "attack", "exploit", "should_alert",
                       "threat_level", "expected_action", "ground_truth")


def all_blocked_4xx(statuses) -> bool:
    """모든 응답이 4xx(입구 차단)인가. 하나라도 2xx 면 앱까지 통과한 것이라 C-c 아님."""
    statuses = list(statuses)
    return bool(statuses) and all(s in BLOCKED_STATUSES for s in statuses)


def has_self_report_markers(text: str, markers=SELF_REPORT_MARKERS) -> bool:
    """텍스트(로그 라인·경로·헤더)에 자기신고/정답 암시 표식이 있는가."""
    low = text.lower()
    return any(m.lower() in low for m in markers)
