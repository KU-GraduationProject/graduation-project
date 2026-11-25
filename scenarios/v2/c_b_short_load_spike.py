"""
C-b — 짧은 정상 부하 스파이크 (F1-a·S2-a 대조, scenarios-v2 2차).

정상 상황: 공지·알림 직후처럼 **정상 사용자 요청이 수십 초 동안 늘었다가** 곧 평소로 돌아온다.
  CPU·요청량이 잠깐 오르지만 포화·장기 지속이 없다. F1-a(지속 과부하)·S2-a(프로세스 점유)와
  구분돼야 한다.

주입: F1-a 와 같은 정상 읽기 경로로, 낮은 동시성·짧은 시간만 요청을 늘린다(F1-a 의 모양을 재사용).
정리: 요청을 멈추면 원복.
"""

from __future__ import annotations

from v2 import f1a_cpu_overload as f1a

# 짧고(수십 초) 가벼운 스파이크
STRENGTH_PROFILE = {"weak": (4, 20), "medium": (8, 40), "strong": (16, 60)}   # (동시성, 초)
DEFAULT_STRENGTH = "medium"


def plan_spike(strength: str = DEFAULT_STRENGTH, duration_seconds: int | None = None) -> dict:
    if strength not in STRENGTH_PROFILE:
        raise ValueError(f"unknown strength: {strength}")
    c, d = STRENGTH_PROFILE[strength]
    return f1a.plan_load("weak", duration_seconds or d, concurrency=c) | {"strength": strength}


def inject(strength: str = DEFAULT_STRENGTH, duration_seconds: int | None = None, **kw):
    plan = plan_spike(strength, duration_seconds)
    return f1a.inject("weak", plan["duration_seconds"], concurrency=plan["concurrency"], **kw)


def dry_run() -> dict:
    return {"plan": plan_spike(), "paths": f1a.PATHS, "pair": ["f1_a_cpu_overload", "s2_a_resource_theft"],
            "env": ["F1A_BASE_URL", "F1A_PATHS"], "note": "수십 초 뒤 평소로 복귀"}


def main(**kw):
    return inject(**kw)


if __name__ == "__main__":
    main()
