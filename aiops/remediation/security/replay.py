"""
서명 리플레이 차단.

서명 검증만으로는 "가로챈 요청을 그대로 다시 보내는" 공격을 막지 못한다.
타임스탬프 창(5분) 안에서는 같은 요청이 계속 통과하기 때문이다. 한 번 통과한
서명을 기억해 두고 같은 서명이 다시 오면 거부한다.

범위: 같은 바이트의 요청을 다시 보내는 것만 막는다. 사람이 Slack 승인 버튼을
두 번 누르면 Slack 이 서로 다른 요청을 보내므로 둘 다 유효한 서명이다. 그 중복은
조치 레코드(remediation_id) 단위 멱등성이 필요하며 Phase 2 범위다.
"""

from __future__ import annotations

import threading
import time

from security.signing import DEFAULT_MAX_AGE_SEC

# 타임스탬프 창보다 오래 기억할 필요는 없다 — 창을 벗어난 요청은 서명 검증에서 걸린다.
DEFAULT_TTL_SEC = DEFAULT_MAX_AGE_SEC
DEFAULT_MAX_ENTRIES = 4096


class ReplayGuard:
    """통과한 서명을 TTL 동안 기억한다. 프로세스 로컬이며 스레드 안전하다."""

    def __init__(self, ttl_sec: int = DEFAULT_TTL_SEC,
                 max_entries: int = DEFAULT_MAX_ENTRIES):
        self.ttl_sec = ttl_sec
        self.max_entries = max_entries
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def remember(self, signature: str, now: float | None = None) -> bool:
        """
        처음 보는 서명이면 기억하고 True. 이미 본 서명이면 False (리플레이).
        """
        now = time.time() if now is None else now
        with self._lock:
            self._prune(now)
            if signature in self._seen:
                return False
            # 무한히 자라지 않게 한다. 오래된 것부터 버린다.
            if len(self._seen) >= self.max_entries:
                oldest = sorted(self._seen.items(), key=lambda kv: kv[1])
                for sig, _ in oldest[: max(1, self.max_entries // 4)]:
                    self._seen.pop(sig, None)
            self._seen[signature] = now + self.ttl_sec
            return True

    def _prune(self, now: float) -> None:
        expired = [sig for sig, exp in self._seen.items() if exp <= now]
        for sig in expired:
            self._seen.pop(sig, None)
