"""
실제 캡처 인터페이스 이름을 Zeek 쪽에서 받아오는 경로 (순수 로직).

왜 파일로 주고받는가:
  Zeek 컨테이너는 backend 의 netns 를 공유하고(network_mode: service:backend), enricher 는
  자기 netns(mgmt-net)에 있다. 그래서 enricher 는 backend 의 인터페이스를 직접 조회할 수
  없다. 게다가 인터페이스 이름은 Zeek 가 기동할 때 서브넷으로 찾아내는 값이라, compose 의
  정적 환경변수로는 전달할 수 없다. 두 컨테이너가 공유하는 zeek_logs 볼륨(Zeek 쓰기 /
  enricher 읽기전용)에 한 줄 파일로 적어 두는 것이 유일하게 깔끔한 경로다.
  (start-zeek.sh 가 쓴다.)

왜 observer.yml 에 고정하지 않는가:
  Docker 가 붙이는 eth0/eth1 순서는 컨테이너를 다시 만들 때마다 바뀐다. 고정값을 두면
  실제로는 eth1 을 관측하면서 이벤트에는 eth0 이라고 적는 거짓 표시가 생긴다.
  NETWORK_EVENT_SCHEMA.md §8.2/§10.3 기준으로 interface 는 Loki label 이 아니라 body 의
  증거 필드이므로, 알 수 없으면 추측하지 말고 null 로 둔다(스키마 규정).

Docker/YAML 에 의존하지 않으므로 단독으로 테스트할 수 있다 (events.py 와 같은 분리 원칙).
"""

from __future__ import annotations

import logging
import os
import threading

logger = logging.getLogger("network-observer")

DEFAULT_PATH = "/zeek-logs/capture-interface"


class CaptureInterface:
    """
    공유 파일에서 실제 캡처 인터페이스 이름을 읽어 준다.

    Zeek 가 재생성되며 다른 인터페이스를 잡을 수 있다(그게 이 파일이 생긴 이유다).
    그래서 한 번만 읽지 않고, 파일의 mtime 이 바뀌면 다시 읽는다. 매 이벤트마다 호출되므로
    변화가 없으면 stat 한 번으로 끝낸다.

    파일이 없거나 비어 있으면 fallback 을 돌려준다(기본 None = 스키마의 "식별 불가").
    같은 경고를 이벤트마다 반복하지 않도록 한 번만 남긴다.
    """

    def __init__(self, path: str = DEFAULT_PATH, fallback: str | None = None):
        self._path = path
        self._fallback = fallback
        self._lock = threading.Lock()
        self._mtime = None
        self._value = fallback
        self._warned_missing = False

    def get(self) -> str | None:
        try:
            mtime = os.stat(self._path).st_mtime
        except OSError:
            with self._lock:
                if not self._warned_missing:
                    logger.warning(
                        "캡처 인터페이스 파일이 없다(%s). interface 필드를 %r 로 기록한다. "
                        "Zeek 가 start-zeek.sh 로 기동했는지 확인할 것.",
                        self._path, self._fallback,
                    )
                    self._warned_missing = True
                return self._fallback

        with self._lock:
            if mtime == self._mtime:
                return self._value

            try:
                with open(self._path, encoding="utf-8") as fh:
                    name = fh.read().strip()
            except OSError:
                # 쓰는 중에 읽었을 수 있다. 다음 호출에서 다시 시도한다.
                return self._value

            self._mtime = mtime
            self._warned_missing = False
            if not name:
                self._value = self._fallback
                return self._value
            if name != self._value:
                logger.info("실제 캡처 인터페이스: %s (%s)", name, self._path)
                self._value = name
            return self._value
