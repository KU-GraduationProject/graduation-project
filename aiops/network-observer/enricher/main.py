"""
Network Observer - Enricher (#5)

Zeek 로그(JSON Lines)를 tail 하여 Canonical Network Event v1.0으로 변환한다.

두 로그를 동시에 tail 한다:
  conn.log           -> event_type=connection          (최종 연결 집계)
  conn_threshold.log -> event_type=connection_threshold (전송 중 조기 이벤트, P6)

책임 범위 (#5):
    Network traffic -> Zeek -> Canonical Network Event 생성
까지다. Loki ingestion은 #8의 책임이므로 여기서는 JSONL 파일과 stdout으로만 출력한다.

참조: docs/network-observability/NETWORK_EVENT_SCHEMA.md
"""

import json
import logging
import os
import signal
import sys
import threading
import time

import docker
import yaml

from events import build_connection_event, build_threshold_event
from identity import IdentityResolver

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("network-observer")

CONFIG_PATH = os.getenv("OBSERVER_CONFIG", "/app/config/observer.yml")
CONN_LOG_PATH = os.getenv("ZEEK_CONN_LOG", "/zeek-logs/conn.log")
# P6: Zeek ConnThreshold 중간 이벤트 로그. 없으면 해당 소스는 조용히 대기만 한다.
THRESHOLD_LOG_PATH = os.getenv("ZEEK_CONN_THRESHOLD_LOG", "/zeek-logs/conn_threshold.log")

_running = True


def _stop(signum, _frame):
    global _running
    logger.info("종료 신호 수신(%s). 정리 중...", signum)
    _running = False


def load_config(path):
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def tail_lines(path, stop_check):
    """
    로그를 tail 한다. Zeek 기동 전에는 파일이 없을 수 있으므로 생길 때까지 기다리고,
    파일이 교체(inode 변화)·절단되면 다시 연다.
    """
    handle = None
    inode = None
    first_open = True
    try:
        while stop_check():
            if handle is None:
                if not os.path.exists(path):
                    time.sleep(1)
                    continue
                handle = open(path, "r", encoding="utf-8", errors="replace")
                inode = os.fstat(handle.fileno()).st_ino
                if first_open:
                    handle.seek(0, os.SEEK_END)
                    first_open = False
                    logger.info("tail 시작: %s", path)
                else:
                    logger.info("재오픈 — 처음부터 읽는다: %s", path)

            line = handle.readline()
            if line:
                stripped = line.strip()
                if stripped:
                    yield stripped
                continue

            try:
                stat = os.stat(path)
                if stat.st_ino != inode:
                    logger.info("%s 교체 감지. 다시 연다.", path)
                    handle.close()
                    handle = None
                    continue
                if stat.st_size < handle.tell():
                    logger.info("%s 절단 감지. 처음부터 다시 읽는다.", path)
                    handle.seek(0)
                    continue
            except FileNotFoundError:
                handle.close()
                handle = None
                continue
            time.sleep(0.5)
    finally:
        if handle is not None:
            handle.close()


class EventWriter:
    """여러 tail 스레드가 하나의 JSONL/stdout 으로 안전하게 쓰도록 직렬화한다."""

    def __init__(self, out_handle, to_stdout):
        self._lock = threading.Lock()
        self._out = out_handle
        self._stdout = to_stdout
        self.emitted = 0
        self.skipped = 0

    def emit(self, event):
        payload = json.dumps(event, ensure_ascii=False)
        with self._lock:
            if self._out is not None:
                self._out.write(payload + "\n")
                self._out.flush()
            if self._stdout:
                print(payload, flush=True)
            self.emitted += 1

    def skip(self):
        with self._lock:
            self.skipped += 1


def _run_source(path, builder, resolver, capture_cfg, observer_cfg, writer):
    """한 로그 파일을 tail 하며 builder 로 canonical event 를 만들어 writer 로 내보낸다."""
    for line in tail_lines(path, lambda: _running):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            writer.skip()
            continue

        resolver.refresh()  # 주기 조건 충족 시에만 실제 갱신

        try:
            event = builder(record, resolver, capture_cfg, observer_cfg)
        except Exception as exc:
            logger.warning("event 변환 실패(건너뜀, %s): %s", path, exc)
            writer.skip()
            continue

        if event is None:
            writer.skip()
            continue
        writer.emit(event)


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    config = load_config(CONFIG_PATH)
    observer_cfg = config.get("observer") or {}
    capture_cfg = config.get("capture") or {}
    output_cfg = config.get("output") or {}

    try:
        docker_client = docker.from_env()
        docker_client.ping()
        logger.info("Docker API 연결 성공")
    except Exception as exc:
        logger.warning("Docker API 연결 실패 — 모든 endpoint가 unknown 처리됨: %s", exc)
        docker_client = None

    resolver = IdentityResolver(config, docker_client)
    resolver.refresh(force=True)

    out_path = output_cfg.get("path")
    to_stdout = bool(output_cfg.get("stdout", True))
    out_handle = None
    if out_path:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        out_handle = open(out_path, "a", encoding="utf-8")
        logger.info("Canonical Event 출력: %s", out_path)

    writer = EventWriter(out_handle, to_stdout)

    sources = [
        (CONN_LOG_PATH, build_connection_event),
        (THRESHOLD_LOG_PATH, build_threshold_event),  # P6
    ]
    threads = []
    for path, builder in sources:
        t = threading.Thread(
            target=_run_source,
            args=(path, builder, resolver, capture_cfg, observer_cfg, writer),
            name=f"tail:{os.path.basename(path)}",
            daemon=True,
        )
        t.start()
        threads.append(t)

    try:
        while _running and any(t.is_alive() for t in threads):
            time.sleep(0.5)
    finally:
        for t in threads:
            t.join(timeout=2)
        if out_handle is not None:
            out_handle.close()
        logger.info("종료. 총 %d건 생성, %d건 skip", writer.emitted, writer.skipped)


if __name__ == "__main__":
    sys.exit(main())
