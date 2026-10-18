"""
Network Observer - Enricher (#5)

Zeek conn.log (JSON Lines)를 tail 하여 Canonical Network Event v1.0으로 변환한다.

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
import time

import docker
import yaml

from identity import IdentityResolver
from zeek_map import (
    EVENT_TYPE_CONNECTION,
    SCHEMA_VERSION,
    build_observer_meta,
    guess_app_protocol,
    map_connection_state,
    map_protocol,
    seconds_to_ms,
    to_utc_rfc3339_ms,
)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("network-observer")

CONFIG_PATH = os.getenv("OBSERVER_CONFIG", "/app/config/observer.yml")
CONN_LOG_PATH = os.getenv("ZEEK_CONN_LOG", "/zeek-logs/conn.log")

_running = True


def _stop(signum, _frame):
    global _running
    logger.info("종료 신호 수신(%s). 정리 중...", signum)
    _running = False


def load_config(path):
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def build_event(record, resolver, capture_cfg, observer_cfg):
    """Zeek conn.log 레코드 1건 -> Canonical Network Event v1.0 dict."""

    src_ip = record.get("id.orig_h")
    dst_ip = record.get("id.resp_h")
    src_port = record.get("id.orig_p")
    dst_port = record.get("id.resp_p")

    # 필수 observed fact가 없으면 canonical event를 만들 수 없다.
    if not src_ip or not dst_ip or src_port is None or dst_port is None:
        return None

    src = resolver.resolve(src_ip, src_port)
    dst = resolver.resolve(dst_ip, dst_port)

    # `network` 결정:
    #   host runtime endpoint가 관여하면 그쪽 network(host-bound)를 따른다.
    #   그 외에는 캡처 지점의 논리 network를 사용한다.
    #   -> NETWORK_EVENT_SCHEMA.md §8.3
    network = capture_cfg.get("logical_network", "unknown")
    if dst.runtime == "host" and dst.network:
        network = dst.network
    elif src.runtime == "host" and src.network:
        network = src.network

    return {
        # --- 공통 ---
        "schema_version": SCHEMA_VERSION,
        "timestamp": to_utc_rfc3339_ms(record["ts"]),
        "event_type": EVENT_TYPE_CONNECTION,
        "observer": observer_cfg.get("name", "network-observer"),

        # --- source endpoint ---
        "src_service": src.service,
        "src_container": src.container,
        "src_runtime": src.runtime,
        "src_ip": src_ip,
        "src_port": int(src_port),

        # --- destination endpoint ---
        "dst_service": dst.service,
        "dst_container": dst.container,
        "dst_runtime": dst.runtime,
        "dst_ip": dst_ip,
        "dst_port": int(dst_port),

        # --- network ---
        "protocol": map_protocol(record.get("proto")),
        "network": network,
        "interface": capture_cfg.get("interface"),
        "app_protocol": guess_app_protocol(record.get("service")),

        # --- connection ---
        "connection_state": map_connection_state(record.get("conn_state")),
        "duration_ms": seconds_to_ms(record.get("duration")),
        "bytes_sent": record.get("orig_bytes"),       # src -> dst
        "bytes_received": record.get("resp_bytes"),   # dst -> src

        # --- optional / extension ---
        "direction": None,        # L4 conn.log에서는 관측 지점 기준 방향을 단정하지 않는다
        "connection_id": record.get("uid"),
        "request_id": None,       # L4에는 존재하지 않는다 (§11.3)
        "observer_instance": observer_cfg.get("instance"),
        "observer_meta": build_observer_meta(record),
    }


def tail_lines(path, stop_check):
    """
    conn.log를 tail 한다.

    Zeek 기동 전에는 파일이 없을 수 있으므로 생길 때까지 기다린다.
    파일이 교체(재생성)되면 inode 변화를 감지해 다시 연다.
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
                    # 최초 기동 시에만 기존 내용을 건너뛴다.
                    handle.seek(0, os.SEEK_END)
                    first_open = False
                    logger.info("conn.log tail 시작: %s", path)
                else:
                    # 교체/절단된 파일은 처음부터 읽어야 그 사이 기록이 유실되지 않는다.
                    logger.info("conn.log 재오픈 — 처음부터 읽는다: %s", path)

            line = handle.readline()
            if line:
                stripped = line.strip()
                if stripped:
                    yield stripped
                continue

            # EOF: 파일 교체(inode 변경) 또는 절단(size < offset) 확인 후 대기
            try:
                stat = os.stat(path)
                if stat.st_ino != inode:
                    logger.info("conn.log 교체 감지. 다시 연다.")
                    handle.close()
                    handle = None
                    continue
                if stat.st_size < handle.tell():
                    # Zeek이 같은 inode를 유지한 채 파일을 비운 경우.
                    # offset이 EOF를 넘어서 영구히 멈추므로 처음부터 다시 읽는다.
                    logger.info("conn.log 절단 감지. 처음부터 다시 읽는다.")
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
        # Docker에 접근하지 못해도 observer는 동작해야 한다.
        # 모든 endpoint가 unknown이 될 뿐, raw fact는 보존된다. (§7.3 / P6)
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

    emitted = 0
    skipped = 0
    try:
        for line in tail_lines(CONN_LOG_PATH, lambda: _running):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            resolver.refresh()  # 주기 조건 충족 시에만 실제 갱신

            try:
                event = build_event(record, resolver, capture_cfg, observer_cfg)
            except Exception as exc:
                logger.warning("event 변환 실패(건너뜀): %s", exc)
                skipped += 1
                continue

            if event is None:
                skipped += 1
                continue

            payload = json.dumps(event, ensure_ascii=False)
            if out_handle is not None:
                out_handle.write(payload + "\n")
                out_handle.flush()
            if to_stdout:
                print(payload, flush=True)

            emitted += 1
            if emitted % 100 == 0:
                logger.info("Canonical Event %d건 생성 (skip %d)", emitted, skipped)
    finally:
        if out_handle is not None:
            out_handle.close()
        logger.info("종료. 총 %d건 생성, %d건 skip", emitted, skipped)


if __name__ == "__main__":
    sys.exit(main())
