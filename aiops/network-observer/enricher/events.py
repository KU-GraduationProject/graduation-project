"""
Zeek 로그 레코드 -> Canonical Network Event 변환 (순수 함수).

main.py 에서 분리해 Docker/YAML 없이도 테스트할 수 있게 한다. resolver 는
identity.IdentityResolver 와 같은 .resolve(ip, port) -> Endpoint 인터페이스면 된다.

두 종류의 이벤트를 만든다:
  build_connection_event : conn.log (최종 연결 집계, event_type=connection)
  build_threshold_event  : conn_threshold.log (전송 중 조기 이벤트, event_type=connection_threshold, P6)
"""

from zeek_map import (
    EVENT_TYPE_CONNECTION,
    EVENT_TYPE_THRESHOLD,
    SCHEMA_VERSION,
    build_observer_meta,
    guess_app_protocol,
    map_connection_state,
    map_protocol,
    seconds_to_ms,
    to_utc_rfc3339_ms,
)


def _resolve_network(src, dst, capture_cfg):
    network = capture_cfg.get("logical_network", "unknown")
    if dst.runtime == "host" and dst.network:
        return dst.network
    if src.runtime == "host" and src.network:
        return src.network
    return network


def _endpoints(record, resolver):
    """conn.log / conn_threshold.log 공통: 5-tuple -> (src, dst) Endpoint. 부족하면 None."""
    src_ip = record.get("id.orig_h")
    dst_ip = record.get("id.resp_h")
    src_port = record.get("id.orig_p")
    dst_port = record.get("id.resp_p")
    if not src_ip or not dst_ip or src_port is None or dst_port is None:
        return None
    return (src_ip, src_port, dst_ip, dst_port,
            resolver.resolve(src_ip, src_port), resolver.resolve(dst_ip, dst_port))


def build_connection_event(record, resolver, capture_cfg, observer_cfg):
    """conn.log 레코드 1건 -> Canonical Network Event v1.0 (event_type=connection)."""
    ep = _endpoints(record, resolver)
    if ep is None:
        return None
    src_ip, src_port, dst_ip, dst_port, src, dst = ep
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp": to_utc_rfc3339_ms(record["ts"]),
        "event_type": EVENT_TYPE_CONNECTION,
        "observer": observer_cfg.get("name", "network-observer"),

        "src_service": src.service, "src_container": src.container,
        "src_runtime": src.runtime, "src_ip": src_ip, "src_port": int(src_port),

        "dst_service": dst.service, "dst_container": dst.container,
        "dst_runtime": dst.runtime, "dst_ip": dst_ip, "dst_port": int(dst_port),

        "protocol": map_protocol(record.get("proto")),
        "network": _resolve_network(src, dst, capture_cfg),
        "interface": capture_cfg.get("interface"),
        "app_protocol": guess_app_protocol(record.get("service")),

        "connection_state": map_connection_state(record.get("conn_state")),
        "duration_ms": seconds_to_ms(record.get("duration")),
        "bytes_sent": record.get("orig_bytes"),
        "bytes_received": record.get("resp_bytes"),

        "direction": None,
        "connection_id": record.get("uid"),
        "request_id": None,
        "observer_instance": observer_cfg.get("instance"),
        "observer_meta": build_observer_meta(record),
    }


def build_threshold_event(record, resolver, capture_cfg, observer_cfg):
    """
    conn_threshold.log 레코드 1건 -> Canonical Network Event (event_type=connection_threshold).

    전송 중 orig 바이트가 임계값(threshold)을 넘은 순간의 조기 이벤트다.
    bytes_sent 는 "그 순간까지의 누적"이며 최종값이 아니다. connection_state 는 진행중을
    뜻하는 established, duration/bytes_received 는 미확정이므로 None.
    """
    ep = _endpoints(record, resolver)
    if ep is None:
        return None
    src_ip, src_port, dst_ip, dst_port, src, dst = ep

    meta = {"zeek_uid": record.get("uid")}
    if record.get("threshold") is not None:
        meta["bytes_threshold"] = record["threshold"]
    if record.get("event_kind"):
        meta["event_kind"] = record["event_kind"]

    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp": to_utc_rfc3339_ms(record["ts"]),
        "event_type": EVENT_TYPE_THRESHOLD,
        "observer": observer_cfg.get("name", "network-observer"),

        "src_service": src.service, "src_container": src.container,
        "src_runtime": src.runtime, "src_ip": src_ip, "src_port": int(src_port),

        "dst_service": dst.service, "dst_container": dst.container,
        "dst_runtime": dst.runtime, "dst_ip": dst_ip, "dst_port": int(dst_port),

        "protocol": map_protocol(record.get("proto")),
        "network": _resolve_network(src, dst, capture_cfg),
        "interface": capture_cfg.get("interface"),
        "app_protocol": None,

        "connection_state": "established",   # 전송 중 (아직 종료 전)
        "duration_ms": None,
        "bytes_sent": record.get("orig_bytes"),   # 임계 도달 시점까지의 누적 (최종값 아님)
        "bytes_received": None,

        "direction": None,
        "connection_id": record.get("uid"),
        "request_id": None,
        "observer_instance": observer_cfg.get("instance"),
        "observer_meta": meta,
    }
