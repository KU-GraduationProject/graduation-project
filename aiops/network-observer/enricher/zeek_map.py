"""
Zeek conn.log -> Canonical Network Event v1.0 필드 매핑.

Zeek 고유 표현(conn_state 문자열, uid, history 등)을 canonical 표현으로 변환한다.
Zeek 원본 값은 버리지 않고 observer_meta에 보존한다.
  -> NETWORK_EVENT_SCHEMA.md §6.3 / D11 / D16
"""

from datetime import datetime, timezone

SCHEMA_VERSION = "1.0"
EVENT_TYPE_CONNECTION = "connection"

# Zeek conn_state -> canonical connection_state enum (NETWORK_EVENT_SCHEMA.md §6.3)
#
# Zeek 상태값은 Zeek 전용이므로 canonical enum으로 반드시 변환한다.
# 소비자(Pipeline)가 Zeek 문자열을 알 필요가 없어야 observer 교체가 가능하다.
_CONN_STATE = {
    "SF":  "closed",        # 정상 수립 후 정상 종료
    "S1":  "established",   # 수립됨, 종료 미관측
    "S2":  "established",   # 수립 후 originator만 종료 시도
    "S3":  "established",   # 수립 후 responder만 종료 시도
    "S0":  "timeout",       # SYN만 관측, 응답 없음
    "REJ": "rejected",      # 연결 거부
    "RSTO": "reset",        # originator가 RST
    "RSTR": "reset",        # responder가 RST
    "RSTOS0": "reset",
    "RSTRH": "reset",
    "SH":  "timeout",       # SYN 후 half-open
    "SHR": "timeout",
    "OTH": "unknown",       # 중간부터 관측 (handshake 미관측)
}

# 전송 계층 프로토콜 정규화 (canonical enum: tcp | udp | icmp | other)
_PROTOCOLS = {"tcp", "udp", "icmp"}


def map_connection_state(zeek_conn_state):
    """Zeek conn_state 문자열을 canonical enum으로 변환. 미지의 값은 unknown."""
    if not zeek_conn_state:
        return "unknown"
    return _CONN_STATE.get(zeek_conn_state, "unknown")


def map_protocol(zeek_proto):
    """Zeek proto를 canonical enum으로 정규화."""
    if not zeek_proto:
        return "other"
    proto = str(zeek_proto).lower()
    return proto if proto in _PROTOCOLS else "other"


def to_utc_rfc3339_ms(epoch_seconds):
    """
    Zeek의 epoch float -> UTC RFC3339 밀리초 문자열.

    Application Log가 KST를 쓰더라도 Network Event는 UTC로 저장한다.
    Loki/Prometheus가 모두 UTC epoch로 저장하므로 상관분석 시 변환이 끼어들지 않게 한다.
      -> NETWORK_EVENT_SCHEMA.md §9.1 / D8
    """
    dt = datetime.fromtimestamp(float(epoch_seconds), tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def seconds_to_ms(duration_seconds):
    """
    Zeek duration(초, float) -> canonical duration_ms(정수 밀리초).
    미완결 연결은 Zeek이 duration을 주지 않으므로 None.
      -> NETWORK_EVENT_SCHEMA.md §9.2 / D9
    """
    if duration_seconds is None:
        return None
    return int(round(float(duration_seconds) * 1000))


def guess_app_protocol(zeek_service):
    """
    Zeek이 식별한 응용 프로토콜(추정값). 확정 사실이 아니므로 nullable이고 label이 아니다.
      -> NETWORK_EVENT_SCHEMA.md §6.5
    """
    if not zeek_service:
        return None
    # Zeek은 "ssl,http"처럼 복수로 줄 수 있다. 첫 번째만 사용한다.
    return str(zeek_service).split(",")[0].strip() or None


def build_observer_meta(record):
    """
    Zeek 고유 필드를 canonical 바깥(observer_meta)으로 격리한다.
    소비자는 이 객체에 의존해서는 안 된다.
      -> NETWORK_EVENT_SCHEMA.md D16
    """
    meta = {}
    for canonical_key, zeek_key in (
        ("zeek_uid", "uid"),
        ("raw_conn_state", "conn_state"),
        ("history", "history"),
        ("orig_pkts", "orig_pkts"),
        ("resp_pkts", "resp_pkts"),
        ("missed_bytes", "missed_bytes"),
    ):
        if record.get(zeek_key) is not None:
            meta[canonical_key] = record[zeek_key]
    return meta or None
