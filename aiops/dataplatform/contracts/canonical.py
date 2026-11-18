"""C-1 canonical JSON, C-2 hashes, C-3 timestamps and every ID formula of 01 §1.1."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from decimal import Decimal


def canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_str(value) -> str:
    return canonical_json(value).decode("utf-8")


def h(value) -> str:
    """C-2: sha256 of canonical JSON, lowercase hex."""
    return hashlib.sha256(canonical_json(value)).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def rows_bytes(rows: list[dict]) -> bytes:
    """Fixture data-file convention: canonical JSON rows joined by newline."""
    return b"\n".join(canonical_json(row) for row in rows)


# ---- C-3 time ---------------------------------------------------------------------------

def utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        raise ValueError(f"timestamp without offset is ambiguous: {dt!r}")
    return dt.astimezone(timezone.utc)


def fmt_ts(dt: datetime) -> str:
    """`YYYY-MM-DDTHH:MM:SS.ffffffZ`."""
    return utc(dt).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_ts(text: str) -> datetime:
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return utc(dt)


def compact_ts(dt: datetime) -> str:
    """`YYYYMMDDTHHMMSSZ` used inside build ids."""
    return utc(dt).strftime("%Y%m%dT%H%M%SZ")


def ns_of(dt: datetime) -> int:
    dt = utc(dt)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = dt - epoch
    return (delta.days * 86400 + delta.seconds) * 10**9 + delta.microseconds * 1000


def from_ns(ns: int) -> datetime:
    """Exact (µs) conversion; floats would lose precision at ns epochs."""
    seconds, rem = divmod(int(ns), 10**9)
    return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(microsecond=rem // 1000)


def from_ms(ms: int) -> datetime:
    seconds, rem = divmod(int(ms), 1000)
    return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(microsecond=rem * 1000)


def seconds_text(ns: int) -> str:
    """Prometheus float-seconds parameter without float rounding: 1794279980512000000 -> '1794279980.512'."""
    value = Decimal(int(ns)).scaleb(-9).normalize()
    return format(value, "f")


def prom_ts_ms(t) -> int:
    """01 §2.3: `int(Decimal(str(t)) * 1000)`."""
    return int(Decimal(str(t)) * 1000)


# ---- 01 §1.1 IDs ------------------------------------------------------------------------

def build_id(prefix: str, now: datetime, hex8: str) -> str:
    """`acq_…` / `sb_…` / `gb_…` + `{YYYYMMDDTHHMMSSZ}_{8hex}`."""
    if len(hex8) != 8 or any(c not in "0123456789abcdef" for c in hex8):
        raise ValueError(f"build id suffix must be 8 lowercase hex chars: {hex8!r}")
    return f"{prefix}_{compact_ts(now)}_{hex8}"


def acquisition_key(plan_id, binding_sha256, query_name, query_text, window_start: str, window_end: str) -> str:
    return h({"plan_id": plan_id, "binding_sha256": binding_sha256, "query_name": query_name,
              "query_text": query_text, "window_start": window_start, "window_end": window_end})[:32]


def bronze_id(acquisition_id: str, page: int, row: int) -> str:
    return f"{acquisition_id}:{page:04d}:{row:06d}"


def loki_record_key(stream_labels: dict, entry_ts_ns: int, line: str) -> str:
    return h([stream_labels, str(entry_ts_ns), line])


def prom_record_key(query_text_sha256: str, series_labels: dict, sample_ts_ms: int, value_raw: str) -> str:
    return h([query_text_sha256, series_labels, sample_ts_ms, value_raw])


def alert_event_id(alert_labels: dict, starts_at: datetime) -> str:
    return h({"labels": alert_labels, "starts_at": fmt_ts(starts_at)})


def incident_id(alert_event: str) -> str:
    return "inc_" + alert_event[:24]


def plan_binding_sha256(binding_shas) -> str:
    return h(sorted({b for b in binding_shas if b is not None}))


def coverage_id(dataset: str, plan_id: str, plan_binding: str, window_start: str, window_end: str) -> str:
    return "cov_" + h([dataset, plan_id, plan_binding, window_start, window_end])[:24]


def normalize_map_index(map_index):
    """Airflow gives unmapped tasks -1; it is stored and hashed as null (01 §1.1, 03 §2)."""
    return map_index if map_index is not None and map_index >= 0 else None


def run_id(orchestrator, dag_id, airflow_run_id, task_id, try_number, map_index=None) -> str:
    parts = [orchestrator, dag_id, airflow_run_id, task_id, try_number]
    if normalize_map_index(map_index) is not None:
        parts.append(map_index)
    return "run_" + h(parts)[:20]


def edge_id(child_dataset, child_key, child_version, parent_dataset, parent_key, parent_version) -> str:
    return h([child_dataset, child_key, child_version, parent_dataset, parent_key, parent_version])[:32]


def db_log_id(site, source, target, session_id, line_num, pg_timestamp_raw) -> str:
    return h(["pg", site, source, target, session_id, line_num, pg_timestamp_raw])


def network_event_id(event: dict) -> str:
    if event.get("connection_id"):
        return h(["net", event.get("observer"), event.get("observer_instance"), event.get("event_type"),
                  event["connection_id"]])
    return h(["net", event.get("observer"), event.get("observer_instance"), event.get("event_type"),
              event.get("timestamp"), event.get("protocol"), event.get("src_ip"), event.get("src_port"),
              event.get("dst_ip"), event.get("dst_port")])


def metric_point_id(query_text_sha256: str, series_labels: dict, sample_ts_ms: int) -> str:
    return h([query_text_sha256, series_labels, sample_ts_ms])


def quarantine_id(record_key: str, target_dataset: str, reason_code: str) -> str:
    return h([record_key, target_dataset, reason_code])


def evidence_log_id(incident, log_dataset, silver_key) -> str:
    return h(["log", incident, log_dataset, silver_key])[:32]


def evidence_metric_id(incident, query_name, series_labels: dict) -> str:
    return h(["metric", incident, query_name, h(series_labels)])[:32]


def evidence_flow_id(incident, scope_role, scope_identity: dict, src, dst, dst_ip, dst_port, protocol) -> str:
    return h(["flow", incident, scope_role, scope_identity, src, dst, dst_ip, dst_port, protocol])[:32]
