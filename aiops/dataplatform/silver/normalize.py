"""Bronze row -> Silver values (01 §3). One function per Silver dataset.

Each normalizer returns `Normalized(pk, values, flags)` or raises `Quarantine(reason, detail)`.
Quality problems are flags, not drops; only rows that cannot be interpreted are quarantined.
Values never include the envelope columns — `silver.build` adds those after dedup.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from contracts import canonical, enums, pipeline_compat, schemas
from contracts.canonical import canonical_str, fmt_ts

IDENTITY_FIELDS = ("site", "source", "service", "runtime", "target")


class Quarantine(Exception):
    def __init__(self, reason: str, detail: str | None = None):
        super().__init__(reason)
        if reason not in enums.QUARANTINE_REASONS:
            raise ValueError(f"unknown quarantine reason {reason}")
        self.reason = reason
        self.detail = detail[:200] if detail else None


@dataclass
class Normalized:
    pk: str
    values: dict
    flags: set = field(default_factory=set)
    order: tuple = ()


# ---- shared rules ------------------------------------------------------------------------

def normalize_severity(raw) -> str:
    """01 §3.9."""
    if raw is None:
        return "UNKNOWN"
    value = str(raw).upper()
    if re.fullmatch(r"DEBUG[1-5]?", value):
        return "DEBUG"
    if value in ("INFO", "NOTICE", "LOG"):
        return "INFO"
    if value in ("WARNING", "WARN"):
        return "WARN"
    if value in ("CRITICAL", "SEVERE", "PANIC", "FATAL"):
        return "FATAL"
    return value if value in ("TRACE", "ERROR") else "UNKNOWN"


# Fluentd `leafy_postgres_log` rule: known zone abbreviations and numeric offsets only.
_PG_TIMESTAMP = re.compile(r"\A(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}(?:\.\d+)?) (\S+)\Z")
_NUMERIC_ZONE = re.compile(r"\A([+-])(\d{2}):?(\d{2})?\Z")
_ZONES = {"UTC": "+00:00", "GMT": "+00:00", "KST": "+09:00"}


def parse_pg_time(value) -> datetime | None:
    m = _PG_TIMESTAMP.match(str(value or ""))
    if not m:
        return None
    zone = m.group(3)
    offset = _ZONES.get(zone)
    if offset is None:
        n = _NUMERIC_ZONE.match(zone)
        if not n:
            return None
        offset = f"{n.group(1)}{n.group(2)}:{n.group(3) or '00'}"
    try:
        return datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}{offset}").astimezone(timezone.utc)
    except ValueError:
        return None


def fluentd_flags(rec: dict) -> set:
    """DQ-S06: every existing Fluentd marker becomes a record flag."""
    flags = set()
    if "log_truncated" in rec:
        flags.add("log_truncated")
    if rec.get("log_partial_incomplete"):
        flags.add("log_partial_incomplete")
    if "log_parse_error" in rec:
        flags.add("log_parse_error")
    if "log_time_parse_error" in rec:
        flags.add("log_time_parse_error")
    return flags


def label_identity(labels: dict, flags: set, legacy: bool) -> dict:
    out = {k: labels.get(k) or "UNKNOWN" for k in IDENTITY_FIELDS}
    # DQ-S05: the legacy `source` label is the output channel (stdout/stderr), never an observation source.
    if legacy or str(out["source"]).lower() in ("stdout", "stderr"):
        out["source"] = "UNKNOWN"
    if "UNKNOWN" in out.values():
        flags.add("identity_unverified")
    return out


def _json_object(line: str) -> dict:
    try:
        value = json.loads(line)
    except ValueError as exc:
        raise Quarantine("invalid_json", str(exc)) from exc
    if not isinstance(value, dict):
        raise Quarantine("not_object", type(value).__name__)
    return value


def _int_or_none(value):
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(str(value))
    except ValueError:
        return None


def _priority(labels: dict, line: str) -> bool:
    return pipeline_compat.log_line().is_priority({"labels": labels, "line": line})


def _truncated_bytes(rec: dict):
    meta = rec.get("log_truncated")
    return meta.get("original_bytes") if isinstance(meta, dict) else None


def _loki_time(row: dict) -> datetime:
    return canonical.from_ns(row["entry_ts_ns"])


# ---- datasets ----------------------------------------------------------------------------

def db_log(row: dict, acq: dict) -> Normalized:
    labels = json.loads(row["stream_labels"])
    rec = _json_object(row["line"])
    flags = fluentd_flags(rec)
    legacy = "site" not in labels
    identity = label_identity(labels, flags, legacy)
    pg_raw = rec.get("timestamp")
    event_time = parse_pg_time(pg_raw)
    source = "body_timestamp"
    if event_time is None:
        event_time, source = _loki_time(row), "receiver_fallback"
        flags.add("event_time_fallback")
    session_id, line_num = rec.get("session_id"), _int_or_none(rec.get("line_num"))
    pk = (canonical.db_log_id(identity["site"], identity["source"], identity["target"], session_id, line_num, pg_raw)
          if session_id is not None and line_num is not None else row["record_key"])
    text_format = labels.get("log_format") == "text" or ("log" in rec and "timestamp" not in rec)
    values = {
        "db_log_id": pk, "event_time": fmt_ts(event_time), "event_time_source": source,
        "loki_ts_ns": row["entry_ts_ns"], **identity, "stream_labels": row["stream_labels"],
        "label_profile": "legacy" if legacy else "release_v1", "log_format": "text" if text_format else "json",
        "severity": normalize_severity(rec.get("error_severity")), "severity_raw": rec.get("error_severity"),
        "is_priority": _priority(labels, row["line"]), "pg_timestamp_raw": pg_raw, "state_code": rec.get("state_code"),
        "message": rec.get("message", rec.get("log") if text_format else None), "detail": rec.get("detail"),
        "hint": rec.get("hint"), "query": rec.get("query"), "user_name": rec.get("user"), "dbname": rec.get("dbname"),
        "application_name": rec.get("application_name"), "backend_type": rec.get("backend_type"),
        "pid": _int_or_none(rec.get("pid")), "session_id": session_id, "line_num": line_num,
        "remote_host": rec.get("remote_host"), "pg_log_file": rec.get("pg_log_file"), "body": canonical_str(rec),
        "truncated_original_bytes": _truncated_bytes(rec), "time_parse_error": rec.get("log_time_parse_error"),
    }
    return Normalized(pk, values, flags, (row["entry_ts_ns"], pk))


def app_log(row: dict, acq: dict) -> Normalized:
    labels = json.loads(row["stream_labels"])
    log_format = labels.get("log_format") or "absent"
    try:
        rec = _json_object(row["line"])
    except Quarantine:
        if log_format in ("json", "json_invalid"):
            raise
        rec = {"line": row["line"]}  # pre-JSON text line: kept whole
    flags = fluentd_flags(rec)
    legacy = "log_stream" not in labels
    identity = label_identity(labels, flags, legacy)
    docker = rec.get("docker", rec.get("_docker"))
    status = _int_or_none(rec.get("status"))
    values = {
        "log_id": row["record_key"], "event_time": fmt_ts(_loki_time(row)), "event_time_source": "loki_entry",
        "loki_ts_ns": row["entry_ts_ns"], **identity, "stream_labels": row["stream_labels"],
        "container_name": labels.get("container_name"),
        "log_stream": labels.get("source") if legacy else labels.get("log_stream"),
        "label_profile": "legacy" if legacy else "release_v1", "log_format": log_format,
        "severity": normalize_severity(rec.get("level")), "severity_raw": rec.get("level"),
        "is_priority": _priority(labels, row["line"]), "message": rec.get("message", rec.get("line")),
        "http_status": status, "request_id": rec.get("request_id"), "exception_class": rec.get("exception_class"),
        "body": canonical_str(rec), "docker_meta": canonical_str(docker) if isinstance(docker, dict) else None,
        "truncated_original_bytes": _truncated_bytes(rec), "parse_error": rec.get("log_parse_error"),
    }
    return Normalized(row["record_key"], values, flags, (row["entry_ts_ns"], row["record_key"]))


def network_event(row: dict, acq: dict) -> Normalized:
    rec = _json_object(row["line"])
    if "schema_version" not in rec:
        raise Quarantine("missing_required_field", "missing: schema_version")
    if str(rec["schema_version"]).split(".")[0] != "1":
        raise Quarantine("unsupported_schema_version", f"schema_version={rec['schema_version']!r}")
    missing = [k for k in schemas.NETWORK_REQUIRED if k not in rec]
    if missing:
        raise Quarantine("missing_required_field", "missing: " + ",".join(missing))
    try:
        event_time = pipeline_compat.correlation().to_instant(rec["timestamp"])
    except (ValueError, TypeError) as exc:
        raise Quarantine("invalid_timestamp", str(exc)) from exc
    fields = {}
    for name in schemas.NETWORK_EVENT_FIELDS:
        value = rec.get(name)
        fields[name] = canonical_str(value) if name == "observer_meta" and value is not None else value
    pk = canonical.network_event_id(rec)
    extra = {k: v for k, v in rec.items() if k not in schemas.NETWORK_EVENT_FIELDS}
    values = {"network_event_id": pk, "event_time": fmt_ts(event_time), "loki_ts_ns": row["entry_ts_ns"],
              **fields, "extra_fields": canonical_str(extra)}
    return Normalized(pk, values, set(), (fmt_ts(event_time), row["entry_ts_ns"], pk))


def metric_point(row: dict, acq: dict) -> Normalized:
    labels = json.loads(row["series_labels"])
    try:
        value = float(row["value_raw"])
    except ValueError as exc:
        raise Quarantine("invalid_value", f"value_raw={row['value_raw']!r}") from exc
    flags = set() if math.isfinite(value) else {"nonfinite_value"}
    scope = json.loads(acq["scope_identity"])
    pk = canonical.metric_point_id(row["query_text_sha256"], labels, row["sample_ts_ms"])
    values = {"metric_point_id": pk, "sample_time": fmt_ts(canonical.from_ms(row["sample_ts_ms"])),
              "sample_ts_ms": row["sample_ts_ms"], "query_name": row["query_name"],
              "query_text_sha256": row["query_text_sha256"],
              "metric_name": labels.get("__name__") or row["query_name"], "series_labels": row["series_labels"],
              "value": value, **{k: scope[k] for k in IDENTITY_FIELDS}}
    return Normalized(pk, values, flags, (row["query_name"], row["series_labels"], row["sample_ts_ms"]))


def _envelope(row: dict) -> dict:
    rec = _json_object(row["line"])
    for key in ("alert_name", "timestamp", "result"):
        if key not in rec:
            raise Quarantine("missing_required_field", f"missing: {key}")
    return rec


def _envelope_identity(rec: dict) -> dict:
    ident = rec.get("identity") if isinstance(rec.get("identity"), dict) else {}
    return {k: ident.get(k) or "UNKNOWN" for k in IDENTITY_FIELDS}


def _alert_event_id(rec: dict) -> str | None:
    if not isinstance(rec.get("alert_labels"), dict) or not rec.get("alert_starts_at"):
        return None
    starts = pipeline_compat.correlation().to_instant(rec["alert_starts_at"])
    return canonical.alert_event_id(rec["alert_labels"], starts)


def alert_event(row: dict, acq: dict) -> Normalized:
    rec = _envelope(row)
    for key in ("alert_labels", "alert_starts_at", "identity_status"):
        if key not in rec:
            raise Quarantine("missing_required_field", f"missing: {key}")
    try:
        starts = pipeline_compat.correlation().to_instant(rec["alert_starts_at"])
    except (ValueError, TypeError) as exc:
        raise Quarantine("invalid_timestamp", str(exc)) from exc
    labels = rec["alert_labels"]
    pk = canonical.alert_event_id(labels, starts)
    values = {"alert_event_id": pk, "alertname": labels.get("alertname") or rec["alert_name"],
              "starts_at": fmt_ts(starts), "starts_at_raw": rec["alert_starts_at"],
              "fingerprint": rec.get("alert_fingerprint"), "severity": labels.get("severity"),
              "category": labels.get("category"), "rulepack_target": labels.get("rulepack_target"),
              "alert_labels": canonical_str(labels), "alert_annotations": canonical_str(rec.get("alert_annotations") or {}),
              **_envelope_identity(rec), "identity_status": rec["identity_status"], "origin": "rca_envelope"}
    return Normalized(pk, values, set(), (fmt_ts(starts), pk))


def _llm_result(raw: dict) -> dict:
    """Revalidate with the Pipeline's `LLMAnalysisResult` unchanged. Two shapes lack `incident_class`:
    envelopes written before the field existed (key absent) and the Pipeline's own failed analysis
    (`LLMAnalysisResult.invalid()`: null + `analysis_status="invalid"`). Every other field is still
    validated by the same model, and the class stays null — it is never guessed."""
    model = pipeline_compat.llm_output().LLMAnalysisResult
    missing = "incident_class" not in raw
    if not missing and not (raw["incident_class"] is None and raw.get("analysis_status") == "invalid"):
        return model(**raw).model_dump()
    # any valid class lets the model check the rest; the placeholder is discarded below
    probe = model(**{**raw, "incident_class": pipeline_compat.load("schemas.actions").INCIDENT_CLASSES[0]})
    return {**probe.model_dump(), "incident_class": None}


def rca_result(row: dict, acq: dict) -> Normalized:
    rec = _envelope(row)
    try:
        rca_time = pipeline_compat.correlation().to_instant(rec["timestamp"])
        alert_event_id = _alert_event_id(rec)
    except (ValueError, TypeError) as exc:
        raise Quarantine("invalid_timestamp", str(exc)) from exc
    raw = rec["result"]
    try:
        result = _llm_result(raw)
    except Exception as exc:  # pydantic ValidationError or a non-dict result
        raise Quarantine("invalid_value", f"result: {exc}") from exc
    flags = set() if rec.get("schema_version") else {"legacy_unversioned"}
    if "incident_class" not in raw:
        flags.add("llm_output_legacy")
    evidence = rec.get("evidence_sources")
    values = {"rca_id": row["record_key"], "rca_time": fmt_ts(rca_time), "loki_ts_ns": row["entry_ts_ns"],
              "envelope_schema_version": rec.get("schema_version"), "alert_event_id": alert_event_id,
              "alert_name": rec["alert_name"], "alert_fingerprint": rec.get("alert_fingerprint"),
              **_envelope_identity(rec), "identity_status": rec.get("identity_status"),
              "evidence_sources": canonical_str(evidence) if evidence is not None else None,
              "root_cause": result["root_cause"], "incident_class": result["incident_class"],
              "analysis_status": raw.get("analysis_status"), "action_type": result["action_type"],
              "action_description": raw.get("action_description"), "threat_level": result["threat_level"],
              "action_targets": list(result["action_targets"]), "evidence": list(result["evidence"]),
              "confidence": float(result["confidence"]),
              "fallback_reason": enums.FALLBACK_ROOT_CAUSES.get(result["root_cause"]),
              "handoff_status": rec.get("handoff_status"), "remediation_dispatched": rec.get("remediation_dispatched"),
              "notification_dispatched": rec.get("notification_dispatched")}
    return Normalized(row["record_key"], values, flags, (fmt_ts(rca_time), row["record_key"]))


def transport_issue(row: dict, acq: dict) -> Normalized:
    line = row["line"]
    kind = ("loki_write_failed" if "failed to write post" in line
            else "fluentd_error_route" if acq["stream_class"] == "fluentd_error" else "other")
    values = {"transport_issue_id": row["record_key"], "event_time": fmt_ts(_loki_time(row)),
              "loki_ts_ns": row["entry_ts_ns"], "issue_kind": kind, "stream_labels": row["stream_labels"],
              "message_excerpt": pipeline_compat.log_line().mask_secrets(line)[:300]}
    return Normalized(row["record_key"], values, set(), (row["entry_ts_ns"], row["record_key"]))


NORMALIZERS = {
    "silver.db_log": db_log, "silver.app_log": app_log, "silver.network_event": network_event,
    "silver.metric_point": metric_point, "silver.alert_event": alert_event, "silver.rca_result": rca_result,
    "silver.transport_issue": transport_issue,
}
