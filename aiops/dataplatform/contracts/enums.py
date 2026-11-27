"""Vocabularies of 01/03/04. Anything outside these sets is a contract violation."""
from __future__ import annotations

STREAM_CLASSES = ("app_log", "db_log", "network_event", "metric", "rca_result", "rca_error",
                  "fluentd_internal", "fluentd_error")
SCOPE_ROLES = ("primary", "related", "global")
SOURCE_SYSTEMS = ("loki", "prometheus")

# 04 §1 acquisition status
ACQ_STATUSES = ("ok", "empty_verified", "empty_unverified", "truncated", "partial", "failed",
                "source_mismatch", "scope_unavailable", "not_attempted")
FAILURE_REASONS = ("api_error", "timeout", "connection_error", "invalid_response", "auth_error")
SCOPE_UNAVAILABLE_REASONS = ("source_unknown", "collector_unmapped", "no_matching_series")
# 04 §4 "best status" order: earlier = better.
BEST_STATUS_ORDER = ("ok", "truncated", "partial", "empty_verified", "empty_unverified", "source_mismatch",
                     "failed", "scope_unavailable", "not_attempted")
SERIES_PREFLIGHT = ("present", "absent", "not_run")

CHANNELS = ("log", "metric", "network")
CHANNEL_STATUSES = ("complete", "complete_empty", "partial", "failed", "unavailable", "not_applicable")
OVERALL_STATUSES = ("complete", "partial", "insufficient")

# 04 §3 record flags
QUALITY_FLAGS = ("log_truncated", "log_partial_incomplete", "log_parse_error", "log_time_parse_error",
                 "source_mismatch", "event_time_fallback", "identity_unverified", "duplicate", "value_revised",
                 "nonfinite_value", "legacy_unversioned", "llm_output_legacy", "window_open", "partial_acquisition",
                 "reacquisition_incomplete", "masked")

EVENT_TIME_SOURCES = ("loki_entry", "body_timestamp", "receiver_fallback", "prometheus_sample")
SEVERITIES = ("TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "UNKNOWN")
LABEL_PROFILES = ("release_v1", "legacy")
QUARANTINE_REASONS = ("invalid_json", "not_object", "unsupported_schema_version", "missing_required_field",
                      "invalid_timestamp", "invalid_value")
SKIPPED_REASONS = ("observer_mismatch", "runtime_mismatch", "target_unresolvable", "target_mismatch")
ISSUE_KINDS = ("loki_write_failed", "fluentd_error_route", "other")
ALLOWLIST_DECISIONS = ("ok", "violation", "not_applicable", "not_evaluated")
LINK_TYPES = ("post_hoc_same_alert", "consumed_gold")
RELATIONS = ("normalized_from", "quarantined_from", "anchored_on", "selected_from", "aggregated_from", "linked_from")
ORCHESTRATORS = ("airflow", "local_cli", "test")
RUN_STATUSES = ("success", "failed", "partial")

# Silver dataset <- Bronze stream classes it reads (01 §2.4, §3).
SILVER_SOURCES = {
    "silver.db_log": ("db_log",),
    "silver.app_log": ("app_log",),
    "silver.network_event": ("network_event",),
    "silver.metric_point": ("metric",),
    "silver.alert_event": ("rca_result",),
    "silver.rca_result": ("rca_result",),
    "silver.transport_issue": ("fluentd_internal", "fluentd_error"),
}
SILVER_DATASETS = tuple(sorted(SILVER_SOURCES))
GOLD_DATASETS = ("gold.incident", "gold.incident_channel", "gold.evidence_log", "gold.evidence_metric",
                 "gold.evidence_network_flow", "gold.rca_link")
CHANNEL_STREAMS = {"log": ("app_log", "db_log"), "metric": ("metric",), "network": ("network_event",)}

# DQ-B06: streams the data platform must never read (00 §9).
FORBIDDEN_SELECTOR_TOKENS = ('job="network-experiment"', "network-experiment", "heldout", "Heldout")

# 01 §3.6: fallback RCA root causes, matched by exact string equality only.
FALLBACK_ROOT_CAUSES = {
    "Observation source unresolved or scoped evidence unavailable — manual investigation required": "source_unresolved",
    "LLM 응답 파싱 실패 — 수동 확인 필요": "llm_parse_failure",
}


def best_status(statuses) -> str | None:
    statuses = list(statuses)
    return min(statuses, key=BEST_STATUS_ORDER.index) if statuses else None
