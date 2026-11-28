"""Vocabularies of 01/03/04. Anything outside these sets is a contract violation."""
from __future__ import annotations

STREAM_CLASSES = ("app_log", "db_log", "network_event", "metric", "rca_result", "rca_error",
                  "fluentd_internal", "fluentd_error", "scenario_run", "remediation_event")
SCOPE_ROLES = ("primary", "related", "global")
SOURCE_SYSTEMS = ("loki", "prometheus", "scenario_run_log")

# 04 §1 acquisition status
ACQ_STATUSES = ("ok", "empty_verified", "empty_unverified", "truncated", "partial", "failed",
                "source_mismatch", "scope_unavailable", "not_attempted")
FAILURE_REASONS = ("api_error", "timeout", "connection_error", "invalid_response", "auth_error")
SCOPE_UNAVAILABLE_REASONS = ("source_unknown", "collector_unmapped", "no_matching_series")
# scenario run log (file source): not configured -> not_attempted; unreadable -> failed
RUN_LOG_REASONS = ("run_log_unconfigured", "file_not_found", "read_error")
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
                 "reacquisition_incomplete", "masked", "run_log_quarantined")

EVENT_TIME_SOURCES = ("loki_entry", "body_timestamp", "receiver_fallback", "prometheus_sample")
SEVERITIES = ("TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "UNKNOWN")
LABEL_PROFILES = ("release_v1", "legacy")
QUARANTINE_REASONS = ("invalid_json", "not_object", "unsupported_schema_version", "missing_required_field",
                      "invalid_timestamp", "invalid_value")
SKIPPED_REASONS = ("observer_mismatch", "runtime_mismatch", "target_unresolvable", "target_mismatch")
ISSUE_KINDS = ("loki_write_failed", "fluentd_error_route", "other")
ALLOWLIST_DECISIONS = ("ok", "violation", "not_applicable", "not_evaluated")
LINK_TYPES = ("post_hoc_same_alert", "consumed_gold")
RELATIONS = ("normalized_from", "quarantined_from", "anchored_on", "selected_from", "aggregated_from", "linked_from",
             "run_candidate")
# gold.scenario_link (#71): `pair_context` outcomes + run log not readable
LINK_STATUSES = ("paired", "no_run", "ambiguous_run", "run_log_unavailable")
# Evaluation answer labels (= scenarios/v2/fixtures.ANSWER_LABEL_KEYS, fixed by a test). Never a Gold column (DQ-G08).
ANSWER_LABEL_KEYS = ("threat_level", "expected_action", "expected_action_ideal", "incident_class")
# gold.remediation_link (#77, DEC-19, docs/data-platform/09 §5). Exact key only; no heuristic link basis.
REMEDIATION_LINK_BASES = ("rca_remediation_id",)
REMEDIATION_LINK_STATUSES = ("linked", "no_remediation_id", "events_not_found", "cross_check_failed")
REMEDIATION_STATUSES = ("complete", "partial", "unlinked")
REMEDIATION_PARTIAL_REASONS = ("window_open", "acquisition_incomplete", "beyond_window")
POLICY_DECISION_LINKS = ("unlinked_no_key",)  # v1: not linked even with #81's keys (DEC-19 revision follows)
# Remediation vocabularies copied from aiops/remediation (store.py states, main.py event names); never imported.
REMEDIATION_JOBS = ("aiops-remediation", "aiops-timeline")
REMEDIATION_TIMELINE_EVENTS = ("remediation_decision_started", "manual_approval_executed", "auto_remediation_completed",
                               "recovery_approval_required")
REMEDIATION_BLOCK_EVENTS = ("evidence_gate_blocked", "capture_blocked", "db_backup_failed",
                            "duplicate_execution_suppressed")
RECORD_STATES_UNSETTLED = ("PROPOSED", "AWAITING_APPROVAL", "APPROVED", "EXECUTING", "RECOVERY_PENDING",
                           "RECOVERY_APPROVAL_REQUIRED", "RECOVERING")
RECORD_STATES_SETTLED = ("VERIFIED", "FAILED", "BLOCKED", "SKIPPED", "REJECTED", "EXPIRED", "SUPERSEDED", "RECOVERED",
                         "RECOVERY_FAILED", "NEEDS_REVIEW", "UNKNOWN", "RECOVERY_UNKNOWN")
# remediation/store.py `RemediationRecord.timings()` keys (alert_active_at has its own Silver column)
REMEDIATION_TIMING_KEYS = ("approval_requested_at", "approved_at", "action_started_at", "action_verified_at",
                           "recovery_due_at", "recovery_started_at", "recovery_verified_at", "service_recovered_at",
                           "restore_duration_sec", "approval_latency_sec", "action_duration_sec",
                           "recovery_duration_sec", "mttr_sec", "service_recovery_sec")
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
    "silver.scenario_run": ("scenario_run",),
    "silver.remediation_event": ("remediation_event",),
}
SILVER_DATASETS = tuple(sorted(SILVER_SOURCES))
GOLD_DATASETS = ("gold.incident", "gold.incident_channel", "gold.evidence_log", "gold.evidence_metric",
                 "gold.evidence_network_flow", "gold.rca_link", "gold.scenario_link", "gold.remediation_link")
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
