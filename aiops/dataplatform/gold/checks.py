"""Gold build checks run before commit (04 §6). BLOCK rules raise; WARN rules are reported."""
from __future__ import annotations

from contracts import enums, pipeline_compat

class GoldCheckError(ValueError):
    pass


REMEDIATION_DETAIL = ("action_type", "final_state", "approval_requested_at", "approved_at", "action_started_at",
                      "action_verified_at", "recovery_due_at", "recovery_verified_at", "service_recovered_at",
                      "approved_by", "mttr_sec", "approval_latency_sec")


def check_build(rows: dict, edges: list[dict], resolved: bool, remediation: dict | None = None) -> list[str]:
    """Returns WARN messages; raises `GoldCheckError` on any BLOCK violation. `remediation` = {alertname, anchor,
    events: {rca_id: used Silver events}} of `gold.remediation_link` for DQ-G12."""
    errors, warnings = [], []
    parents = {(e["child_dataset"], e["child_key"]) for e in edges}
    keys = {"gold.incident": "incident_id", "gold.rca_link": None, "gold.evidence_log": "evidence_id",
            "gold.evidence_metric": "evidence_id", "gold.evidence_network_flow": "evidence_id",
            "gold.scenario_link": "incident_id", "gold.remediation_link": None}
    for dataset, key in keys.items():
        for row in rows.get(dataset, []):
            child = f"{row['incident_id']}:{row['rca_id']}" if key is None else row[key]
            if (dataset, child) not in parents:
                errors.append(f"DQ-G01 {dataset} {child} has no Silver parent edge")
    primary = {c["channel"] for c in rows["gold.incident_channel"] if c["scope_role"] == "primary"}
    if primary != set(enums.CHANNELS):
        errors.append(f"DQ-G02 primary channels {sorted(primary)}")
    for c in rows["gold.incident_channel"]:
        if c["status"] not in enums.CHANNEL_STATUSES:
            errors.append(f"DQ-G02 channel status {c['status']!r}")
    mask = pipeline_compat.log_line().mask_secrets
    for dataset in ("gold.evidence_log", "gold.evidence_metric", "gold.evidence_network_flow"):
        for row in rows[dataset]:
            if mask(row["rendered_line"]) != row["rendered_line"]:
                errors.append(f"DQ-G04 {row['evidence_id']} rendered_line is not masked")
    if not resolved and any(rows[d] for d in ("gold.evidence_log", "gold.evidence_metric",
                                              "gold.evidence_network_flow")):
        errors.append("DQ-G05 unresolved identity must produce no evidence")
    selected = {}
    for row in rows["gold.evidence_log"]:
        if row["selected_for_prompt"]:
            selected.setdefault(("log", row["scope_role"], row["is_priority"]), []).append(row)
    for row in rows["gold.evidence_metric"]:
        if row["selected_for_prompt"]:
            selected.setdefault(("metric", row["scope_role"], row["query_name"]), []).append(row)
    for row in rows["gold.evidence_network_flow"]:
        if row["selected_for_prompt"]:
            selected.setdefault(("flow", row["scope_role"], row["scope_identity"]), []).append(row)
    for key, items in selected.items():
        limit = {"log": 30 if key[2] is True else 20, "metric": 5, "flow": 8}[key[0]]
        if len(items) > limit:
            warnings.append(f"DQ-G06 {key[0]} {key[1]} selection {len(items)} > {limit}")
    labels = set(enums.ANSWER_LABEL_KEYS)
    for dataset, items in rows.items():
        for row in items:
            if labels & set(row):
                errors.append(f"DQ-G08 {dataset} carries answer labels {sorted(labels & set(row))}")
    if "gold.scenario_link" in rows and len(rows["gold.scenario_link"]) != 1:
        errors.append(f"DQ-G09 gold.scenario_link has {len(rows['gold.scenario_link'])} rows (exactly 1)")
    if "gold.remediation_link" in rows:
        errors.extend(_check_remediation(rows, remediation))
    if errors:
        raise GoldCheckError("; ".join(errors))
    return warnings


def _check_remediation(rows: dict, context: dict | None) -> list[str]:
    from gold.build import cross_check, is_record_event
    errors = []
    links, rca = rows["gold.remediation_link"], rows.get("gold.rca_link", [])
    if len(links) != len(rca) or {r["rca_id"] for r in links} != {r["rca_id"] for r in rca}:
        errors.append(f"DQ-G10 gold.remediation_link has {len(links)} rows for {len(rca)} gold.rca_link rows")
    for row in links:
        linked = row["link_status"] == "linked"
        if row["link_status"] not in enums.REMEDIATION_LINK_STATUSES or row["policy_decision_link"] not in \
                enums.POLICY_DECISION_LINKS or row["link_basis"] not in (None,) + enums.REMEDIATION_LINK_BASES \
                or linked != (row["link_basis"] is not None):
            errors.append(f"DQ-G11 {row['rca_id']} link_status={row['link_status']} link_basis={row['link_basis']} "
                          f"policy_decision_link={row['policy_decision_link']}")
        elif not linked and (any(row[c] is not None for c in REMEDIATION_DETAIL) or row["targets"]
                             or row["execution_results"] != "[]" or row["block_events"] != "[]"):
            errors.append(f"DQ-G11 {row['rca_id']} {row['link_status']} row carries remediation details")
        if linked and context is not None:
            for event in context["events"].get(row["rca_id"], []):
                if is_record_event(event) and not cross_check(event, context["alertname"], context["anchor"]):
                    errors.append(f"DQ-G12 {row['rca_id']} event {event['remediation_event_id']} alert "
                                  f"{event['alertname']}@{event['alert_active_at']} is not the incident's")
    return errors
