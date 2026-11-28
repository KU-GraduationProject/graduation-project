"""Gold build checks run before commit (04 §6). BLOCK rules raise; WARN rules are reported."""
from __future__ import annotations

from contracts import enums, pipeline_compat

class GoldCheckError(ValueError):
    pass


def check_build(rows: dict, edges: list[dict], resolved: bool) -> list[str]:
    """Returns WARN messages; raises `GoldCheckError` on any BLOCK violation."""
    errors, warnings = [], []
    parents = {(e["child_dataset"], e["child_key"]) for e in edges}
    keys = {"gold.incident": "incident_id", "gold.rca_link": None, "gold.evidence_log": "evidence_id",
            "gold.evidence_metric": "evidence_id", "gold.evidence_network_flow": "evidence_id",
            "gold.scenario_link": "incident_id"}
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
    if errors:
        raise GoldCheckError("; ".join(errors))
    return warnings
