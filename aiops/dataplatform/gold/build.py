"""`build_gold`: one incident's current Silver builds + its Bronze acquisitions -> one Gold build.

Applies the exact incident window, scope matching (collector endpoint rules), the 04 §4 channel
status rules and the real-time prompt selection, and records Gold -> Silver edges. A Silver row
belongs to a channel when one of its Bronze parents came from that channel's acquisitions, so one
row can feed several scopes (many-to-many, 03 §3). No LLM is called (DEC-07).
"""
from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from datetime import timedelta

from bronze.plan import REMEDIATION_SELECTORS, WINDOW, remediation_chunks, remediation_window
from contracts import canonical, enums, pipeline_compat, schemas
from contracts.canonical import canonical_str, fmt_ts, parse_ts
from contracts.runtime import RunContext
from gold import render
from silver.build import coverage, coverage_inputs
from silver.normalize import instant_or_none
from storage import lineage_writer, paths
from storage.manifest import commit_build, flag_counts, manifest_by_id, output_rows, ref
from storage.store import LocalFsStore

IDENTITY = ("site", "source", "service", "runtime", "target")
UNCOLLECTED = {"scope_unavailable", "not_attempted"}
INCOMPLETE = {"partial", "truncated", "failed", "source_mismatch", "scope_unavailable", "not_attempted"}
MAX_PRIORITY, MAX_OTHER, MAX_SERIES = 30, 20, 5
GRACE_S = 300  # scenarios/v2/fixtures.pair_context default: alerts up to 5 min after a run ends


# ---- inputs ------------------------------------------------------------------------------

def plan_gold(store: LocalFsStore, plan: dict) -> dict | None:
    """Inputs of the incident's next Gold build, or None when they equal the current build's."""
    silver = {}
    for dataset in enums.SILVER_DATASETS:
        cov = coverage(dataset, plan)
        pointer = store.read_pointer("silver", dataset=dataset, coverage_id=cov["coverage_id"])
        if pointer:
            silver[dataset] = [pointer["manifest_id"]]
    if "silver.alert_event" not in silver:
        return None  # v1: the incident is anchored on its RCA envelope (01 §3.5)
    gold_cov = coverage("gold.incident", plan)
    acquisitions = (coverage_inputs(store, gold_cov, streams=enums.STREAM_CLASSES)
                    + coverage_inputs(store, coverage("silver.remediation_event", plan)))  # chunks (09 §3.3)
    inputs = [m for d in sorted(silver) for m in silver[d]] + acquisitions
    pointer = store.read_pointer("gold", incident_id=plan["incident_id"])
    if pointer:
        built = store.read_manifest("gold", pointer["build_id"])
        if built and built["inputs"] == inputs:
            return None
    return {"incident": plan, "silver_inputs": silver, "acquisitions": acquisitions}


def _silver(store, silver_inputs):
    """dataset -> [(row, build_id, parent acquisition ids)], plus quarantine rows with parents."""
    rows, quarantine = defaultdict(list), []
    for dataset, manifest_ids in silver_inputs.items():
        for manifest_id in manifest_ids:
            manifest = manifest_by_id(store, manifest_id)
            parents = defaultdict(set)
            for e in output_rows(store, manifest, "lineage.edge"):
                parents[(e["child_dataset"], e["child_key"])].add(e["parent_version"])
            pk = next(name for name, _, _ in schemas.columns(dataset))
            for row in output_rows(store, manifest, dataset):
                rows[dataset].append((row, manifest["build_id"], parents[(dataset, row[pk])]))
            for row in output_rows(store, manifest, "silver.quarantine"):
                quarantine.append((row, parents[("silver.quarantine", row["quarantine_id"])]))
    return rows, quarantine


# ---- channel rules -----------------------------------------------------------------------

def channel_status(identity_status, bests: dict, acqs: list, in_window: int, matched: int, skipped: Counter,
                   runtime: str) -> tuple[str, str | None]:
    """04 §4 rules 1-8, in order."""
    values = set(bests.values())
    reason_of = {a["query_name"]: a["status_reason"] for a in acqs}
    if identity_status != "resolved":
        return "unavailable", identity_status
    if not values or values <= UNCOLLECTED:
        first = next(iter(bests), None)
        return "unavailable", (reason_of.get(first) or bests.get(first)) if first else "not_attempted"
    if values <= {"failed", "source_mismatch"}:
        first = next(q for q in bests)
        return "failed", reason_of.get(first) or bests[first]
    if in_window >= 1 and matched == 0:
        if runtime == "host" and skipped.get("target_unresolvable"):
            return "unavailable", "host_target_field_absent"
        return "unavailable", skipped.most_common(1)[0][0] if skipped else "scope_unverified"
    incomplete = [q for q, s in bests.items() if s in INCOMPLETE]
    if incomplete:
        q = incomplete[0]
        return "partial", reason_of.get(q) if bests[q] in UNCOLLECTED else bests[q]
    if matched >= 1:
        return "complete", None
    if in_window == 0 and values <= {"ok", "empty_verified"}:
        return "complete_empty", None
    return "unavailable", "scope_unverified"


def _bests(acqs: list) -> dict:
    by_query = defaultdict(list)
    for a in acqs:
        by_query[a["query_name"]].append(a["status"])
    return {q: enums.best_status(s) for q, s in by_query.items()}


def _reacquisition_incomplete(acqs: list, bests: dict) -> bool:
    for query, best in bests.items():
        if best != "ok":
            continue
        same = [a for a in acqs if a["query_name"] == query]
        first_ok = min(a["requested_at"] for a in same if a["status"] == "ok")
        if any(a["requested_at"] > first_ok and a["status"] in ("partial", "truncated", "failed") for a in same):
            return True
    return False


def _match_log(row: dict, scope: dict) -> str | None:
    if "source_mismatch" in row["_quality_flags"]:
        return "target_mismatch"  # row came from another source than the scope (04 §3: never used in Gold)
    if row["runtime"] != scope["runtime"]:
        return "runtime_mismatch"
    if row["target"] == "UNKNOWN":
        return "target_unresolvable"
    if row["target"] != scope["target"] or row["site"] != scope["site"] or row["service"] != scope["service"]:
        return "target_mismatch"
    return None


def _match_network(row: dict, scope: dict, observer: dict) -> str | None:
    """Collector endpoint rule (collector/network.py `_parse`): observer, then runtime, then target field."""
    if any(row.get(k) != v for k, v in observer.items()):
        return "observer_mismatch"
    sides = [s for s in ("src", "dst") if row.get(f"{s}_service") == scope["service"]]
    runtime_sides = [s for s in sides if row.get(f"{s}_runtime") == scope["runtime"]]
    if not runtime_sides:
        return "runtime_mismatch"
    field = "target" if scope["runtime"] != "container" else "container"
    values = [row.get(f"{s}_{field}") for s in runtime_sides]
    if scope["target"] in values:
        return None
    return "target_unresolvable" if all(v is None for v in values) else "target_mismatch"


def _event(row: dict) -> dict:
    event = {k: row[k] for k in schemas.NETWORK_EVENT_FIELDS}
    event["observer_meta"] = json.loads(row["observer_meta"]) if row["observer_meta"] else None
    return event


# ---- build -------------------------------------------------------------------------------

def build_gold(incident: dict, silver_inputs: dict, acquisitions: list[str], store: LocalFsStore,
               run: RunContext) -> dict:
    build_id = run.new_build_id("gb")
    request = incident["request"]
    incident_id = incident["incident_id"]
    rows, quarantine = _silver(store, silver_inputs)
    acq_rows = [output_rows(store, manifest_by_id(store, m), "bronze.acquisition")[0] for m in acquisitions]

    alert_rows = [(r, b) for r, b, _ in rows["silver.alert_event"]
                  if canonical.incident_id(r["alert_event_id"]) == incident_id]
    if not alert_rows:
        raise ValueError(f"{incident_id}: no silver.alert_event row anchors this incident")
    alert, alert_build = alert_rows[0]
    anchor = parse_ts(alert["starts_at"])
    ws, we = anchor - WINDOW, anchor + WINDOW
    identity_status = alert["identity_status"]
    resolved = identity_status == "resolved"
    policy = pipeline_compat.policy_evaluator()

    def in_window_ns(ns):
        return ws <= canonical.from_ns(ns) <= we

    def in_window_ts(text):
        return ws <= parse_ts(text) <= we

    scopes = []
    for a in acq_rows:
        if a["scope_role"] == "global":
            continue
        key = (a["scope_role"], a["scope_identity"])
        if key not in [s["key"] for s in scopes]:
            scopes.append({"key": key, "role": a["scope_role"], "identity": json.loads(a["scope_identity"])})
    scopes.sort(key=lambda s: enums.SCOPE_ROLES.index(s["role"]))

    channels, ev_log, ev_metric, ev_flow = [], [], [], []
    log_edges, metric_edges, flow_edges = [], [], []
    for scope in scopes:
        ident = scope["identity"]
        for channel in enums.CHANNELS:
            acqs = [a for a in acq_rows if a["scope_role"] == scope["role"] and a["scope_identity"] == scope["key"][1]
                    and a["stream_class"] in enums.CHANNEL_STREAMS[channel]]
            acq_ids = {a["acquisition_id"] for a in acqs}
            bests = _bests(acqs)
            datasets = {"log": ("silver.app_log", "silver.db_log"), "metric": ("silver.metric_point",),
                        "network": ("silver.network_event",)}[channel]
            candidates = [(d, r, b) for d in datasets for r, b, parents in rows[d] if parents & acq_ids]
            if channel == "log":
                window = [(d, r, b) for d, r, b in candidates if in_window_ns(r["loki_ts_ns"])]
            elif channel == "metric":
                window = [(d, r, b) for d, r, b in candidates if in_window_ts(r["sample_time"])]
            else:
                window = [(d, r, b) for d, r, b in candidates if in_window_ts(r["event_time"])
                          and ident["service"] in (r["src_service"], r["dst_service"])]
            observer = json.loads(acqs[0]["scope_selector"]) if channel == "network" and acqs else {}
            skipped, matched = Counter(), []
            for d, r, b in window:
                reason = (_match_log(r, ident) if channel == "log" else _match_network(r, ident, observer)
                          if channel == "network" else ("target_mismatch" if "source_mismatch" in r["_quality_flags"]
                                                        else None))
                if reason:
                    skipped[reason] += 1
                else:
                    matched.append((d, r, b))
            status, reason = channel_status(identity_status if scope["role"] == "primary" else
                                            ("resolved" if resolved else identity_status),
                                            bests, acqs, len(window), len(matched), skipped, ident["runtime"])
            flags = set()
            selected_parents = 0
            if resolved:
                if channel == "log":
                    rows_out, used = _log_evidence(incident_id, build_id, run, scope["role"], matched)
                    ev_log.extend(rows_out)
                    log_edges.extend(used)
                    selected_parents = sum(1 for r in rows_out if r["selected_for_prompt"])
                    flags |= {f for r in rows_out for f in r["_quality_flags"]}
                elif channel == "metric":
                    rows_out, used = _metric_evidence(incident_id, build_id, run, scope["role"], matched)
                    ev_metric.extend(rows_out)
                    metric_edges.extend(used)
                    selected = {r["evidence_id"] for r in rows_out if r["selected_for_prompt"]}
                    selected_parents = sum(1 for e in used if e["child_key"] in selected)
                    flags |= {f for _, r, _ in matched for f in r["_quality_flags"]}
                else:
                    rows_out, used = _flow_evidence(incident_id, build_id, run, scope, matched, policy)
                    ev_flow.extend(rows_out)
                    flow_edges.extend(used)
                    selected = {r["evidence_id"] for r in rows_out if r["selected_for_prompt"]}
                    selected_parents = sum(1 for e in used if e["child_key"] in selected)
                    flags |= {f for r in rows_out for f in r["_quality_flags"]}
            if _reacquisition_incomplete(acqs, bests):
                flags.add("reacquisition_incomplete")
            if acqs and not all(a["window_closed"] for a in acqs):
                flags.add("window_open")
            channel_quarantine = sum(1 for q, parents in quarantine if parents & acq_ids
                                     and q["target_dataset"] in datasets)
            channels.append(schemas.project("gold.incident_channel", {
                "incident_id": incident_id, "gold_build_id": build_id, "channel": channel,
                "scope_role": scope["role"], **{k: ident[k] for k in IDENTITY}, "status": status,
                "status_reason": reason, "acquisition_ids": [a["acquisition_id"] for a in acqs],
                "acquisition_statuses": [a["status"] for a in acqs], "rows_in_window": len(window),
                "rows_matched": len(matched), "rows_selected": selected_parents, "skipped": sum(skipped.values()),
                "skipped_reasons": canonical_str(dict(skipped)), "quarantined": channel_quarantine,
                "truncated": "truncated" in bests.values(),
                "window_closed": all(a["window_closed"] for a in acqs),
                **_envelope(build_id, run, flags)}))

    rca_rows = sorted(((r, b) for r, b, _ in rows["silver.rca_result"]
                       if r["alert_event_id"] == alert["alert_event_id"]), key=lambda p: p[0]["rca_time"])
    links, link_edges = [], []
    for r, b in rca_rows:
        links.append(schemas.project("gold.rca_link", {
            "incident_id": incident_id, "gold_build_id": build_id, "rca_id": r["rca_id"],
            "link_type": "post_hoc_same_alert", "rca_time": r["rca_time"], "fallback_reason": r["fallback_reason"],
            **_envelope(build_id, run, set())}))
        link_edges.append(lineage_writer.edge("gold.rca_link", f"{incident_id}:{r['rca_id']}", build_id, "silver.rca_result",
                                              r["rca_id"], b, "linked_from", run.run_id))

    scenario_link, scenario_edges = _scenario_link(incident_id, build_id, run, alert, alert_build, anchor, rows,
                                                   quarantine, acq_rows)
    remediation, remediation_edges, remediation_used = _remediation_links(incident_id, build_id, run, request, alert,
                                                                          anchor, rca_rows, rows, acq_rows)

    transport = [r for r, _, _ in rows["silver.transport_issue"] if in_window_ns(r["loki_ts_ns"])]
    fluentd = [a["status"] for a in acq_rows if a["stream_class"] == "fluentd_internal"]
    primary = [c["status"] for c in channels if c["scope_role"] == "primary"]
    overall = ("complete" if primary and all(s in ("complete", "complete_empty", "not_applicable") for s in primary)
               else "insufficient" if "complete" not in primary else "partial")
    incident_row = schemas.project("gold.incident", {
        "incident_id": incident_id, "gold_build_id": build_id, "alert_event_id": alert["alert_event_id"],
        "alertname": alert["alertname"], "severity": alert["severity"], "category": alert["category"],
        "rulepack_target": alert["rulepack_target"], **{k: alert[k] for k in IDENTITY},
        "identity_status": identity_status, "anchor_time": alert["starts_at"], "window_start": fmt_ts(ws),
        "window_end": fmt_ts(we), "window_policy": request.get("window_policy", "symmetric_5m"),
        "scope_policy": request.get("scope_policy", "alert_identity_only"), "overall_status": overall,
        "evidence_count": len(ev_log) + len(ev_metric) + len(ev_flow), "rca_count": len(links),
        "transport_loss_suspected": bool(transport),
        "transport_check_status": enums.best_status(fluentd) or "not_attempted",
        "input_versions": canonical_str({d: [manifest_by_id(store, m)["build_id"] for m in ids]
                                         for d, ids in sorted(silver_inputs.items())}),
        "built_at": fmt_ts(run.now()), **_envelope(build_id, run, set())})
    anchor_edge = lineage_writer.edge("gold.incident", incident_id, build_id, "silver.alert_event",
                                      alert["alert_event_id"], alert_build, "anchored_on", run.run_id)
    edges = log_edges + metric_edges + flow_edges + link_edges + [anchor_edge] + scenario_edges + remediation_edges

    gold_rows = {"gold.incident": [incident_row], "gold.incident_channel": channels, "gold.evidence_log": ev_log,
                 "gold.evidence_metric": ev_metric, "gold.evidence_network_flow": ev_flow, "gold.rca_link": links,
                 "gold.scenario_link": [scenario_link], "gold.remediation_link": remediation}
    from gold.checks import check_build
    check_build(gold_rows, edges, resolved,
                remediation={"alertname": alert["alertname"], "anchor": anchor, "events": remediation_used})

    date = paths.date_of(alert["starts_at"])
    outputs = [(d, paths.gold_file(d, incident_id, date, build_id), gold_rows[d]) for d in enums.GOLD_DATASETS]
    outputs.append(("lineage.edge", paths.edge_file(build_id), edges))
    previous = store.read_pointer("gold", incident_id=incident_id)
    manifest = commit_build(
        store, run, layer="gold", build_id=build_id, plan_id=incident["plan_id"], incident_id=incident_id,
        coverage_id=coverage("gold.incident", incident)["coverage_id"], build_status=overall,
        inputs=[m for d in sorted(silver_inputs) for m in silver_inputs[d]] + list(acquisitions), outputs=outputs,
        quality={"flag_counts": flag_counts(r for d in enums.GOLD_DATASETS for r in gold_rows[d]),
                 "quarantined": 0, "skipped": 0},
        supersedes=previous["manifest_id"] if previous else None, created_at=run.now())
    return {**ref(manifest), "incident_id": incident_id}


def pair_runs(runs: list[dict], anchor, grace_s: int = GRACE_S) -> tuple[str, list[dict]]:
    """`scenarios/v2/fixtures.pair_context` over `silver.scenario_run` rows: the `ok` runs with
    started_at <= anchor <= ended_at + grace (both ends inclusive). Exactly one -> `paired`."""
    grace = timedelta(seconds=grace_s)
    hits = sorted((r for r in runs if r["status"] == "ok"
                   and parse_ts(r["started_at"]) <= anchor <= parse_ts(r["ended_at"]) + grace),
                  key=lambda r: (r["started_at"], r["scenario_run_id"]))
    return ("paired" if len(hits) == 1 else "ambiguous_run" if hits else "no_run"), hits


def _scenario_link(incident_id, build_id, run, alert, alert_build, anchor, rows, quarantine, acq_rows):
    """gold.scenario_link: always one row, so an incident without a run is recorded, never dropped (#71).
    Answer labels are not here; evaluation looks them up in scenarios/v2/registry.py by `scenario_id`."""
    log_status = enums.best_status([a["status"] for a in acq_rows if a["stream_class"] == "scenario_run"]) \
        or "not_attempted"
    runs = {r["scenario_run_id"]: (r, b) for r, b, _ in rows["silver.scenario_run"]}
    if log_status in ("ok", "empty_verified"):
        status, hits = pair_runs([r for r, _ in runs.values()], anchor)
    else:
        status, hits = "run_log_unavailable", []
    paired = hits[0] if status == "paired" else {}
    flags = {"run_log_quarantined"} if any(q["target_dataset"] == "silver.scenario_run" for q, _ in quarantine) \
        else set()
    row = schemas.project("gold.scenario_link", {
        "incident_id": incident_id, "gold_build_id": build_id, "link_status": status,
        "pair_time": alert["starts_at"], "pair_time_source": "alert_starts_at", "grace_s": GRACE_S,
        "candidate_run_ids": [h["scenario_run_id"] for h in hits], "scenario_run_id": paired.get("scenario_run_id"),
        "scenario_id": paired.get("scenario_id"), "variant_id": paired.get("variant_id"), "seed": paired.get("seed"),
        "run_started_at": paired.get("started_at"), "run_ended_at": paired.get("ended_at"),
        "run_log_status": log_status, **_envelope(build_id, run, flags)})
    edges = [lineage_writer.edge("gold.scenario_link", incident_id, build_id, "silver.alert_event",
                                 alert["alert_event_id"], alert_build, "anchored_on", run.run_id)]
    edges.extend(lineage_writer.edge("gold.scenario_link", incident_id, build_id, "silver.scenario_run",
                                     h["scenario_run_id"], runs[h["scenario_run_id"]][1], "run_candidate", run.run_id)
                 for h in hits)
    return row, edges


# ---- gold.remediation_link (#77, DEC-19, docs/data-platform/09 §5) ------------------------

_NO_DETAIL = {"link_basis": None, "action_type": None, "final_state": None, "targets": [],
              "approval_requested_at": None, "approved_at": None, "action_started_at": None,
              "action_verified_at": None, "recovery_due_at": None, "recovery_verified_at": None,
              "service_recovered_at": None, "approved_by": None, "execution_results": "[]", "block_events": "[]",
              "mttr_sec": None, "approval_latency_sec": None}
_DETAIL_TIMES = ("approval_requested_at", "approved_at", "action_started_at", "action_verified_at", "recovery_due_at",
                 "recovery_verified_at", "service_recovered_at")


def is_record_event(event: dict) -> bool:
    """`_push_record` rows: the only events that carry the record state and `alert_active_at`."""
    return event["stream_job"] == "aiops-remediation" and event["record_state"] is not None


def cross_check(event: dict, alertname: str, anchor) -> bool:
    """09 §5.1: same alert name and `alert_active_at` == anchor as instants (C-4), never as strings."""
    return (event["alertname"] == alertname and event["alert_active_at"] is not None
            and parse_ts(event["alert_active_at"]) == anchor)


def remediation_chunk_reasons(acqs: list[dict], expected: list[tuple]) -> list[str]:
    """`window_open` / `acquisition_incomplete` over the planned (query_name, window_start, window_end) chunks."""
    by_chunk = defaultdict(list)
    for a in acqs:
        by_chunk[(a["query_name"], a["window_start"], a["window_end"])].append(a)
    reasons = set()
    for chunk in expected:
        got = by_chunk.get(tuple(chunk))
        if not got:
            reasons.add("acquisition_incomplete")
            continue
        if not any(a["window_closed"] for a in got):
            reasons.add("window_open")
        if enums.best_status(a["status"] for a in got) not in ("ok", "empty_verified"):
            reasons.add("acquisition_incomplete")
    return [r for r in enums.REMEDIATION_PARTIAL_REASONS if r in reasons]


def _number(value):
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _remediation_detail(used: list[dict], records: list[dict]) -> dict:
    last = records[-1]
    timings = json.loads(last["timings"]) if last["timings"] else {}
    times = {k: fmt_ts(t) if (t := instant_or_none(timings.get(k))) else None for k in _DETAIL_TIMES}
    approvals = [e for e in used if e["event"] == "manual_approval_executed"]
    blocks = [e for e in used if e["event"] in enums.REMEDIATION_BLOCK_EVENTS]
    return {"link_basis": "rca_remediation_id", "action_type": last["action_type"], "final_state": last["record_state"],
            "targets": list(last["targets"]), **times,
            "approved_by": next((e["approved_by"] for e in approvals if e["approved_by"] is not None), None),
            "execution_results": canonical_str([{"target": e["targets"][0] if e["targets"] else None,
                                                 "status": e["status"], "result": e["result"],
                                                 "verified": e["verified"]} for e in approvals]),
            "block_events": canonical_str([{"event": e["event"], "reason": e["reason"], "event_time": e["event_time"]}
                                           for e in blocks]),
            "mttr_sec": _number(timings.get("mttr_sec")),
            "approval_latency_sec": _number(timings.get("approval_latency_sec"))}


def remediation_link(rca: dict, events: list[dict], chunk_reasons: list[str], alertname: str, anchor,
                     window) -> tuple[dict, list[dict]]:
    """One RCA's link values and the Silver events it used. Only the exact `remediation_id` key links (DEC-19):
    never an alert name or time proximity. `policy_decision` is never attached in v1, even when it carries a
    `remediation_id` (#81): its link is the DEC-19 revision (`policy_decision_link=unlinked_no_key`)."""
    start, end = window
    rid = rca.get("remediation_id")  # null in silver.rca_result 1.0 builds
    used = sorted((e for e in events if rid is not None and e["remediation_id"] == rid
                   and e["event"] != "policy_decision" and start <= canonical.from_ns(e["loki_ts_ns"]) <= end),
                  key=lambda e: (e["event_time"], e["loki_ts_ns"], e["remediation_event_id"]))
    records = [e for e in used if is_record_event(e)]
    status = ("no_remediation_id" if rid is None else "events_not_found" if not records
              else "cross_check_failed" if not all(cross_check(e, alertname, anchor) for e in records) else "linked")
    detail = _remediation_detail(used, records) if status == "linked" else dict(_NO_DETAIL)
    if status == "linked":
        reasons = set(chunk_reasons)
        due = detail["recovery_due_at"]
        unsettled = detail["final_state"] not in enums.RECORD_STATES_SETTLED
        if (due is not None and parse_ts(due) > end) or (unsettled and "window_open" not in chunk_reasons):
            reasons.add("beyond_window")  # the outcome is decided after the window (09 §5.2)
        reasons = [r for r in enums.REMEDIATION_PARTIAL_REASONS if r in reasons]
        overall = "partial" if reasons else "complete"
    elif status == "events_not_found" and chunk_reasons:
        reasons, overall = list(chunk_reasons), "partial"  # the events may not have arrived yet
    else:
        reasons, overall = [], "unlinked"
    values = {"rca_id": rca["rca_id"], "rca_time": rca["rca_time"], "handoff_status": rca.get("handoff_status"),
              "remediation_id": rid, "link_status": status, "policy_decision_link": "unlinked_no_key", **detail,
              "remediation_status": overall, "partial_reasons": reasons,
              "remediation_window_start": fmt_ts(start), "remediation_window_end": fmt_ts(end)}
    return values, used if status == "linked" else []


def _remediation_links(incident_id, build_id, run, request, alert, anchor, rca_rows, rows, acq_rows):
    """gold.remediation_link: one row per gold.rca_link RCA (DQ-G10), edges to the RCA and every used event."""
    start, end = remediation_window(request)
    expected = [(name, fmt_ts(s), fmt_ts(e)) for s, e in remediation_chunks(start, end)
                for name, _ in REMEDIATION_SELECTORS]
    reasons = remediation_chunk_reasons([a for a in acq_rows if a["stream_class"] == "remediation_event"], expected)
    events = [r for r, _, _ in rows["silver.remediation_event"]]
    event_build = {r["remediation_event_id"]: b for r, b, _ in rows["silver.remediation_event"]}
    flags = {"window_open"} if "window_open" in reasons else set()
    out, edges, used_by = [], [], {}
    for r, b in rca_rows:
        values, used = remediation_link(r, events, reasons, alert["alertname"], anchor, (start, end))
        out.append(schemas.project("gold.remediation_link", {"incident_id": incident_id, "gold_build_id": build_id,
                                                             **values, **_envelope(build_id, run, flags)}))
        key = f"{incident_id}:{r['rca_id']}"
        edges.append(lineage_writer.edge("gold.remediation_link", key, build_id, "silver.rca_result", r["rca_id"], b,
                                         "linked_from", run.run_id))
        edges.extend(lineage_writer.edge("gold.remediation_link", key, build_id, "silver.remediation_event",
                                         e["remediation_event_id"], event_build[e["remediation_event_id"]],
                                         "linked_from", run.run_id) for e in used)
        used_by[r["rca_id"]] = used
    return out, edges, used_by


def _envelope(build_id, run, flags) -> dict:
    return {"_schema_version": schemas.SCHEMA_VERSION, "_dataset_version": build_id, "_run_id": run.run_id,
            "_quality_flags": sorted(flags)}


def _original_line(row: dict) -> str:
    body = json.loads(row["body"])
    if row.get("log_format") == "absent" and set(body) == {"line"}:
        return body["line"]
    return row["body"]


def _log_evidence(incident_id, build_id, run, role, matched):
    """All matched logs become rows; `selected_for_prompt` = builder.py priority ≤30 + other ≤20."""
    ordered = sorted(matched, key=lambda t: (t[1]["loki_ts_ns"], t[1].get("log_id") or t[1].get("db_log_id")))
    priority = [t for t in ordered if t[1]["is_priority"]]
    other = [t for t in ordered if not t[1]["is_priority"]]
    selected = sorted(priority[:MAX_PRIORITY] + other[:MAX_OTHER], key=lambda t: t[1]["loki_ts_ns"])
    rank = {id(t): i + 1 for i, t in enumerate(selected)}
    out, used = [], []
    for t in ordered:
        dataset, row, build = t
        short = dataset.split(".")[1]
        key = row["log_id"] if short == "app_log" else row["db_log_id"]
        rendered, masked = render.render_with_mask_flag(json.loads(row["stream_labels"]), _original_line(row))
        evidence = canonical.evidence_log_id(incident_id, short, key)
        flags = set(row["_quality_flags"]) | ({"masked"} if masked else set())
        out.append(schemas.project("gold.evidence_log", {
            "evidence_id": evidence, "incident_id": incident_id, "gold_build_id": build_id, "scope_role": role,
            "log_dataset": short, "silver_key": key, "event_time": row["event_time"], "severity": row["severity"],
            "is_priority": row["is_priority"], "rank": rank.get(id(t)), "selected_for_prompt": id(t) in rank,
            "rendered_line": rendered, **_envelope(build_id, run, flags)}))
        used.append(lineage_writer.edge("gold.evidence_log", evidence, build_id, dataset, key, build,
                                        "selected_from", run.run_id))
    return out, used


def _metric_evidence(incident_id, build_id, run, role, matched):
    series = {}
    for _, row, build in sorted(matched, key=lambda t: (t[1]["query_name"], t[1]["series_labels"],
                                                       t[1]["sample_ts_ms"])):
        series.setdefault((row["query_name"], row["series_labels"]), []).append((row, build))
    out, used, per_query = [], [], Counter()
    for (query, labels_text), points in series.items():
        per_query[query] += 1
        rank = per_query[query]
        finite = [(r, r["value"]) for r, _ in points if isinstance(r["value"], (int, float))
                  and r["value"] == r["value"] and r["value"] not in (float("inf"), float("-inf"))]
        values = [v for _, v in finite]
        labels = json.loads(labels_text)
        evidence = canonical.evidence_metric_id(incident_id, query, labels)
        latest = values[-1] if values else None
        peak = max(values) if values else None
        out.append(schemas.project("gold.evidence_metric", {
            "evidence_id": evidence, "incident_id": incident_id, "gold_build_id": build_id, "scope_role": role,
            "query_name": query, "metric_name": points[0][0]["metric_name"], "series_labels": labels_text,
            "samples": len(values), "latest": latest, "peak": peak, "minimum": min(values) if values else None,
            # math.fsum: correctly rounded on every Python (3.12+ sum() is compensated, 3.11 is not)
            "mean": math.fsum(values) / len(values) if values else None,
            "first_time": finite[0][0]["sample_time"] if finite else None,
            "last_time": finite[-1][0]["sample_time"] if finite else None,
            "nonfinite_count": len(points) - len(values), "rank": rank,
            "selected_for_prompt": rank <= MAX_SERIES and bool(values),
            "rendered_line": render.metric_line(query, latest, peak, len(values)) if values
            else f"{query}: no finite samples",
            **_envelope(build_id, run, {f for r, _ in points for f in r["_quality_flags"]})}))
        used.extend(lineage_writer.edge("gold.evidence_metric", evidence, build_id, "silver.metric_point",
                                        r["metric_point_id"], b, "aggregated_from", run.run_id) for r, b in points)
    return out, used


def _flow_evidence(incident_id, build_id, run, scope, matched, policy):
    ordered = sorted(matched, key=lambda t: (t[1]["event_time"], t[1]["network_event_id"]))
    events = []
    for _, row, build in ordered:
        event = _event(row)
        event["_row"], event["_build"] = row, build
        events.append(event)
    out, used = [], []
    for rank, (key, st) in enumerate(render.aggregate_flows(events), start=1):
        src, dst, dst_ip, dst_port, proto = key
        evidence = canonical.evidence_flow_id(incident_id, scope["role"], scope["identity"], src, dst, dst_ip,
                                              dst_port, proto)
        decision = policy.evaluate({"src_service": src, "dst_service": dst, "dst_ip": dst_ip,
                                    "dst_port": dst_port}) if policy else None
        allow = ("not_evaluated" if decision is None else "not_applicable" if not decision.applicable
                 else "ok" if decision.authorized else "violation")
        flow_rows = [e["_row"] for e in st["events"]]
        out.append(schemas.project("gold.evidence_network_flow", {
            "evidence_id": evidence, "incident_id": incident_id, "gold_build_id": build_id,
            "scope_role": scope["role"], "scope_identity": canonical_str(scope["identity"]), "src_service": src,
            "dst_service": dst, "dst_ip": dst_ip, "dst_port": dst_port, "protocol": proto, "conns": st["conns"],
            "states": canonical_str(dict(st["states"])), "app_protocols": canonical_str(dict(st["apps"])),
            "bytes_sent_sum": sum(st["sent"]) if st["sent"] else None,
            "bytes_received_sum": sum(st["recv"]) if st["recv"] else None,
            "duration_ms_avg": sum(st["dur"]) / len(st["dur"]) if st["dur"] else None,
            "duration_ms_max": max(st["dur"]) if st["dur"] else None, "early_count": len(st["early_ts"]),
            "early_first_time": fmt_ts(pipeline_compat.correlation().to_instant(min(st["early_ts"])))
            if st["early_ts"] else None,
            "early_peak_bytes": max(st["early_bytes"]) if st["early_bytes"] else None,
            "allowlist_decision": allow, "allowlist_reason": decision.reason if decision else None,
            "events_matched": len(st["events"]), "rank": rank, "selected_for_prompt": rank <= render.MAX_FLOWS,
            "rendered_line": render.flow_line(st, policy),
            **_envelope(build_id, run, {f for r in flow_rows for f in r["_quality_flags"]})}))
        used.extend(lineage_writer.edge("gold.evidence_network_flow", evidence, build_id, "silver.network_event",
                                        e["_row"]["network_event_id"], e["_build"], "aggregated_from", run.run_id)
                    for e in st["events"])
    return out, used
