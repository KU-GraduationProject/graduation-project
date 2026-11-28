"""`plan_incident`: incident request + OBSERVATION_BINDINGS -> acquisition plan items (05 §4 Track A).

Selectors come only from verified bindings (identity.parse_bindings). A scope without a binding
or selector becomes a `scope_unavailable` item that is recorded but never queried (01 §2.4).
Query strings reuse the Pipeline collector rules so real-time and batch ask the same thing.
"""
from __future__ import annotations

import json
from datetime import timedelta

from contracts import canonical, enums, pipeline_compat
from contracts.canonical import fmt_ts, h, ns_of, seconds_text

DEFAULT_LOKI_LIMIT = 5000
DEFAULT_MAX_PAGES = 100
WINDOW = timedelta(minutes=5)  # symmetric_5m: real-time parity (main.py:288)
UNKNOWN_SCOPE = {k: "UNKNOWN" for k in ("instance", "job", "observer", "runtime", "service", "site", "source",
                                        "target")}
# DEC-19 remediation window (docs/data-platform/09 §3.2): anchor - 5m - pad ~ anchor + horizon + pad. A constant —
# the data platform never reads Remediation settings: approval wait SLACK_APPROVAL_TTL_SEC default 900 s
# (remediation/slack_socket.py) + longest policy ttl_seconds 3600 s (PAUSE, policy/remediation_policy.yml) + 300 s.
# Change it together with DEC-19 when those values change.
REMEDIATION_HORIZON = timedelta(seconds=900 + 3600 + 300)
REMEDIATION_CHUNK = timedelta(minutes=15)  # 05 §6: no Loki request window longer than 15 minutes
REMEDIATION_SELECTORS = (("remediation_audit", "aiops-remediation"), ("remediation_timeline", "aiops-timeline"))


class ForbiddenSelector(ValueError):
    """DQ-B06: the plan would read a stream the data platform must never touch."""


class ChunkPlanError(ValueError):
    """DQ-B07: remediation chunks must tile the remediation window, each at most 15 minutes."""


def _ident():
    return pipeline_compat.identity()


def metric_queries(binding) -> dict[str, tuple[str, dict]]:
    """name -> (PromQL, expected series labels). Same strings as `MetricsCollector.fetch_around`."""
    selector = _ident().selector
    scope = binding.metrics
    s = selector(scope)
    queries, scopes = {}, {}
    if binding.identity.runtime == "container":
        cpu = selector({**scope, "cpu": "total"})
        queries = {
            "cpu_usage": f"rate(container_cpu_usage_seconds_total{cpu}[1m])",
            "memory_usage": f"container_memory_usage_bytes{s}",
            "memory_limit": f"container_spec_memory_limit_bytes{s}",
            "net_rx_bytes": f"rate(container_network_receive_bytes_total{s}[1m])",
            "net_tx_bytes": f"rate(container_network_transmit_bytes_total{s}[1m])",
        }
        if binding.metrics_profile == "gc-telemetry-v1":
            del queries["memory_usage"]
            del queries["net_tx_bytes"]
            queries["memory_working_set"] = f"container_memory_working_set_bytes{s}"
            stable_scope = {k: v for k, v in scope.items() if k != "id"}
            stable = selector(stable_scope)
            for name, metric in (("restart_count", "aiops_docker_container_restarts_total"),
                                 ("started_at_seconds", "aiops_docker_container_started_at_seconds")):
                queries[name] = metric + stable
                scopes[name] = stable_scope
    else:
        cpu = s[:-1] + ',mode!="idle"}'
        queries = {
            "host_cpu": f"avg by (job,instance) (rate(node_cpu_seconds_total{cpu}[1m]))",
            "host_mem": f"node_memory_MemAvailable_bytes{s} / node_memory_MemTotal_bytes{s}",
        }
        scopes["host_cpu"] = {k: scope[k] for k in ("job", "instance")}
    return {name: (query, scopes.get(name, scope)) for name, query in queries.items()}


def _check_allowed(text: str | None) -> None:
    if text and any(token in text for token in enums.FORBIDDEN_SELECTOR_TOKENS):
        raise ForbiddenSelector(f"forbidden stream in selector (DQ-B06): {text}")


def _log_stream_class(identity) -> str:
    return "db_log" if identity.service == "db" and identity.runtime == "host" else "app_log"


def incident_window(request: dict):
    """(anchor, event window, acquisition window) for the request (02 §5)."""
    if request.get("window_policy", "symmetric_5m") != "symmetric_5m":
        raise ValueError(f"unsupported window_policy: {request.get('window_policy')}")
    anchor = canonical.utc(pipeline_compat.correlation().to_instant(request["alert"]["starts_at"]))
    pad = timedelta(seconds=int(request.get("acquisition_padding_s", 60)))
    return anchor, (anchor - WINDOW, anchor + WINDOW), (anchor - WINDOW - pad, anchor + WINDOW + pad)


def remediation_window(request: dict):
    """(start, end) of the DEC-19 remediation window."""
    anchor, _, _ = incident_window(request)
    pad = timedelta(seconds=int(request.get("acquisition_padding_s", 60)))
    return anchor - WINDOW - pad, anchor + REMEDIATION_HORIZON + pad


def remediation_chunks(start, end, size=REMEDIATION_CHUNK) -> list[tuple]:
    """Consecutive chunks from `start`: each `size` long, the last one shorter. chunk i ends where i+1 starts."""
    chunks, cursor = [], start
    while cursor < end:
        chunks.append((cursor, min(cursor + size, end)))
        cursor = chunks[-1][1]
    return chunks


def check_remediation_chunks(chunks, start, end) -> None:
    """DQ-B07 (BLOCK at plan time): no gap, no overlap, nothing past the window, every chunk <= 15 minutes."""
    if not chunks or chunks[0][0] != start or chunks[-1][1] != end:
        raise ChunkPlanError(f"chunks do not cover the remediation window {start}..{end} (DQ-B07)")
    for chunk_start, chunk_end in chunks:
        if not chunk_start < chunk_end <= chunk_start + REMEDIATION_CHUNK:
            raise ChunkPlanError(f"chunk {chunk_start}..{chunk_end} is empty or longer than 15 minutes (DQ-B07)")
    for (_, previous_end), (next_start, _) in zip(chunks, chunks[1:]):
        if previous_end != next_start:
            raise ChunkPlanError(f"gap or overlap between chunks at {previous_end} / {next_start} (DQ-B07)")


def remediation_queries(alertname: str) -> dict[str, str]:
    """09 §3.1. Stream label matching only; the timeline selector keeps Remediation's own event names."""
    selector = _ident().selector
    events = "|".join(enums.REMEDIATION_TIMELINE_EVENTS)
    return {"remediation_audit": selector({"job": "aiops-remediation", "alert": alertname}),
            "remediation_timeline": selector({"job": "aiops-timeline", "alert": alertname})[:-1]
            + f',event=~"{events}"}}'}


def plan_incident(request: dict, bindings_raw: str) -> list[dict]:
    """Full acquisition plan of one incident. Filters (`stream_classes`) never change the binding set."""
    ident = _ident()
    alert = request["alert"]
    labels, annotations = alert["labels"], alert.get("annotations", {})
    anchor, _, (window_start, window_end) = incident_window(request)
    alert_event = canonical.alert_event_id(labels, anchor)
    incident = canonical.incident_id(alert_event)
    if request.get("expected_incident_id") and request["expected_incident_id"] != incident:
        raise ValueError(f"incident id mismatch: computed {incident}, expected {request['expected_incident_id']}")
    rows = json.loads(bindings_raw or "[]")
    bindings = ident.parse_bindings(bindings_raw or "[]")
    shas = {id(b): h(row) for b, row in zip(bindings, rows)}
    plan_id = f"incident:{incident}"
    ctx = {
        "plan_id": plan_id, "incident_id": incident, "window_start": fmt_ts(window_start),
        "window_end": fmt_ts(window_end), "start_ns": ns_of(window_start), "end_ns": ns_of(window_end),
        "limit": int(request.get("page_limit") or DEFAULT_LOKI_LIMIT),
        "max_pages": int(request.get("max_pages") or DEFAULT_MAX_PAGES),
        "lateness_margin_s": int(request.get("lateness_margin_s", 600)),
        "force_reacquire": bool(request.get("force_reacquire", False)),
    }

    identity, binding, status = ident.resolve_identity(labels, annotations, bindings)
    scopes = [("primary", identity, binding if status == "resolved" else None,
               "source_unknown" if status != "resolved" else None)]
    if request.get("scope_policy", "alert_identity_only") == "alert_identity_plus_related":
        for related in request.get("related_scopes", []):
            wanted = {k: related.get(k) for k in ("site", "service", "runtime", "target")}
            found = [b for b in bindings if all(getattr(b.identity, k) == v for k, v in wanted.items())]
            if len(found) == 1:
                scopes.append(("related", found[0].identity, found[0], None))
            else:
                scopes.append(("related", ident.ObservationIdentity(**wanted), None, "source_unknown"))

    items = []
    for role, scope_identity, scope_binding, missing in scopes:
        items.extend(_scope_items(ctx, role, scope_identity, scope_binding, missing,
                                  shas.get(id(scope_binding)) if scope_binding else None))
    items.extend(_global_items(ctx, alert, identity))
    items.extend(_remediation_items(ctx, alert, request))

    # Fixed at plan time over the FULL plan: a stream filter never shrinks the binding set (02 §7).
    binding_set = sorted({i["binding_sha256"] for i in items if i["binding_sha256"]})
    plan_binding = canonical.plan_binding_sha256(binding_set)
    wanted_classes = set(request.get("stream_classes") or enums.STREAM_CLASSES)
    wanted_metrics = request.get("metric_queries")
    out = []
    for item in items:
        _check_allowed(item["query_text"])
        item["plan_binding_sha256"] = plan_binding
        item["binding_set"] = binding_set
        item["acquisition_key"] = canonical.acquisition_key(plan_id, item["binding_sha256"], item["query_name"],
                                                            item["query_text"], item["window_start"],
                                                            item["window_end"])
        if item["stream_class"] not in wanted_classes:
            continue
        if wanted_metrics is not None and item["stream_class"] == "metric" and item["query_text"] is not None \
                and item["query_name"] not in wanted_metrics:
            continue
        out.append(item)
    return out


def _base(ctx, role, scope_identity: dict, binding_sha, source_system, stream_class, query_name) -> dict:
    return {"plan_id": ctx["plan_id"], "incident_id": ctx["incident_id"], "scope_role": role,
            "source_system": source_system, "api": f"{source_system}.query_range", "stream_class": stream_class,
            "query_name": query_name, "query_text": None, "window_start": ctx["window_start"],
            "window_end": ctx["window_end"], "start_ns": ctx["start_ns"], "end_ns": ctx["end_ns"],
            "scope_identity": scope_identity, "scope_selector": {}, "binding_sha256": binding_sha,
            "expected_labels": {}, "body_filter": {}, "preflight_selector": None, "limit": ctx["limit"],
            "max_pages": ctx["max_pages"], "lateness_margin_s": ctx["lateness_margin_s"],
            "force_reacquire": ctx["force_reacquire"], "unavailable_reason": None}


def _loki_params(ctx) -> dict:
    return {"direction": "forward", "end": str(ctx["end_ns"]), "limit": ctx["limit"], "start": str(ctx["start_ns"])}


def _prom_params(ctx) -> dict:
    return {"end": seconds_text(ctx["end_ns"]), "start": seconds_text(ctx["start_ns"]), "step": "15s"}


def _unavailable(item: dict, reason: str, params: dict) -> dict:
    item.update(api=None, unavailable_reason=reason, query_params=params)
    return item


def _scope_items(ctx, role, scope_identity, binding, missing, binding_sha) -> list[dict]:
    ident = _ident()
    corr = pipeline_compat.correlation()
    identity_dict = scope_identity.to_dict()
    items = []

    # logs
    item = _base(ctx, role, identity_dict, binding_sha, "loki", _log_stream_class(scope_identity), "logs")
    if binding is None or not binding.logs:
        items.append(_unavailable(item, missing or "collector_unmapped", _loki_params(ctx)))
    else:
        query = ident.selector(binding.logs)
        item.update(query_text=query, query_params=_loki_params(ctx), scope_selector=binding.logs,
                    expected_labels=binding.logs, preflight_selector=query)
        items.append(item)

    # network: src and dst selectors of the collector, with the same `| json |` body filter
    if binding is None or not binding.network:
        item = _base(ctx, role, identity_dict, binding_sha, "loki", "network_event", "network")
        items.append(_unavailable(item, missing or "collector_unmapped", _loki_params(ctx)))
    else:
        filters = " and ".join(f"{k}={json.dumps(v)}" for k, v in binding.network.items())
        src_sel, dst_sel = corr.network_event_selectors(scope_identity.service)
        for name, stream_sel, side in (("network_src", src_sel, "src_service"), ("network_dst", dst_sel, "dst_service")):
            item = _base(ctx, role, identity_dict, binding_sha, "loki", "network_event", name)
            item.update(query_text=f"{stream_sel} | json | {filters}", query_params=_loki_params(ctx),
                        scope_selector=binding.network, preflight_selector=stream_sel,
                        expected_labels={"log_type": "network", side: scope_identity.service},
                        body_filter=binding.network)
            items.append(item)

    # metrics
    unmapped_name = "host_metrics" if scope_identity.runtime == "host" else "container_metrics"
    if binding is None or not binding.metrics:
        item = _base(ctx, role, identity_dict, binding_sha, "prometheus", "metric", unmapped_name)
        items.append(_unavailable(item, missing or "collector_unmapped", _prom_params(ctx)))
    else:
        for name, (query, expected) in metric_queries(binding).items():
            item = _base(ctx, role, identity_dict, binding_sha, "prometheus", "metric", name)
            item.update(query_text=query, query_params=_prom_params(ctx), scope_selector=binding.metrics,
                        expected_labels=expected, preflight_selector=ident.selector(expected))
            items.append(item)
    return items


def _global_items(ctx, alert, identity) -> list[dict]:
    ident = _ident()
    known = {k: v for k, v in identity.to_dict().items() if k in ("site", "source", "service", "runtime", "target")
             and v != "UNKNOWN"}
    rca_labels = {"job": "aiops-llm", "alert": alert["labels"]["alertname"], **known}
    rca = _base(ctx, "global", dict(UNKNOWN_SCOPE), None, "loki", "rca_result", "rca_result")
    rca_query = ident.selector(rca_labels)
    rca.update(query_text=rca_query, query_params=_loki_params(ctx), expected_labels=rca_labels,
               preflight_selector=rca_query)
    fluentd = _base(ctx, "global", dict(UNKNOWN_SCOPE), None, "loki", "fluentd_internal", "fluentd_internal")
    fluentd.update(query_text='{log_type="fluentd_internal"} |= "failed to write post"',
                   query_params=_loki_params(ctx), expected_labels={"log_type": "fluentd_internal"},
                   preflight_selector='{log_type="fluentd_internal"}')
    # scenarios/v2 run log (runs.jsonl): read whole at acquire time from DP_SCENARIO_RUN_LOG (#71)
    runs = _base(ctx, "global", dict(UNKNOWN_SCOPE), None, "scenario_run_log", "scenario_run", "runs")
    runs.update(api="file.read", query_params={})
    return [rca, fluentd, runs]


def _remediation_items(ctx, alert, request) -> list[dict]:
    """DEC-19: Remediation audit + timeline streams over the remediation window, in chunks of <= 15 minutes."""
    start, end = remediation_window(request)
    chunks = remediation_chunks(start, end)
    check_remediation_chunks(chunks, start, end)
    alertname = alert["labels"]["alertname"]
    queries = remediation_queries(alertname)
    items = []
    for chunk_start, chunk_end in chunks:
        chunk = {**ctx, "window_start": fmt_ts(chunk_start), "window_end": fmt_ts(chunk_end),
                 "start_ns": ns_of(chunk_start), "end_ns": ns_of(chunk_end)}
        for name, job in REMEDIATION_SELECTORS:
            item = _base(chunk, "global", dict(UNKNOWN_SCOPE), None, "loki", "remediation_event", name)
            item.update(query_text=queries[name], query_params=_loki_params(chunk),
                        expected_labels={"job": job, "alert": alertname}, preflight_selector=queries[name])
            items.append(item)
    return items
