"""Read-only M4 collection and reproducible baseline review (stdlib + PyYAML).

plan: emit exact queries; collect: GET APIs and sanitize in memory; analyze:
analyze the sanitized JSON or report BLOCKED without observations. No rule writes.
Existing M2/M3 expression builders are reused without modifying those modules.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import hmac
import importlib.util
import json
import math
from pathlib import Path
import re
import secrets
import statistics
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

import yaml

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "docs/rulepack/m4/analysis.yml"
M4_STAGE = "분석 도구 및 오프라인 검증 완료 / 실측 Baseline 수립 대기"


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


m2, infra, resource, m3 = (module(name) for name in ("generate_m2", "generate_m2_2", "generate_m2_3", "generate_m3"))


def timestamp(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
        return float(value)
    if not isinstance(value, str):
        raise ValueError("Explicit timezone-aware timestamp required")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamp requires timezone")
    return parsed.timestamp()


def utc(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def window_override(config, start, end):
    if (start is None) != (end is None):
        raise ValueError("--start and --end must be supplied together")
    if start is None:
        return config
    bounds = timestamp(start), timestamp(end)
    previous = config["window"]
    if config["normal"]["confirmed"] and (
        previous["start"] is None or bounds != (timestamp(previous["start"]), timestamp(previous["end"]))
    ):
        raise ValueError("CLI window cannot inherit normal confirmation from a different configured interval")
    effective = {**config, "window": {"start": utc(bounds[0]), "end": utc(bounds[1])}}
    validate(effective)
    return effective


def publish_statistics(result, normal_confirmed, data_kind):
    """Never publish quantiles of unconfirmed/fixture data, even as diagnostics."""
    if normal_confirmed and data_kind == "observed":
        return {**result, "percentiles_status": "CONFIRMED_INTERVAL_ONLY"}
    def redact(value):
        if isinstance(value, dict):
            return {key: None if key in {"median", "p50", "p90", "p95", "p99"} else redact(item)
                    for key, item in value.items()}
        if isinstance(value, list):
            return [redact(item) for item in value]
        return value
    return {**redact(result), "percentiles_status": "SYNTHETIC_TEST_ONLY" if data_kind == "synthetic" else "NORMAL_UNCONFIRMED"}


def validate(config):
    required = {"version", "window", "normal", "reserved_evaluation_windows", "step_seconds", "quality", "max_log_lines",
                "sources", "web_targets", "postgres_targets", "network_targets", "candidates"}
    if not isinstance(config, dict) or set(config) != required or type(config["version"]) is not int or config["version"] != 1:
        raise ValueError("Invalid M4 version/config keys")
    if type(config["step_seconds"]) is not int or config["step_seconds"] != 5:
        raise ValueError("M4 preserves the existing 5-second rule evaluation grid")
    if type(config["max_log_lines"]) is not int or not 1 <= config["max_log_lines"] <= 5000:
        raise ValueError("max_log_lines must be 1..5000")
    normal = config["normal"]
    if set(normal) != {"confirmed", "incident_and_injection_free", "confirmed_by", "evidence"}:
        raise ValueError("Invalid normal-interval attestation")
    if any(type(normal[k]) is not bool for k in ("confirmed", "incident_and_injection_free")):
        raise ValueError("Normal flags must be booleans")
    if normal["confirmed"] and not (normal["incident_and_injection_free"] and all(isinstance(normal[k], str) and normal[k].strip() for k in ("confirmed_by", "evidence"))):
        raise ValueError("Normal confirmation needs operator/evidence and incident/injection exclusion")
    window = config["window"]
    if set(window) != {"start", "end"} or (window["start"] is None) != (window["end"] is None):
        raise ValueError("Set both window endpoints or neither")
    bounds = None
    if window["start"] is not None:
        bounds = timestamp(window["start"]), timestamp(window["end"])
        if not 0 < bounds[1] - bounds[0] <= 86400:
            raise ValueError("One analysis run must span >0 and <=24h; use separate runs for longer periods")
    if normal["confirmed"] and bounds is None:
        raise ValueError("Normal confirmation requires an explicit interval")
    for held in config["reserved_evaluation_windows"]:
        left, right = timestamp(held["start"]), timestamp(held["end"])
        if right <= left or (bounds and max(left, bounds[0]) <= min(right, bounds[1])):
            raise ValueError("M6 evaluation interval must not overlap baseline fitting")
    quality = config["quality"]
    if set(quality) != {"minimum_duration_seconds", "minimum_samples", "minimum_coverage", "maximum_raw_gap_steps"}:
        raise ValueError("Invalid quality gates")
    if not 0 < quality["minimum_coverage"] <= 1 or any(quality[k] <= 0 for k in quality if k != "minimum_coverage"):
        raise ValueError("Invalid quality gate value")
    seen = defaultdict(set)
    all_ids = [key for family in ("sources", "web_targets", "postgres_targets", "network_targets") for key in config[family]]
    if len(set(all_ids)) != len(all_ids):
        raise ValueError("Source/target ids must be globally unique")
    for source_id, source in config["sources"].items():
        if not infra.IDENTIFIER.fullmatch(source_id) or not source["names"]:
            raise ValueError("Source id/names required")
        if type(source["memory_limit_semantics_confirmed"]) is not bool:
            raise ValueError("Memory limit confirmation must be boolean")
        for name in source["names"]:
            if not infra.IDENTIFIER.fullmatch(name):
                raise ValueError("Invalid container name")
        for kind in ("cadvisor", "pipeline"):
            infra._scope(source[kind])
            pair = tuple(sorted(source[kind].items()))
            if pair in seen[kind]:
                raise ValueError("Overlapping collector sources")
            seen[kind].add(pair)
    for key in ("web_targets", "postgres_targets"):
        for target_id, target in config[key].items():
            m2._selectors(target["metric_selector"], {"job", "instance"}, "job")
            if "instance" not in target["metric_selector"]:
                raise ValueError("Exact exporter instance required")
            m2._selectors(target["log_selector"], m2.LOG_LABELS, "service")
            if "runtime" not in target["log_selector"]:
                raise ValueError("Exact log runtime required")
            if not m2.IDENTIFIER.fullmatch(target_id):
                raise ValueError("Invalid target id")
        targets = list(config[key].values())
        for index, left in enumerate(targets):
            for right in targets[index + 1:]:
                for field in ("metric_selector", "log_selector"):
                    a, b = left[field], right[field]
                    if all(a[k] == b[k] for k in a.keys() & b.keys()):
                        raise ValueError("Overlapping target selectors")
    for key in ("sources", "web_targets", "postgres_targets", "network_targets"):
        for item in config[key].values():
            if type(item["scope_confirmed"]) is not bool:
                raise ValueError("Scope confirmation must be boolean")
    for item in config["network_targets"].values():
        if type(item["policy_confirmed"]) is not bool or item["log_selector"] != {"log_type": "network", "src_service": "backend"}:
            raise ValueError("Network selector must preserve the current backend network contract")
    if len(config["network_targets"]) > 1:
        raise ValueError("Identical indexed network selectors cannot identify separate sources; observers remain separate inside the sample summary")
    for family in ("web_targets", "postgres_targets", "network_targets"):
        for item in config[family].values():
            if type(item["log_continuity_confirmed"]) is not bool or (item["log_continuity_confirmed"] and not isinstance(item["log_continuity_evidence"], str)):
                raise ValueError("Log continuity requires a boolean and operator evidence")
            if item["log_continuity_confirmed"] and not item["log_continuity_evidence"].strip():
                raise ValueError("Log continuity evidence is empty")
    return bounds


def without_threshold(expression, number):
    result, count = re.subn(r"\s*>\s*" + re.escape(str(number)) + r"\s*$", "", expression.strip())
    if count != 1:
        raise ValueError("Review changed source threshold before analysis")
    return result


def plan(config):
    validate(config)
    queries, raw = [], []
    originals = infra.source_rules()
    memory_rules = resource.source_rules()
    def add(query_id, engine, expression, source, family, unit, lookback=0, threshold=None, hold=0, evidence=()):
        queries.append(dict(id=query_id, engine=engine, expression=expression.strip(), source=source, family=family,
                            unit=unit, lookback_seconds=lookback, threshold=threshold, for_seconds=hold, evidence=list(evidence)))
    def probe(query_id, expression, source, family):
        raw.append(dict(id=query_id, expression=expression, source=source, family=family))
    for source_id, source in config["sources"].items():
        for name in source["names"]:
            expression = infra._cpu_expression(originals["HighCpuUsage"]["expr"], {"name": name}, source)
            expression, count = re.subn(r">\s*0\.5\s+and", "and", expression)
            if count != 1:
                raise ValueError("Review changed CPU threshold")
            add(f"{source_id}/cpu/{name}", "prometheus", expression, source_id, "cpu", "CPU_core_equivalent", 30, .5, 30, ("cpu_counter", "metadata"))
        add(source_id + "/memory", "prometheus", without_threshold(resource.memory_expression(memory_rules["HighMemoryUsage"]["expr"], source), .85),
            source_id, "memory", "working_set/limit", 0, .85, 300, ("working_set", "memory_limit", "metadata"))
        network_source = {**source, "network_names": source["names"]}
        expression = resource.network_expression(memory_rules["HighNetworkReceive"]["expr"], network_source)
        container, host = expression.split(") or (", 1)
        for branch, expression in (("container", container + ")"), ("host_fallback", "(" + host)):
            expression, count = re.subn(r"\s*>\s*1e7", "", expression)
            if count != 1:
                raise ValueError("Review changed network threshold")
            add(f"{source_id}/receive/{branch}", "prometheus", expression, source_id, "network_" + branch,
                "bytes/second", 60, 1e7, 30, ("network_counter",))
        scope = infra.selector(source["cadvisor"])[1:-1]
        add(source_id + "/receive/presence_guard", "prometheus", 'count(container_network_receive_bytes_total{id=~"/docker/.+",' + scope + '}) > 0',
            source_id, "network_presence", "series_count", 60)
        add(source_id + "/receive/root_rate", "prometheus", 'sum without (interface) (rate(container_network_receive_bytes_total{interface!="lo",id="/",' + scope + '}[1m]))',
            source_id, "network_root_rate", "bytes/second", 60)
        for kind, metric, extra in (("cpu_counter", "container_cpu_usage_seconds_total", 'id=~"/docker/.+",cpu="total",'),
                                    ("working_set", "container_memory_working_set_bytes", 'id=~"/docker/.+",'),
                                    ("memory_limit", "container_spec_memory_limit_bytes", 'id=~"/docker/.+",'),
                                    ("network_counter", "container_network_receive_bytes_total", "")):
            probe(source_id + "/" + kind, metric + "{" + extra + scope + "}", source_id, kind)
        probe(source_id + "/metadata", "container_name_info" + infra.selector(source["pipeline"]), source_id, "metadata")
    logs = m2._source_rules(m2.SOURCE_FILES["loki"], (*m2.WEB_LOG_RULES, "SQLInjectionAttempt"))
    for target_id, target in config["web_targets"].items():
        add(target_id + "/request_rate", "prometheus", "rate(nginx_http_requests_total" + m2.selector(target["metric_selector"]) + "[1m])",
            target_id, "http_rate", "requests/second", 60, 30, 30, ("nginx_counter",))
        probe(target_id + "/nginx_counter", "nginx_http_requests_total" + m2.selector(target["metric_selector"]), target_id, "nginx_counter")
        mapped = {"id": target_id, **target}
        for name, threshold in (("HighNginxErrorRate", 10), ("VulnerabilityScanningDetected", 50)):
            expr = m2._target_rule(logs[name], mapped)["expr"]
            add(target_id + "/" + name, "loki", without_threshold(expr, threshold), target_id, "http_status_count", "events/minute", 60, threshold)
        stream = m3.selector({**target["log_selector"], "log_format": "json"})
        for window, duration in (("1m", 60), ("1h", 3600)):
            add(target_id + "/requests/" + window, "loki", f"sum(count_over_time({stream}[{window}]))", target_id, "http_requests", "events/" + window, duration)
        for status in (200, 300, 400, 500):
            add(f"{target_id}/status/{status // 100}xx", "loki", f'sum(count_over_time({stream} | json | status >= {status} and status < {status + 100} | __error__="" [1m]))',
                target_id, "http_status_distribution", "events/minute", 60)
        add(target_id + "/SQLInjection", "loki", without_threshold(m3.rule("SQLInjection", mapped)["expr"], 0), target_id, "sql_new", "events/2minutes", 120, 0)
        previous = logs["SQLInjectionAttempt"]["expr"]
        if previous.count('{service="frontend"}') != 1:
            raise ValueError("Review changed existing SQLi selector")
        previous = previous.replace('{service="frontend"}', m2.selector(target["log_selector"]))
        add(target_id + "/SQLInjectionAttempt", "loki", without_threshold(previous, 5), target_id, "sql_existing", "events/2minutes", 120, 5)
    for target_id, target in config["postgres_targets"].items():
        add(target_id + "/connections_per_series", "prometheus", "pg_stat_activity_count" + m2.selector(target["metric_selector"]),
            target_id, "postgres_per_series", "sessions_per_labelset", 0, 40, 30, ("pg_connections",))
        probe(target_id + "/pg_connections", "pg_stat_activity_count" + m2.selector(target["metric_selector"]), target_id, "pg_connections")
        add(target_id + "/DBConnectionLimit", "loki", without_threshold(m3.rule("DBConnectionLimit", {"id": target_id, **target})["expr"], 0),
            target_id, "postgres_refusal", "events/2minutes", 120, 0)
    policy = yaml.safe_load((ROOT / "aiops/policy/allowlist.yml").read_text())
    result = {"version": 1, "window": config["window"], "step_seconds": config["step_seconds"], "queries": queries, "raw_inputs": raw,
              "network_policy": {"allow": [{key: value for key, value in item.items() if key in {"match", "service", "ip", "port"}} for item in policy["allow"]],
                                 "thresholds": policy["thresholds"]}, "normal": config["normal"]}
    for query_id, candidate in config["candidates"].items():
        definition = next((q for q in queries if q["id"] == query_id), None)
        if not definition or definition["threshold"] is None or set(candidate) != {"threshold", "unit", "rationale"}:
            raise ValueError("Candidate requires a threshold-bearing query and threshold/unit/rationale")
        if not isinstance(candidate["threshold"], (int, float)) or isinstance(candidate["threshold"], bool) or not math.isfinite(candidate["threshold"]) or candidate["threshold"] < 0 or candidate["unit"] != definition["unit"] or not candidate["rationale"].strip():
            raise ValueError("Candidate must have finite value, matching unit and evidence rationale")
    return result


def percentile(values, percent):
    if not values:
        return None
    values = sorted(values)
    position = (len(values) - 1) * percent / 100
    lower = math.floor(position)
    return values[lower] + (values[math.ceil(position)] - values[lower]) * (position - lower)


def summarize(points):
    if not points:
        return None
    values = [value for _, value in points]
    mean = statistics.fmean(values)
    spread = statistics.pstdev(values)
    center = statistics.fmean(t for t, _ in points)
    variance = sum((t - center) ** 2 for t, _ in points)
    slope = sum((t - center) * (v - mean) for t, v in points) / variance if variance else None
    hours = defaultdict(list)
    for time, value in points:
        hours[utc(time)[:13] + ":00Z"].append(value)
    return {"samples": len(values), "mean": mean, "median": percentile(values, 50), "p90": percentile(values, 90),
            "p95": percentile(values, 95), "p99": percentile(values, 99), "max": max(values), "min": min(values),
            "stddev": spread, "coefficient_of_variation": spread / mean if mean else None,
            "linear_trend_per_hour": slope * 3600 if slope is not None else None,
            "hourly_utc": {hour: {"samples": len(vals), "mean": statistics.fmean(vals), "p95": percentile(vals, 95), "max": max(vals)} for hour, vals in sorted(hours.items())}}


def quality(points, start, end, step, raw=False):
    valid, rejected, seen = [], 0, set()
    for time, value in points:
        time = timestamp(time)
        if time in seen:
            raise ValueError("Duplicate timestamp; do not average distinct observations")
        seen.add(time)
        try:
            value = float(value)
        except (ValueError, TypeError):
            rejected += 1
            continue
        if not math.isfinite(value) or not start <= time <= end:
            rejected += 1
            continue
        if not raw and abs((time - start) / step - round((time - start) / step)) > .001:
            rejected += 1
            continue
        valid.append((time, value))
    valid.sort()
    expected = max(0, math.floor((end - start) / step) + 1)
    gaps = [b[0] - a[0] for a, b in zip(valid, valid[1:])]
    return valid, {"expected_samples": expected, "observed_samples": len(valid), "rejected_samples": rejected,
                   "coverage": min(1, len(valid) / expected) if expected else None,
                   "max_gap_seconds": max(gaps) if gaps else None,
                   "leading_gap_seconds": valid[0][0] - start if valid else None,
                   "trailing_gap_seconds": end - valid[-1][0] if valid else None,
                   "first_sample": utc(valid[0][0]) if valid else None, "last_sample": utc(valid[-1][0]) if valid else None}


def excursions(points, threshold, hold, step):
    episodes, current = [], []
    def finish():
        if current:
            duration = current[-1][0] - current[0][0]
            episodes.append({"start": utc(current[0][0]), "last_observed": utc(current[-1][0]), "span_seconds": duration,
                             "samples": len(current), "max": max(value for _, value in current), "for_satisfied": duration >= hold})
            current.clear()
    for time, value in points:
        if current and time - current[-1][0] > step * 1.01:
            finish()
        if value > threshold:
            current.append((time, value))
        else:
            finish()
    finish()
    return {"threshold": threshold, "comparison": ">", "for_seconds": hold,
            "exceeding_samples": sum(row["samples"] for row in episodes), "episodes": episodes,
            "exceeding_sample_fraction": sum(row["samples"] for row in episodes) / len(points) if points else None,
            "for_satisfied_episodes": sum(row["for_satisfied"] for row in episodes),
            "observed_exceedance_span_seconds": sum(row["span_seconds"] for row in episodes),
            "state_before_first_sample": "UNVERIFIED", "state_after_last_sample": "UNVERIFIED"}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("Redirect refused; use the verified API URL")


def get(base, path, parameters):
    parsed = urlsplit(base)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("API base must be http(s), without credentials/query/fragment")
    request = Request(base.rstrip("/") + path + "?" + urlencode(parameters), method="GET")
    try:
        with build_opener(NoRedirect()).open(request, timeout=20) as response:
            payload = response.read(32 * 1024 * 1024 + 1)
        if len(payload) > 32 * 1024 * 1024:
            return {"error": "RESPONSE_TOO_LARGE"}
        result = json.loads(payload)
        if result.get("status") != "success":
            return {"error": "API_STATUS_FAILED"}
        if result.get("warnings") or result.get("infos"):
            return {"error": "API_PARTIAL_OR_ANNOTATED_RESULT"}
        return result
    except HTTPError as exc:
        return {"error": "HTTP_" + str(exc.code)}
    except (URLError, TimeoutError, OSError, ValueError):
        # Never persist server error bodies/URLs, which may contain query data.
        return {"error": "API_CONNECTION_OR_FORMAT_ERROR"}


def tagger():
    key = secrets.token_bytes(32)
    return lambda value: hmac.new(key, json.dumps(value, sort_keys=True).encode(), hashlib.sha256).hexdigest()[:20]


def matrix_rows(result, query_id, tag):
    if result.get("error"):
        return [], result["error"]
    if result.get("data", {}).get("resultType") != "matrix":
        return [], "EXPECTED_MATRIX"
    rows = []
    for series in result["data"]["result"]:
        labels = series["metric"]
        state = labels.get("state")
        dimensions = {"state": state} if state in {"active", "idle", "idle in transaction", "idle in transaction (aborted)", "fastpath function call", "disabled"} else {}
        rows.append({"query_id": query_id, "series_id": tag(labels), "label_keys": sorted(labels),
                     "entity": labels.get("name") or tag(labels), "dimensions": dimensions, "points": series.get("values", [])})
    return rows, "OK" if rows else "NO_SERIES"


def log_records(result):
    if result.get("error") or result.get("data", {}).get("resultType") != "streams":
        return []
    return [(int(time) / 1e9, line) for stream in result["data"]["result"] for time, line in stream["values"]]


def http_summary(records, tag, start, end, capped):
    statuses, paths, minutes, hours = Counter(), Counter(), Counter(), Counter()
    invalid = 0
    for time, line in records:
        try:
            if not start <= time <= end:
                raise ValueError()
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError()
            status = int(row["status"])
            uri = row["request_uri"]
            if not isinstance(uri, str) or not 100 <= status <= 599:
                raise ValueError()
            path = uri.split("?", 1)[0]
            paths[tag(path)] += 1
            statuses[str(status // 100) + "xx"] += 1
            minutes[str(int(time // 60) * 60)] += 1
            hours[str(int(time // 3600) * 3600)] += 1
        except (ValueError, TypeError, KeyError):
            invalid += 1
    return {"kind": "http", "requested_start": utc(start), "requested_end": utc(end), "rows": len(records), "invalid_rows": invalid,
            "truncated": capped, "status_class_counts_in_sample": dict(statuses), "path_token_counts": dict(paths),
            "minute_counts_observed_buckets": dict(minutes), "hour_counts_observed_buckets": dict(hours),
            "raw_uri_or_user_data_persisted": False, "sample_only": True}


def network_summary(records, tag, start, end, capped, policy):
    events, seen, conflicts = [], {}, set()
    invalid, thresholds, duplicates = 0, 0, 0
    for _, line in records:
        try:
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError()
            if row.get("event_type") == "connection_threshold":
                thresholds += 1
                continue
            if row.get("event_type") != "connection":
                raise ValueError()
            required = ("observer_instance", "connection_id", "src_ip", "src_port", "dst_ip", "dst_port", "timestamp")
            if any(row.get(key) is None for key in required):
                raise ValueError()
            time = timestamp(row["timestamp"])
            value = row.get("bytes_sent")
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value < 0:
                raise ValueError()
            identity = tuple(row[key] for key in required)
            if identity in seen:
                duplicates += 1
                if seen[identity] != value:
                    conflicts.add(identity)
                continue
            seen[identity] = value
            if not start <= time <= end:
                raise ValueError()
            allowed = any((item["match"] == "service" and row.get("dst_service") == item["service"]) or
                          (item["match"] == "endpoint" and row["dst_ip"] == item["ip"] and row["dst_port"] == item["port"])
                          for item in policy["allow"])
            events.append({"time": time, "observer": tag(row["observer_instance"]), "destination": tag([row["dst_ip"], row["dst_port"]]),
                           "bytes": value, "identity": identity, "policy": "CONFIGURED_ALLOWED" if allowed else "CONFIGURED_NOT_ALLOWED"})
        except (ValueError, TypeError, KeyError):
            invalid += 1
    events = [row for row in events if row["identity"] not in conflicts]
    windows = []
    for duration in (300, 3600, 86400):
        left = max(start, end - duration)
        groups = defaultdict(list)
        for row in events:
            if left < row["time"] <= end:
                groups[(row["observer"], row["destination"], row["policy"])].append(row)
        prior = {(row["observer"], row["destination"]) for row in events if row["time"] <= left}
        newly_seen = sum((observer, destination) not in prior for observer, destination, _ in groups)
        windows.append({"requested_window_seconds": duration, "available_window_seconds": end - left, "complete_requested_duration": end - start >= duration,
                        "event_samples": sum(len(rows) for rows in groups.values()),
                        "prior_reference_seconds": left - start,
                        "first_observed_destination_candidates": newly_seen if not capped and left > start else None,
                        "novelty_scope": "captured prior reference only; never global destination novelty",
                        "destinations": [{"observer_token": observer, "destination_token": destination, "policy": policy_label,
                                          "connections": len(rows), "payload_bytes": sum(row["bytes"] for row in rows),
                                          "current_5m_condition_in_sample": (policy_label == "CONFIGURED_NOT_ALLOWED" and sum(row["bytes"] for row in rows) > policy.get("thresholds", {}).get("min_transfer_bytes", math.inf)) if duration == 300 else None,
                                          "bytes_per_connection": summarize([(row["time"], row["bytes"]) for row in rows]),
                                          "first_observed_in_available_reference": (observer, destination) not in prior}
                                         for (observer, destination, policy_label), rows in sorted(groups.items())]})
    return {"kind": "network", "rows": len(records), "invalid_rows": invalid, "threshold_events_excluded": thresholds,
            "duplicate_final_events_excluded": duplicates, "truncated": capped, "windows": windows, "sample_only": True,
            "conflicting_final_event_identities_excluded": len(conflicts),
            "event_time": "connection_start; completion/ingestion lag and unseen connections are not measurable here"}


def collect(config, prometheus, loki):
    bounds = validate(config)
    if bounds is None:
        raise ValueError("Set an explicit measured interval before collection; no inferred normal window")
    start, end = bounds
    query_plan = plan(config)
    tag = tagger()
    result = {"version": 1, "data_kind": "observed", "acquired_at_utc": utc(datetime.now(timezone.utc).timestamp()),
              "config_sha256": digest(config), "plan_sha256": digest(query_plan), "window": config["window"],
              "series": [], "raw_quality": {}, "checks": {}, "log_summaries": {}, "event_totals": {}}
    for definition in query_plan["queries"]:
        left = start + definition["lookback_seconds"]
        if left >= end:
            result["checks"][definition["id"]] = "INSUFFICIENT_WINDOW"
            continue
        params = {"query": definition["expression"], "start": left, "end": end, "step": config["step_seconds"]}
        engine = definition["engine"]
        response = get(prometheus if engine == "prometheus" else loki,
                       "/api/v1/query_range" if engine == "prometheus" else "/loki/api/v1/query_range", params)
        rows, status = matrix_rows(response, definition["id"], tag)
        result["series"].extend(rows)
        result["checks"][definition["id"]] = status
        if engine == "loki" and definition["family"] in {"sql_new", "sql_existing", "postgres_refusal", "http_requests"}:
            full_interval = re.sub(r"\[(?:1m|1h|2m)\]", "[" + str(int(end - start)) + "s]", definition["expression"])
            total = get(loki, "/loki/api/v1/query", {"query": full_interval, "time": end})
            vector = total.get("data", {}).get("result", [])
            result["event_totals"][definition["id"]] = {
                "status": total.get("error", "OK" if total.get("data", {}).get("resultType") == "vector" and len(vector) == 1 else "NO_UNAMBIGUOUS_TOTAL"),
                "value": float(vector[0]["value"][1]) if len(vector) == 1 and total.get("data", {}).get("resultType") == "vector" and math.isfinite(float(vector[0]["value"][1])) else None,
                "meaning": "interval pattern matches/events, not adjudicated false positives or alert notifications"}
    for definition in query_plan["raw_inputs"]:
        expression = definition["expression"] + "[" + str(int(end - start)) + "s]"
        response = get(prometheus, "/api/v1/query", {"query": expression, "time": end})
        entries = []
        if response.get("data", {}).get("resultType") == "matrix":
            for row in response["data"]["result"]:
                valid, check = quality(row.get("values", []), start, end, config["step_seconds"], raw=True)
                labels = {key: value for key, value in row["metric"].items() if key != "__name__"}
                entries.append({"series_id": tag(labels), "id_token": tag(labels.get("id")), "label_keys": sorted(labels),
                                "labelset_token": tag(labels), "quality": check,
                                "diagnostic_statistics": summarize(valid),
                                "all_one": bool(valid) and all(v == 1 for _, v in valid),
                                "invalid_limits": sum(not math.isfinite(float(v)) or float(v) <= 0 or float(v) in config["sources"].get(definition["source"], {}).get("unlimited_limit_values", []) for _, v in row.get("values", []))})
        result["raw_quality"][definition["id"]] = {"status": response.get("error", "OK" if entries else "NO_SERIES"), "series": entries}
    for key, summarizer in (("web_targets", http_summary), ("network_targets", network_summary)):
        for source, target in config[key].items():
            selector = target["log_selector"]
            if key == "web_targets":
                selector = {**selector, "log_format": "json"}
            response = get(loki, "/loki/api/v1/query_range", {"query": m3.selector(selector), "start": str(int(start * 1e9)),
                           "end": str(int(end * 1e9)), "direction": "forward", "limit": config["max_log_lines"]})
            records = log_records(response)
            args = [records, tag, start, end, len(records) >= config["max_log_lines"]]
            if key == "network_targets":
                args.append(query_plan["network_policy"])
            result["log_summaries"][source] = {**summarizer(*args), "query_status": response.get("error", "OK" if records else "NO_ROWS")}
            if key == "network_targets":
                result["log_summaries"][source]["policy_application_confirmed"] = target["policy_confirmed"]
    return publish_statistics(result, config["normal"]["confirmed"], "observed")


def source_config(config, source):
    return next(config[key][source] for key in ("sources", "web_targets", "postgres_targets", "network_targets") if source in config[key])


def fallback_activity(observations, config, bounds):
    if not bounds or not observations["series"]:
        return []
    result = []
    for source in config["sources"]:
        prefix = source + "/receive/"
        grouped = {kind: [row for row in observations["series"] if row["query_id"] == prefix + kind]
                   for kind in ("root_rate", "presence_guard", "host_fallback")}
        caches = defaultdict(list)
        for kind, rows in grouped.items():
            for row in rows:
                points = {}
                for time, value in row["points"]:
                    try:
                        value = float(value)
                        if math.isfinite(value): points[timestamp(time)] = value
                    except (ValueError, TypeError):
                        continue
                caches[kind].append(points)
        states = Counter()
        intervals = []
        left = bounds[0] + 60
        for index in range(max(0, math.floor((bounds[1] - left) / config["step_seconds"]) + 1)):
            time = left + index * config["step_seconds"]
            values = {kind: [series[time] for series in rows if time in series] for kind, rows in caches.items()}
            checks = [observations["checks"].get(prefix + kind) for kind in grouped]
            if any(check not in {"OK", "NO_SERIES"} for check in checks): state = "COLLECTION_UNVERIFIED"
            elif len(values["root_rate"]) > 1: state = "AMBIGUOUS_ROOT_SERIES"
            elif not values["root_rate"]: state = "ROOT_RATE_MISSING"
            elif values["presence_guard"]: state = "MASKED_BY_ANY_DOCKER_SERIES"
            elif values["host_fallback"]: state = "HOST_FALLBACK_ACTIVE"
            else: state = "INCONSISTENT_QUERY_RESULTS"
            states[state] += 1
            if intervals and intervals[-1]["state"] == state:
                intervals[-1]["last_observed"] = utc(time)
            else:
                intervals.append({"state": state, "start": utc(time), "last_observed": utc(time)})
        result.append({"source": source, "states_by_evaluation_samples": dict(states), "intervals": intervals,
                       "scope": "host; never attributed to a Leafy container", "raw_scrape_continuity_required": True})
    return result


def analyze(config, observations=None):
    bounds, query_plan = validate(config), plan(config)
    if observations is not None:
        if observations.get("version") != 1 or observations.get("data_kind") not in {"observed", "synthetic"} or observations.get("config_sha256") != digest(config) or observations.get("plan_sha256") != digest(query_plan) or observations.get("window") != config["window"]:
            raise ValueError("Input provenance/config/query plan/window mismatch")
        if bounds is None:
            raise ValueError("Observed/synthetic input requires an explicit interval")
    observations = observations or {"data_kind": "none", "series": [], "checks": {}, "raw_quality": {}, "log_summaries": {}, "event_totals": {}}
    definitions = {query["id"]: query for query in query_plan["queries"]}
    output = {"version": 1, "status": "PARTIAL" if observations["series"] else "BLOCKED", "m4_stage": M4_STAGE, "data_kind": observations["data_kind"],
              "normal_status": "NORMAL_CONFIRMED" if config["normal"]["confirmed"] else "NORMAL_UNCONFIRMED",
              "window": config["window"], "config_sha256": digest(config), "plan_sha256": digest(query_plan),
              "series": [], "missing_queries": sorted(set(definitions) - {row["query_id"] for row in observations["series"]}),
              "collection_checks": observations["checks"], "log_summaries": observations["log_summaries"], "baseline_eligible_series": 0,
              "event_totals": observations.get("event_totals", {}), "raw_input_diagnostics": observations["raw_quality"],
              "input_acquired_at_utc": observations.get("acquired_at_utc"),
              "real_alert_firing_verified": False, "thresholds_applied": False}
    output["network_fallback_activity"] = fallback_activity(observations, config, bounds)
    seen = set()
    for row in observations["series"]:
        if row["query_id"] not in definitions or (row["query_id"], row["series_id"]) in seen:
            raise ValueError("Unknown query or duplicate series identity")
        seen.add((row["query_id"], row["series_id"]))
        definition = definitions[row["query_id"]]
        start, end = bounds if bounds else (0, -1)
        start += definition["lookback_seconds"]
        values, check = quality(row["points"], start, end, config["step_seconds"])
        reasons = []
        if observations["data_kind"] != "observed": reasons.append("SYNTHETIC_TEST_ONLY")
        if not config["normal"]["confirmed"]: reasons.append("NORMAL_UNCONFIRMED")
        source = source_config(config, definition["source"])
        if not source["scope_confirmed"]: reasons.append("SOURCE_SCOPE_UNCONFIRMED")
        gates = config["quality"]
        if end - start < gates["minimum_duration_seconds"] or len(values) < gates["minimum_samples"]: reasons.append("INSUFFICIENT_DURATION_OR_SAMPLES")
        if (check["coverage"] or 0) < gates["minimum_coverage"] or check["rejected_samples"] or (check["max_gap_seconds"] or 0) > 2 * config["step_seconds"]: reasons.append("EVALUATED_DATA_INCOMPLETE")
        if observations["checks"].get(row["query_id"]) != "OK": reasons.append("QUERY_NOT_COMPLETE")
        for family in definition["evidence"]:
            raw = observations["raw_quality"].get(definition["source"] + "/" + family, {})
            if raw.get("status") != "OK" or not raw.get("series"):
                reasons.append("RAW_INPUT_MISSING:" + family)
                continue
            for entry in raw["series"]:
                sample = entry["quality"]
                if (sample["coverage"] or 0) < gates["minimum_coverage"] or max(sample["leading_gap_seconds"] or 0, sample["trailing_gap_seconds"] or 0, sample["max_gap_seconds"] or 0) > gates["maximum_raw_gap_steps"] * config["step_seconds"] or sample["rejected_samples"]:
                    reasons.append("RAW_INPUT_GAPS:" + family)
                if family == "metadata" and not entry["all_one"]: reasons.append("METADATA_NOT_ONE")
                if family == "memory_limit" and entry["invalid_limits"]: reasons.append("INVALID_OR_UNLIMITED_MEMORY_LIMIT")
            if family == "metadata" and len({entry["id_token"] for entry in raw["series"]}) != len(raw["series"]): reasons.append("DUPLICATE_METADATA_ID")
        if definition["family"] == "memory":
            if not source["memory_limit_semantics_confirmed"]: reasons.append("MEMORY_LIMIT_SEMANTICS_UNCONFIRMED")
            raw = observations["raw_quality"]
            a = {entry["labelset_token"] for entry in raw.get(definition["source"] + "/working_set", {}).get("series", [])}
            b = {entry["labelset_token"] for entry in raw.get(definition["source"] + "/memory_limit", {}).get("series", [])}
            if not a or a != b: reasons.append("MEMORY_FULL_LABEL_MISMATCH")
        if definition["engine"] == "loki" and not source.get("log_continuity_confirmed", False): reasons.append("LOG_CONTINUITY_UNVERIFIED")
        if definition["family"] == "network_host_fallback": reasons.append("CONDITIONAL_FALLBACK_DISTRIBUTION_ONLY")
        reasons = sorted(set(reasons))
        stats = summarize(values)
        current = excursions(values, definition["threshold"], definition["for_seconds"], config["step_seconds"]) if definition["threshold"] is not None else None
        candidate = config["candidates"].get(row["query_id"])
        output["series"].append({"query_id": row["query_id"], "source": definition["source"], "series_id": row["series_id"],
                                 "entity": "host_scope" if definition["family"] in {"network_host_fallback", "network_root_rate"} else row["entity"],
                                 "dimensions": row.get("dimensions", {}),
                                 "unit": definition["unit"], "quality": check, "diagnostic_statistics": stats,
                                 "normal_baseline_statistics": stats if not reasons else None, "excluded_reasons": reasons,
                                 "current_condition": current, "candidate_condition": excursions(values, candidate["threshold"], definition["for_seconds"], config["step_seconds"]) if candidate and not reasons else None,
                                 "candidate_rationale": candidate["rationale"] if candidate and not reasons else None})
        output["baseline_eligible_series"] += not reasons
    return publish_statistics(output, config["normal"]["confirmed"], observations["data_kind"])


def markdown(result):
    lines = ["# M4 Baseline 분석 실행 결과", "", f"상태: **{result['status']}** / {result['normal_status']} / data_kind={result['data_kind']}", "",
             f"M4 판정: **{result['m4_stage']}**이다.", "",
             f"확정 Baseline 사용 가능 시계열: {result['baseline_eligible_series']}개이다. 실제 경보 발화는 미검증이다.", "",
             "| Query / source / entity | 단위 | 표본 | 정상 P95 | 정상 P99 | for 충족 구간 | Baseline 제외 사유 |",
             "|---|---|---:|---:|---:|---:|---|"]
    for row in result["series"]:
        stats = row["normal_baseline_statistics"] or {}
        lines.append(f"| {row['query_id']} / {row['source']} / {row['entity']} | {row['unit']} | {row['quality']['observed_samples']} | {stats.get('p95', '—')} | {stats.get('p99', '—')} | {(row['current_condition'] or {}).get('for_satisfied_episodes')} | {', '.join(row['excluded_reasons']) or '없음'} |")
    if not result["series"]:
        lines += ["", "실측 입력이 없어 평균·분위수·임계값 초과 횟수·후보 임계값을 산출하지 않은 상태이다."]
    lines += ["", "진단 통계는 정상 판정이 아니다. 집계는 source/시계열별이며 수집 누락을 0으로 채우지 않는다.",
              "정상 미확인/합성 입력의 분위수는 JSON과 이 표에서 산출 결과로 제공하지 않는다.",
              "for 충족 구간은 표본 기반 후보이다. 실제 Ruler 상태·Alertmanager 알림 횟수/FPR/재현율을 뜻하지 않는다.", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "collect", "analyze"))
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--output", type=Path, required=True, help="Local output file (plan/collect) or directory (analyze)")
    parser.add_argument("--input", type=Path, help="Sanitized collect JSON, or an existing export using the documented contract")
    parser.add_argument("--prometheus", default="http://127.0.0.1:9090")
    parser.add_argument("--loki", default="http://127.0.0.1:3100")
    parser.add_argument("--start", help="Explicit analysis start, RFC3339 with timezone; pair with --end")
    parser.add_argument("--end", help="Explicit analysis end, RFC3339 with timezone; never implies normal confirmation")
    args = parser.parse_args()
    try:
        output = args.output.resolve()
        if output.is_relative_to(ROOT) and not output.is_relative_to(ROOT / "docs/rulepack/m4"):
            raise ValueError("Repository output is restricted to docs/rulepack/m4")
        if args.action != "analyze" and output.suffix != ".json":
            raise ValueError("plan/collect output must be a JSON file")
        config = yaml.safe_load(args.config.read_text(encoding="utf-8"))
        config = window_override(config, args.start, args.end)
        if args.action == "analyze":
            observations = json.loads(args.input.read_text()) if args.input else None
            result = analyze(config, observations)
            args.output.mkdir(parents=True, exist_ok=True)
            (args.output / "analysis.json").write_text(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n")
            (args.output / "summary.md").write_text(markdown(result), encoding="utf-8")
        else:
            result = plan(config) if args.action == "plan" else collect(config, args.prometheus, args.loki)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
        print(f"M4 {args.action}: local output written; no rule change/deployment")
    except (ValueError, KeyError, TypeError, OSError, yaml.YAMLError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
