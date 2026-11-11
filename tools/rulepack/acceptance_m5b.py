"""Read-only M5-B probes. No alert POST, rule reload, Docker, or LLM inference.

Only M5 candidate expressions and bounded input samples are queried. Responses
are reduced in memory; raw logs, annotations, configs, and label values are not
exported. HTTP success/empty results never certify alert delivery or scope.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import errno
import hashlib
import json
import math
import secrets
from pathlib import Path
import re
import socket
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

import yaml

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "docs/rulepack/m5b"
SELECTOR = re.compile(r'(?:[a-zA-Z_:][a-zA-Z0-9_:]*)?\{(?:\s*[a-zA-Z_]\w*\s*(?:=~|!~|!=|=)\s*"(?:\\.|[^"\\])*"\s*,?)+\s*\}')
SCHEMA_KEYS = {"request_uri", "status", "error_severity", "state_code", "message", "timestamp",
               "event_type", "bytes_sent", "dst_ip", "dst_port", "src_service", "dst_service", "observer_instance"}
STAGES = ("INPUT_VERIFIED", "SELECTOR_VERIFIED", "QUERY_SUCCESS", "RULE_LOADED",
          "FIRING_VERIFIED", "ALERT_DELIVERED", "PIPELINE_RECEIVED", "RCA_VERIFIED")
UNREACHABLE = {"CONNECTION_REFUSED", "ACCESS_DENIED", "TIMEOUT", "TRANSPORT_ERROR"}


class Identities:
    """Opaque, run-local equality tokens; never export hosts, jobs or endpoints."""
    def __init__(self):
        self.values = {}

    def token(self, kind, value):
        if value is None:
            return None
        key = (kind, str(value))
        if key not in self.values:
            self.values[key] = kind + "_" + secrets.token_hex(6)
        return self.values[key]


def digest(text):
    return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()


def plan(bundle=None):
    rows, hashes = [], {}
    for engine in ("loki", "prometheus"):
        name = f"docs/rulepack/m5/generated/{engine}.rules.yml" if bundle is None else (
            "loki/fake/release.rules.yml" if engine == "loki" else "prometheus.rules.yml")
        path = ROOT / name if bundle is None else Path(bundle) / name
        if bundle is not None:
            manifest = json.loads((Path(bundle) / "manifest.json").read_text())
            if hashlib.sha256(path.read_bytes()).hexdigest() != manifest["outputs_sha256"].get(name):
                raise ValueError("Release bundle drift; regenerate/review before probing")
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        for group in yaml.safe_load(path.read_text(encoding="utf-8"))["groups"]:
            for index, rule in enumerate(group["rules"]):
                inputs = sorted(set(SELECTOR.findall(rule["expr"])))
                if engine == "prometheus" and rule["alert"] == "HighPostgresConnections":
                    inputs = ["pg_stat_activity_count"]
                if not inputs:
                    raise ValueError("Candidate input extraction requires review")
                rows.append({"id": f'{engine}:{group["name"]}:{index}', "engine": engine,
                             "alert": rule["alert"], "target": rule["annotations"]["container"],
                             "static_labels": rule["labels"], "expr": rule["expr"], "inputs": inputs,
                             "duration": duration_seconds(rule.get("for", "0s")),
                             "keep_firing_for": duration_seconds(rule.get("keep_firing_for", "0s")),
                             "group_sha256": digest(group["name"]),
                             "configured_interval": duration_seconds(group["interval"]) if "interval" in group else None,
                             "annotations_sha256": object_digest(rule.get("annotations", {}))})
    reference = yaml.safe_load((ROOT / "docs/rulepack/m5/reference/loki.legacy-sqli.rules.yml").read_text(encoding="utf-8")) if bundle is None else None
    return {"version": 1, "candidate_sha256": hashes, "rules": rows,
            "legacy_sql_expr": reference["groups"][0]["rules"][0]["expr"] if reference else None}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, base, timeout=8):
        u = urlsplit(base)
        if (u.scheme not in {"http", "https"} or not u.hostname or u.username is not None
                or u.password is not None or u.query or u.fragment or u.path not in {"", "/"}):
            raise ValueError("Use an existing origin URL without credentials, path, query, or fragment")
        self.base, self.timeout = base.rstrip("/"), timeout
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def get(self, path, params=None):
        if not path.startswith("/") or path.startswith("//") or "?" in path or "#" in path:
            raise ValueError("Fixed API path required")
        url = self.base + path + ("?" + urlencode(params) if params else "")
        meta = {"method": "GET", "path": path, "at_utc": datetime.now(timezone.utc).isoformat()}
        try:
            with self.opener.open(Request(url, method="GET", headers={"Accept": "application/json"}), timeout=self.timeout) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
                if len(raw) > 4 * 1024 * 1024:
                    return {**meta, "status": "RESPONSE_LIMIT"}, None
                data = json.loads(raw)
            if isinstance(data, dict) and data.get("status", "success") not in {"success", "ok"}:
                return {**meta, "status": "API_ERROR"}, None
            partial = isinstance(data, dict) and bool(data.get("warnings") or data.get("infos"))
            return {**meta, "status": "PARTIAL" if partial else "SUCCESS"}, data
        except HTTPError as e:
            # Classify errors without exporting the server text, query or label values.
            try:
                raw = e.read(65536)
            except OSError:
                raw = b""
            detail = raw.decode("utf-8", errors="replace").lower()
            kind = next((kind for kind, words in (
                ("JOIN_ERROR", ("many-to-many", "many-to-one", "duplicate series", "multiple matches")),
                ("PARSE_ERROR", ("parse error", "syntax error", "unexpected token")),
                ("TEMPLATE_ERROR", ("template", "urldecode", "fromjson")),
                ("PIPELINE_ERROR", ("pipeline error", "unwrap", "sampleextraction")))
                if any(word in detail for word in words)), "UNCLASSIFIED")
            e.close()
            return {**meta, "status": "HTTP_ERROR", "http_status": e.code, "error_class": kind}, None
        except (URLError, OSError) as e:
            cause = getattr(e, "reason", e)
            code = getattr(cause, "errno", None)
            status = {errno.ECONNREFUSED: "CONNECTION_REFUSED", errno.EPERM: "ACCESS_DENIED",
                      errno.EACCES: "ACCESS_DENIED"}.get(code, "TRANSPORT_ERROR")
            if isinstance(cause, (TimeoutError, socket.timeout)):
                status = "TIMEOUT"
            return {**meta, "status": status}, None
        except (ValueError, UnicodeError):
            return {**meta, "status": "INVALID_JSON"}, None


def vector_summary(data, identities=None):
    body = data.get("data", {}) if isinstance(data, dict) else {}
    if body.get("resultType") != "vector" or not isinstance(body.get("result"), list):
        raise ValueError("Expected an instant vector")
    rows = body["result"]
    values = [float(row["value"][1]) for row in rows]
    finite = [x for x in values if math.isfinite(x)]
    summary = {"result": "EMPTY" if not rows else "PRESENT", "series": len(rows),
            "finite_values": len(finite), "positive_values": sum(x > 0 for x in finite),
            "label_keys": sorted({k for row in rows for k in row.get("metric", {})}),
            "sample_times": sorted({row["value"][0] for row in rows})}
    if identities:
        summary["identities"] = [identity_summary(row.get("metric", {}), identities) for row in rows]
    return summary


def log_summary(data, identities=None):
    body = data.get("data", {})
    if body.get("resultType") != "streams" or not isinstance(body.get("result"), list):
        raise ValueError("Expected log streams")
    rows, bad, latest, keys = 0, 0, None, Counter()
    for stream in body["result"]:
        for ts, line in stream["values"]:
            rows += 1
            latest = max(latest or 0, int(ts))
            try:
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    raise ValueError()
                for key in SCHEMA_KEYS & obj.keys():
                    keys[f"{key}:{type(obj[key]).__name__}"] += 1
            except (ValueError, TypeError):
                bad += 1
    summary = {"result": "PRESENT" if rows else "EMPTY", "sample_rows": rows,
            "sample_cap_reached": rows >= 50, "invalid_or_nonobject_json": bad,
            "latest_entry_ns": latest, "schema_key_type_counts": dict(sorted(keys.items())),
            "label_keys": sorted({k for stream in body["result"] for k in stream.get("stream", {})})}
    if identities:
        summary["identities"] = [identity_summary(s.get("stream", {}), identities) for s in body["result"]]
    return summary


def identity_summary(labels, identities):
    return {k: identities.token(k, labels[k]) for k in (
        "job", "instance", "site", "source", "source_id", "observer_instance", "id", "name",
        "service", "runtime", "target", "log_format", "rulepack_source", "rulepack_target") if k in labels}


def object_digest(value):
    return digest(json.dumps(value, sort_keys=True, ensure_ascii=False))


def duration_seconds(value):
    if isinstance(value, (int, float)):
        return float(value)
    if not re.fullmatch(r"(?:\d+(?:ms|[smhdwy]))+", value):
        raise ValueError("Unsupported rule duration")
    units = {"ms": .001, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "y": 31536000}
    return sum(int(n) * units[u] for n, u in re.findall(r"(\d+)(ms|[smhdwy])", value))


def loaded_rules(data):
    rules = []
    for group in data["data"]["groups"]:
        for rule in group["rules"]:
            if rule.get("type") != "alerting":
                continue
            rules.append({"alert": rule["name"], "expr_sha256": digest(rule["query"]),
                          "group_sha256": digest(group["name"]),
                          "labels_sha256": object_digest(rule.get("labels", {})),
                          "annotations_sha256": object_digest(rule.get("annotations", {})),
                          "duration": rule.get("duration"), "keep_firing_for": rule.get("keepFiringFor", 0),
                          "label_keys": sorted(rule.get("labels", {})), "health": rule.get("health"),
                          "has_last_error": bool(rule.get("lastError")), "state": rule.get("state"),
                          "last_evaluation": rule.get("lastEvaluation"), "interval": group.get("interval")})
    return rules


def stages(item, evidence):
    result = {stage: "UNVERIFIED" for stage in STAGES}
    if isinstance(item["inputs"], list):
        inputs = [evidence[ref] for ref in item["inputs"]]
        if inputs and all(x["status"] == "SUCCESS" and x.get("summary", {}).get("result") == "PRESENT" for x in inputs):
            result["SELECTOR_VERIFIED"] = "VERIFIED"
        # INPUT needs units, types, continuity and PC mapping, not just sample presence.
    else:
        result["SELECTOR_VERIFIED"] = "BLOCKED"
    evaluation = evidence.get(item["evaluation"], {})
    if evaluation.get("status") == "SUCCESS":
        result["QUERY_SUCCESS"] = "VERIFIED"
    elif evaluation.get("status") in UNREACHABLE or not evaluation:
        result["QUERY_SUCCESS"] = "BLOCKED"
    elif evaluation.get("status") == "HTTP_ERROR" and evaluation.get("http_status") in {401, 403, 404}:
        result["QUERY_SUCCESS"] = "BLOCKED"
    elif evaluation.get("status") not in {"PARTIAL"}:
        result["QUERY_SUCCESS"] = "FAIL"
    if item.get("exact_definition_loaded"):
        result["RULE_LOADED"] = "VERIFIED"
    if (item.get("matching_definition_count") or 0) > 1:
        result["RULE_LOADED"] = "FAIL"
    # Current firing state and same-name AM alerts are observations, not correlated E2E proof.
    return result


def collect(clients, at, expected_model=None, bundle=None):
    p = plan() if bundle is None else plan(bundle)
    evidence, inventories = {}, {}
    identities = Identities()

    def get(service, name, path, params=None, summarizer=None):
        meta, data = clients[service].get(path, params)
        if data is not None:
            try:
                meta["summary"] = summarizer(data) if summarizer else {}
            except (KeyError, TypeError, ValueError, OverflowError):
                meta["status"] = "UNEXPECTED_RESPONSE"
        evidence[name] = meta
        return data if meta["status"] == "SUCCESS" else None

    targets = get("prometheus", "prometheus_targets", "/api/v1/targets", summarizer=lambda d: {
        "active": [{"identity": identity_summary(x["labels"], identities),
                    "health": x["health"], "last_scrape": x["lastScrape"],
                    "has_last_error": bool(x.get("lastError")), "label_keys": sorted(x["labels"])}
                   for x in d["data"]["activeTargets"]]})
    labels = get("loki", "loki_labels", "/loki/api/v1/labels",
                 {"start": str(int((at - 1800) * 1e9)), "end": str(int(at * 1e9))},
                 lambda d: {"label_names": d["data"]})
    for engine, path in (("prometheus", "/api/v1/rules"), ("loki", "/prometheus/api/v1/rules")):
        inventory = get(engine, engine + "_rules", path, {"type": "alert"}, loaded_rules)
        if inventory is not None:
            inventories[engine] = evidence[engine + "_rules"]["summary"]
        get(engine, engine + "_build", "/api/v1/status/buildinfo" if engine == "prometheus" else "/loki/api/v1/status/buildinfo",
            summarizer=lambda d: {"version": d.get("data", d).get("version")})

    def unreachable(engine):
        primary = "prometheus_targets" if engine == "prometheus" else "loki_labels"
        return all(evidence[key]["status"] in UNREACHABLE for key in (primary, engine + "_rules", engine + "_build"))

    get("alertmanager", "alertmanager_status", "/api/v2/status", summarizer=am_summary)
    get("alertmanager", "alertmanager_alerts", "/api/v2/alerts", summarizer=lambda d: {
        "alerts": [{"alert": x["labels"].get("alertname"), "label_keys": sorted(x["labels"]),
                    "identity": identity_summary(x["labels"], identities),
                    "starts_at": x.get("startsAt"), "ends_at": x.get("endsAt"),
                    "annotation_keys": sorted(x.get("annotations", {})),
                    "state": x.get("status", {}).get("state")} for x in d]})
    get("pipeline", "pipeline_health", "/health", summarizer=lambda d: {"status": d["status"], "timestamp": d.get("timestamp")})
    get("pipeline", "pipeline_schema", "/openapi.json", summarizer=webhook_summary)
    get("ollama", "ollama_tags", "/api/tags", summarizer=lambda d: {
        "model_count": len(d["models"]),
        "code_default_model_present": any(x.get("name") == "llama3.1:8b" for x in d["models"]),
        "expected_model_present": any(x.get("name") == expected_model for x in d["models"]) if expected_model else None,
        "deployed_model_identity": "UNVERIFIED"})
    if p["legacy_sql_expr"] and not unreachable("loki"):
        get("loki", "existing_rca_metadata", "/loki/api/v1/query_range", {
            "query": '{job="aiops-llm"}', "start": str(int((at - 86400) * 1e9)),
            "end": str(int(at * 1e9)), "limit": 50, "direction": "backward"}, rca_summary)
        get("loki", "existing_timeline_metadata", "/loki/api/v1/query_range", {
            "query": '{job="aiops-timeline"}', "start": str(int((at - 86400) * 1e9)),
            "end": str(int(at * 1e9)), "limit": 50, "direction": "backward"},
            lambda d: log_summary(d, identities))

    cache, results = {}, []
    for rule in p["rules"]:
        engine = rule["engine"]
        item = {k: rule[k] for k in ("id", "engine", "alert", "target", "static_labels")}
        item.update({"scope_acceptance": "UNVERIFIED", "pipeline_resolution": "UNVERIFIED", "alert_e2e": "UNVERIFIED"})
        if unreachable(engine):
            item.update({"inputs": "UNVERIFIED_API_UNAVAILABLE", "evaluation": "UNVERIFIED_API_UNAVAILABLE"})
        else:
            refs = []
            for selector in rule["inputs"]:
                key = engine + "_input_" + digest(selector)
                refs.append(key)
                if key not in cache:
                    path = "/api/v1/query" if engine == "prometheus" else "/loki/api/v1/query_range"
                    params = {"query": selector, "time": at} if engine == "prometheus" else {
                        "query": selector, "start": str(int((at - 1800) * 1e9)), "end": str(int(at * 1e9)), "limit": 50, "direction": "backward"}
                    summarize = vector_summary if engine == "prometheus" else log_summary
                    get(engine, key, path, params, lambda d: summarize(d, identities))
                    cache[key] = True
            key = "evaluation_" + rule["id"]
            get(engine, key, "/api/v1/query" if engine == "prometheus" else "/loki/api/v1/query", {"query": rule["expr"], "time": at}, lambda d: vector_summary(d, identities))
            item.update({"inputs": refs, "evaluation": key,
                         "same_name_loaded": [r for r in inventories[engine] if r["alert"] == rule["alert"]] if engine in inventories else None,
                         "exact_expression_loaded": any(r["expr_sha256"] == digest(rule["expr"]) for r in inventories.get(engine, []))
                         if engine in inventories else None})
        matches = [r for r in inventories.get(engine, []) if r["alert"] == rule["alert"]
                   and r["group_sha256"] == rule["group_sha256"]
                   and (rule["configured_interval"] is None or r["interval"] == rule["configured_interval"])
                   and r["expr_sha256"] == digest(rule["expr"])
                   and r["labels_sha256"] == object_digest(rule["static_labels"])
                   and r["annotations_sha256"] == rule["annotations_sha256"]
                   and r["duration"] == rule["duration"] and r["keep_firing_for"] == rule["keep_firing_for"]]
        item["exact_definition_loaded"] = len(matches) == 1 if engine in inventories else None
        item["matching_definition_count"] = len(matches) if engine in inventories else None
        item["loaded_state_observations"] = [r["state"] for r in matches]
        item["stages"] = stages(item, evidence)
        results.append(item)
    if not unreachable("loki"):
        get("loki", "legacy_sql_evaluation", "/loki/api/v1/query", {"query": p["legacy_sql_expr"], "time": at}, vector_summary)
    return {"version": 2, "mode": "READ_ONLY_RUNTIME_PROBE", "evaluated_at_utc": datetime.fromtimestamp(at, timezone.utc).isoformat(),
            "candidate_sha256": p["candidate_sha256"], "endpoints": {k: {
                "origin_token": identities.token("endpoint", c.base), "address_redacted": True} for k, c in clients.items()},
            "evidence": evidence, "rules": results, "deployment_performed": False,
            "actual_alert_e2e_verified": False, "normal_status": "NORMAL_UNCONFIRMED",
            "limits": "Instant predicate evaluation and bounded input samples; no for/keep-firing, scope, delivery, or RCA certification"}


def rca_summary(data):
    body = data.get("data", {})
    if body.get("resultType") != "streams":
        raise ValueError("Expected RCA streams")
    entries = []
    for stream in body["result"]:
        for ts, line in stream["values"]:
            try:
                obj = json.loads(line)
                result = obj.get("result", {})
                entries.append({"entry_ns": int(ts), "timestamp": obj.get("timestamp")
                                if isinstance(obj.get("timestamp"), str) and re.fullmatch(r"[0-9T:Z.+-]+", obj["timestamp"]) else None,
                                "top_level_keys": sorted(obj), "result_keys": sorted(result),
                                "identity_keys": sorted(set(obj) & {"source", "source_id", "site", "runtime", "instance", "identity", "run_id"}),
                                "zero_confidence": result.get("confidence") == 0,
                                "candidate_rca_verified": False})
            except (ValueError, TypeError, AttributeError):
                entries.append({"invalid_record": True, "candidate_rca_verified": False})
    return {"sample_rows": len(entries), "sample_cap_reached": len(entries) >= 50, "entries": entries,
            "historical_metadata_only": True}


def webhook_summary(data):
    schemas = data["components"]["schemas"]
    label = schemas["AlertLabel"]
    post = data["paths"].get("/webhook/alert", {}).get("post", {})
    return {"webhook_post_present": bool(post),
            "request_schema_ref": post.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {}).get("$ref"),
            "alert_label_properties": sorted(label["properties"]),
            "alert_label_additionalProperties": label.get("additionalProperties", "unspecified"),
            "schemas": {key: {"properties": sorted(schemas[key].get("properties", {})),
                              "required": schemas[key].get("required", [])}
                        for key in ("AlertLabel", "Alert", "AlertManagerWebhook") if key in schemas}}


def am_summary(d):
    config = yaml.safe_load(d.get("config", {}).get("original", "")) or {}
    urls = [x.get("url") for r in config.get("receivers", []) for x in r.get("webhook_configs", [])]
    return {"version": d.get("versionInfo", {}).get("version"),
            "configured_pipeline_webhook_present": "http://pipeline:8000/webhook/alert" in urls,
            "receiver_count": len(config.get("receivers", [])),
            "route_timing": {k: config.get("route", {}).get(k) for k in ("group_wait", "group_interval", "repeat_interval")},
            "identity_grouping_present": set(("alertname", "site", "source", "service", "runtime", "target")) <= set(config.get("route", {}).get("group_by", []))}


def output_path(value):
    path = Path(value).resolve()
    if path.is_relative_to(ROOT) and not path.is_relative_to(OUTPUT):
        raise ValueError("Repository outputs are restricted to docs/rulepack/m5b")
    if path.suffix != ".json" or path.is_symlink():
        raise ValueError("JSON evidence output required")
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", action="store_true", help="Write exact query plan without network access")
    parser.add_argument("--output")
    parser.add_argument("--bundle", type=Path, help="Reviewed prepare_release bundle; exact rules/hashes replace M5-A probe definitions")
    for service, port in (("prometheus", 9090), ("loki", 3100), ("alertmanager", 9093), ("pipeline", 8000), ("ollama", 11434)):
        parser.add_argument("--" + service, default=f"http://127.0.0.1:{port}")
    parser.add_argument("--at", help="RFC3339 query instant; no assertion of normal operation")
    parser.add_argument("--expected-model", help="Previously verified deployed Ollama model; tags presence is not inference proof")
    args = parser.parse_args()
    out = output_path(args.output or str(OUTPUT / ("query-plan.json" if args.plan else "runtime.json")))
    at = datetime.fromisoformat(args.at.replace("Z", "+00:00")) if args.at else datetime.now(timezone.utc)
    if at.tzinfo is None:
        raise ValueError("Explicit timezone required")
    data = plan(args.bundle) if args.plan else collect({name: Client(getattr(args, name)) for name in ("prometheus", "loki", "alertmanager", "pipeline", "ollama")}, at.timestamp(), args.expected_model, args.bundle)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(out), "definitions": len(data["rules"]), "actual_alert_e2e_verified": False}))


if __name__ == "__main__":
    main()
