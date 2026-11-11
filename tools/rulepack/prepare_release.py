"""Build an offline GC/JH review bundle from operator-verified inventory.

No network, daemon, deployment, reload or image build. Existing M2/M5 drafts
remain immutable inputs. Empty/placeholder inventories cannot produce a bundle.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "aiops/pipeline"))
from identity import parse_bindings
import generate_m2_2 as infra
import generate_m2_3 as resources

FIELDS = ("site", "source", "service", "runtime", "target")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
CID = re.compile(r"[a-f0-9]{64}\Z")
DIMENSIONS = "site, source, service, runtime, target, name"


def value(text):
    if (not isinstance(text, str) or not text.strip() or
            any(x in text.upper() for x in ("REPLACE", "UNKNOWN", "<", ">")) or
            any(ord(c) < 32 for c in text)):
        raise ValueError("verified non-placeholder inventory values required")
    return text


def validate(config):
    if set(config) != {"version", "inventory_verified", "gc", "telemetry", "host_postgres"}:
        raise ValueError("unexpected release profile keys")
    if type(config["version"]) is not int or config["version"] != 1 or config["inventory_verified"] is not True:
        raise ValueError("operator inventory attestation required")
    gc, endpoint = config["gc"], config["telemetry"]
    if set(gc) != {"site", "source", "project", "targets"} or set(endpoint) != {"job", "instance"}:
        raise ValueError("unexpected GC/endpoint keys")
    for k in ("site", "source", "project"):
        if not NAME.fullmatch(value(gc[k])):
            raise ValueError("GC labels must satisfy the producer contract")
    if not gc["targets"] or set(gc["targets"]) - {"frontend", "backend", "minio"}:
        raise ValueError("GC Docker profile excludes host PostgreSQL")
    names, ids = set(), set()
    for target in gc["targets"].values():
        if set(target) != {"name", "id"} or not NAME.fullmatch(value(target["name"])) or not CID.fullmatch(target["id"]):
            raise ValueError("exact Docker name/full id required")
        if target["name"] in names or target["id"] in ids:
            raise ValueError("duplicate Docker identity")
        names.add(target["name"]); ids.add(target["id"])
    for text in endpoint.values():
        value(text)
    # instance is a verified host:port, never a URL with embedded credentials.
    if not re.fullmatch(r"(?:[A-Za-z0-9_.-]+|\[[0-9a-fA-F:]+\]):[0-9]{1,5}", endpoint["instance"]):
        raise ValueError("verified private transport host:port required")
    if not 1 <= int(endpoint["instance"].rsplit(":", 1)[1]) <= 65535:
        raise ValueError("invalid transport port")
    pg = config["host_postgres"]
    if pg is not None:
        if set(pg) != {"site", "source", "target", "dedicated_receiver_verified"} or pg["dedicated_receiver_verified"] is not True:
            raise ValueError("host PG requires a dedicated authenticated sender/receiver attestation")
        for k in ("site", "source", "target"):
            if not NAME.fullmatch(value(pg[k])):
                raise ValueError("invalid PG identity")
        if pg["source"] == gc["source"] or pg["target"] in names:
            raise ValueError("host PG source/target must be separate from Docker")
    return config


def identity(gc, service, name):
    return {"site": gc["site"], "source": gc["source"], "service": service,
            "runtime": "container", "target": name}


def telemetry_expression(expr, gc):
    # Inputs are the strict original M2 renderers, whose selector grammar is
    # constrained. Add producer identity to every input, including fallback
    # suppression/count and the metadata RHS. Never join different endpoints.
    scope = ', site=' + json.dumps(gc["site"]) + ', source=' + json.dumps(gc["source"])
    expr = re.sub(r"\{([^{}]*)\}", lambda m: "{" + m[1] + scope + "}", expr)
    # Preserve identity through the original sum/max aggregations. Thresholds,
    # units, windows, reset handling, fallback suppression and timing stay intact.
    return re.sub(r"\b(sum|max) by \(name\)", lambda m: m[1] + " by (" + DIMENSIONS + ")", expr)


def log_rule(original, ident):
    rule = deepcopy(original)
    # App/PG rules have one stream selector. No broad source fallback is allowed.
    stream = re.search(r"\{[^{}]*\}", rule["expr"])
    if not stream or 'log_type="network"' in stream[0]:
        raise ValueError("network rules require the separately verified observer contract")
    body = stream[0][1:-1]
    body = re.sub(r'\bservice(?:=~|=)"(?:[^"\\]|\\.)*"',
                  'service=' + json.dumps(ident["service"]), body)
    required = {k: v for k, v in ident.items() if k != "service"}
    for k, v in required.items():
        if not re.search(r"\b" + k + r"\s*(?:=|!)", body):
            body += ", " + k + "=" + json.dumps(v)
        elif not re.search(r"\b" + k + "=" + re.escape(json.dumps(v)) + r"(?:,|$)", body):
            raise ValueError("log rule has a conflicting identity selector")
    rule["expr"] = rule["expr"][:stream.start()] + "{" + body + "}" + rule["expr"][stream.end():]
    rule["labels"].update(ident)
    # Host compatibility field is not a container action target; handoff stays off.
    rule["annotations"]["container"] = ident["target"]
    return rule


def render(config):
    validate(config)
    gc, endpoint = config["gc"], config["telemetry"]
    src = {"cadvisor": endpoint, "pipeline": endpoint}
    targets, bindings = [], []
    for service, target in gc["targets"].items():
        ident = identity(gc, service, target["name"])
        bindings.append({"identity": ident, "match": ident,
                         "logs": ident, "metrics_profile": "gc-telemetry-v1",
                         "metrics": {**ident, **endpoint, "id": "/docker/" + target["id"]}})
        targets.append({"id": service, "source": "gc", "name": target["name"],
                        "alert_target": target["name"],
                        "rules": ["cpu", "restart"] if service == "backend" else ["cpu"]})
    # Root cgroup signals are Docker VM host context, never Windows PostgreSQL.
    root_identity = {"site": gc["site"], "source": gc["source"], "service": "docker-vm",
                     "runtime": "host", "target": "docker-vm"}
    bindings.append({"identity": root_identity, "match": root_identity})
    infra_doc = infra.build_rules({"version": 1, "sources": {"gc": src}, "targets": targets})
    resource_doc = resources.build_rules({"version": 1, "sources": {"gc": {
        **src, "rules": ["memory", "network"], "network_names": [x["name"] for x in gc["targets"].values()]}}})
    for doc in (infra_doc, resource_doc):
        for group in doc["groups"]:
            group["name"] = "release-" + group["name"]
            group["interval"] = "5s"
            for rule in group["rules"]:
                rule["expr"] = telemetry_expression(rule["expr"], gc)
                if "rulepack_target" in rule["labels"]:
                    service = rule["labels"]["rulepack_target"]
                    rule["labels"].update(identity(gc, service, gc["targets"][service]["name"]))
                else:
                    rule["labels"].update(site=gc["site"], source=gc["source"], **{
                        k: "{{ $labels." + k + " }}" for k in ("service", "runtime", "target")})
    prom_rules = {"groups": infra_doc["groups"] + resource_doc["groups"]}
    pg = config["host_postgres"]
    if pg:
        ident = {k: pg[k] for k in ("site", "source", "target")}
        ident.update(service="db", runtime="host")
        bindings.append({"identity": ident, "match": ident, "logs": ident})
    parse_bindings(json.dumps(bindings))
    existing = yaml.safe_load((ROOT / "docs/rulepack/m5/generated/loki.rules.yml").read_text())
    logs, excluded = [], []
    for group in existing["groups"]:
        for rule in group["rules"]:
            selector = re.search(r"\{[^{}]*\}", rule["expr"])[0]
            if 'log_type="network"' in selector:
                excluded.append(rule["alert"] + ": observer_instance/host endpoint contract pending")
                continue
            if 'runtime="host"' in selector or 'service="db"' in selector:
                if pg:
                    logs.append(log_rule(rule, bindings[-1]["identity"]))
                else:
                    excluded.append(rule["alert"] + ": host PostgreSQL inventory/receiver missing")
                continue
            for service, target in gc["targets"].items():
                matcher = re.search(r'\bservice(=~|=)"([^"\\]*)"', selector)
                if matcher and (matcher[2] == service if matcher[1] == "=" else re.fullmatch(matcher[2], service)):
                    logs.append(log_rule(rule, identity(gc, service, target["name"])))
    loki_rules = {"groups": [{"name": "release-gc-app-and-host-logs", "interval": "5s", "rules": logs}]}
    scrape = yaml.safe_load((ROOT / "monitoring/prometheus/drafts/oi02-04/scrape.candidate.yml").read_text())["scrape_configs"][0]
    scrape["job_name"] = endpoint["job"]
    scrape["file_sd_configs"] = [{"files": ["/etc/prometheus/release/targets.json"]}]
    scrape["metric_relabel_configs"][0]["regex"] = re.escape(gc["site"]) + ";" + re.escape(gc["source"])
    prom_config = {"global": {"scrape_interval": "5s", "evaluation_interval": "5s"},
                   "alerting": {"alertmanagers": [{"static_configs": [{"targets": ["alertmanager:9093"]}]}]},
                   "rule_files": ["/etc/prometheus/release/prometheus.rules.yml"], "scrape_configs": [scrape]}
    am = yaml.safe_load((ROOT / "monitoring/alertmanager/alertmanager.yml").read_text())
    am["route"]["group_by"] = ["alertname", *FIELDS]
    fluent = (ROOT / "leafy/fluentd/fluent.conf").read_text()
    fluent = fluent.replace("      source         $._lbl_source", "      source         $._lbl_observation_source\n      log_stream     $._lbl_source\n      site           $._lbl_site\n      target         $._lbl_target")
    # PG labels are stamped from verified receiver config, not incoming JSON.
    if pg:
        params = '\n'.join('    ' + k + ' "' + pg[v] + '"' for k, v in
                           (("site", "site"), ("observation_source", "source"), ("target", "target")))
        fluent = fluent.replace("    runtime host", "    runtime host\n" + params)
        fluent = fluent.replace("      service    $._lbl_service", "      site       $._lbl_site\n      source     $._lbl_observation_source\n      target     $._lbl_target\n      service    $._lbl_service")
    logging = yaml.safe_load((ROOT / "deploy/leafy-pc/leafy-compose-logging.example.yml").read_text())
    logging.pop("x-aiops-log-opts", None)
    logging["services"] = {k: v for k, v in logging["services"].items() if k in gc["targets"]}
    for service, entry in logging["services"].items():
        entry["labels"] = {"aiops.site": gc["site"], "aiops.source": gc["source"]}
        entry["logging"]["options"] = {**entry["logging"]["options"], "labels": "com.docker.compose.service,aiops.site,aiops.source"}
    producer = {k: gc[k] for k in ("site", "source", "project")}
    producer["targets"] = {s: t["name"] for s, t in gc["targets"].items()}
    manifest = {"deployment_allowed": False, "runtime_accepted": False,
                "scope": "GC Docker and optional host PG; partial M5 deployment candidate",
                "excluded": excluded + ["HighNginxRequestRate: dedicated nginx exporter mapping pending",
                                         "HighPostgresConnections: host exporter unit/series mapping pending"],
                "gates": ["Docker Desktop cAdvisor compatibility", "JH-to-GC approved private transport/ACL",
                          "GC logging labels/container recreation approval", "dedicated PG receiver if enabled",
                          "real scrape/evaluation 5s and duplicate-source audit", "AM->Pipeline->Loki E2E"],
                "profile_sha256": hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()}
    docs = {"prometheus.rules.yml": prom_rules, "loki/fake/release.rules.yml": loki_rules,
            "prometheus.yml": prom_config, "alertmanager.yml": am, "gc.logging.override.yml": logging}
    # Compose merges volumes by container target. Each operating rule/config
    # mount is replaced explicitly, so old broad rules cannot stay loaded beside
    # these source-scoped candidates. No service is started by this generator.
    bundle = "${RELEASE_BUNDLE:?Set absolute reviewed bundle path}"
    docs["jh.compose.override.yml"] = {"services": {
        "prometheus": {"volumes": [bundle + ":/etc/prometheus/release:ro",
                                    bundle + "/prometheus.yml:/etc/prometheus/prometheus.yml:ro",
                                    bundle + "/empty-prometheus-rules:/etc/prometheus/rules:ro"]},
        "loki": {"volumes": [bundle + "/loki:/loki/rules:ro"]},
        "alertmanager": {"volumes": [bundle + "/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro"]},
        "fluentd": {"volumes": [bundle + "/fluent.conf:/fluentd/etc/fluent.conf:ro"]},
        "pipeline": {"environment": {"OBSERVATION_BINDINGS": json.dumps(bindings), "TARGET_SERVICE_MAP": "", "SLACK_WEBHOOK_URL": ""}},
        "remediation": {"environment": {"REMEDIATION_MODE": "disabled"}}
    }}
    result = {name: yaml.safe_dump(doc, allow_unicode=True, sort_keys=False) for name, doc in docs.items()}
    result.update({"bindings.json": json.dumps(bindings, indent=2) + "\n",
                   "pipeline.env": "OBSERVATION_BINDINGS=" + json.dumps(bindings, separators=(",", ":")) + "\n",
                   "collector.json": json.dumps(producer, indent=2) + "\n",
                   "targets.json": json.dumps([{"targets": [endpoint["instance"]]}], indent=2) + "\n",
                   "fluent.conf": fluent})
    manifest["outputs_sha256"] = {name: hashlib.sha256(text.encode()).hexdigest() for name, text in result.items()}
    result["manifest.json"] = json.dumps(manifest, indent=2) + "\n"
    result["empty-prometheus-rules/.keep"] = "No operating rules loaded from this mount.\n"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        # Never write into an operating mount or an existing review bundle.
        output = args.output.resolve()
        if output.exists() or ROOT.is_relative_to(output) or any(output.is_relative_to(ROOT / p) for p in
                ("monitoring", "leafy", "aiops", "deploy", "back", ".git")):
            raise ValueError("output must be a new review directory outside operating paths")
        rendered = render(json.loads(args.profile.read_text(encoding="utf-8-sig")))
        output.mkdir(parents=True)
        for name, text in rendered.items():
            path = output / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as exc:
        parser.error(str(exc))
    print("Offline review bundle created; deployment/runtime acceptance remains BLOCKED")


if __name__ == "__main__":
    main()
