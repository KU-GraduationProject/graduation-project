"""Assemble M5-A offline candidates, never write to operating mounts or services.

M2 replaces its eight original alert names. M3 SQLInjection is the candidate
primary; legacy SQLInjectionAttempt remains in a separate reference-only file.
Requires PyYAML. --check verifies upstream generation and bundle drift read-only.
"""

from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "docs/rulepack/m5/integration.yml"
OUTPUT = ROOT / "docs/rulepack/m5"
ORIGINALS = {
    "legacy_security": ("loki", "monitoring/loki/rules/fake/security-rules.yml"),
    "legacy_network": ("loki", "monitoring/loki/rules/fake/network-allowlist.yml"),
    "legacy_metrics": ("prometheus", "monitoring/prometheus/rules/alert.rules.yml"),
}
DRAFTS = {
    "m2_logs": ("loki", "docs/rulepack/m2/generated/loki.rules.yml"),
    "m2_metrics": ("prometheus", "docs/rulepack/m2/generated/prometheus.rules.yml"),
    "m2_infra": ("prometheus", "docs/rulepack/m2/generated/prometheus.infra.rules.yml"),
    "m2_resources": ("prometheus", "docs/rulepack/m2/generated/prometheus.resources.rules.yml"),
    "m3_logs": ("loki", "docs/rulepack/m3/generated/loki.rules.yml"),
}
REPLACEMENTS = {
    "UnauthorizedDBAccess": "m2_logs", "HighNginxErrorRate": "m2_logs", "VulnerabilityScanningDetected": "m2_logs",
    "HighNginxRequestRate": "m2_metrics", "HighCpuUsage": "m2_infra", "ContainerRestarted": "m2_infra",
    "HighMemoryUsage": "m2_resources", "HighNetworkReceive": "m2_resources",
}
EXPECTED_ORIGINALS = set(REPLACEMENTS) | {
    "SecretDumpAttempt", "SQLInjectionAttempt", "SuspiciousProcessExecution", "SuspiciousProcessExec",
    "PathTraversalAttempt", "ContainerEscapeAttempt", "UnauthorizedDataTransfer", "UnauthorizedTransferEarly", "HighPostgresConnections",
}


class _Dumper(yaml.SafeDumper):
    pass


def _string(dumper, value):
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|" if "\n" in value else None)


_Dumper.add_representer(str, _string)


def load_module(name):
    spec = importlib.util.spec_from_file_location("m5_" + name, Path(__file__).with_name(name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def upstream():
    """Re-render in memory to reject stale drafts; never rewrite M2/M3 files."""
    modules = [load_module(name) for name in ("generate_m2", "generate_m2_2", "generate_m2_3", "generate_m3")]
    m2, infra, resources, m3 = modules
    configurations = [m2.DEFAULT_CONFIG, infra.CONFIG, resources.CONFIG, m3.DEFAULT_CONFIG]
    expected = {m2.DEFAULT_OUTPUT / name: text for name, text in m2.render(yaml.safe_load(configurations[0].read_text(encoding="utf-8"))).items()}
    for module, config, output in zip(modules[1:], configurations[1:], (infra.OUTPUT, resources.OUTPUT, m3.OUTPUT)):
        expected[output] = module.render(yaml.safe_load(config.read_text(encoding="utf-8")))
    for path, text in expected.items():
        if path.read_text(encoding="utf-8") != text:
            raise ValueError(f"Upstream draft drift; review/reproduce separately: {path.relative_to(ROOT)}")
    return configurations + [Path(module.__file__) for module in modules]


def flattened(document):
    return [rule for group in document["groups"] for rule in group["rules"]]


def read_document(path):
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or set(document) != {"groups"} or not isinstance(document["groups"], list):
        raise ValueError("Expected an alert rule group document")
    for group in document["groups"]:
        if not isinstance(group, dict) or not isinstance(group.get("name"), str) or not isinstance(group.get("rules"), list):
            raise ValueError("Invalid group")
        for rule in group["rules"]:
            if not isinstance(rule, dict) or not {"alert", "expr", "for", "labels", "annotations"} <= set(rule):
                raise ValueError("Expected alert, expression, timing, labels and annotations")
            if any(not isinstance(rule[key], str) or not rule[key].strip() for key in ("alert", "expr", "for")):
                raise ValueError("Invalid alert/expression/timing")
            if rule["labels"].get("severity") not in {"warning", "critical"} or rule["labels"].get("category") not in {"infra", "security"} or not rule["annotations"].get("container"):
                raise ValueError("Existing severity/category/Pipeline target contract required")
    return document


def validate_bundle(documents):
    identities, predicates = set(), set()
    for engine, document in documents.items():
        names = [group["name"] for group in document["groups"]]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate group name")
        for rule in flattened(document):
            identity = rule["alert"], tuple(sorted(rule["labels"].items()))
            if identity in identities:
                raise ValueError("Ambiguous duplicate alert/static-label identity")
            identities.add(identity)
            predicate = engine, rule["expr"].strip(), rule["for"], rule.get("keep_firing_for")
            if predicate in predicates:
                raise ValueError("Duplicate exact condition under multiple alert identities")
            predicates.add(predicate)
    names = {rule["alert"] for document in documents.values() for rule in flattened(document)}
    if "SQLInjection" not in names or "SQLInjectionAttempt" in names:
        raise ValueError("M3 SQL primary and legacy reference separation required")
    if "LoginBruteForce" in names:
        raise ValueError("Deferred authentication contract must not become an alert")


def yaml_text(document):
    return "# M5-A offline candidate/reference only; not mounted or deployed. Do not edit.\n" + yaml.dump(
        document, Dumper=_Dumper, allow_unicode=True, sort_keys=False, width=110)


def validate_cross_component_mappings(web_db, infra, resources, logs):
    shared_sources = sorted(infra["sources"].keys() & resources["sources"].keys())
    for source in shared_sources:
        left, right = infra["sources"][source], resources["sources"][source]
        for collector in {"cadvisor", "pipeline"} & left.keys() & right.keys():
            if left[collector] != right[collector]:
                raise ValueError("Same source id has inconsistent collector selectors across M2 components")
    shared_aliases = set()
    for role in ("web_targets", "postgres_targets"):
        for left in web_db[role]:
            for right in logs[role]:
                if left["alert_target"] != right["alert_target"]:
                    continue
                shared_aliases.add(left["alert_target"])
                a, b = left["log_selector"], right["log_selector"]
                if any(a[key] != b[key] for key in a.keys() & b.keys()):
                    raise ValueError("Same log-role alias has conflicting selectors across M2/M3")
    return {"shared_source_ids_checked": shared_sources, "shared_log_aliases_checked": sorted(shared_aliases),
            "meaning": "Static mapping consistency only; does not resolve mixed Docker/host runtime identities"}


def render(config):
    if config != {"version": 1, "sql_injection_policy": "m3_primary_legacy_reference"} or type(config.get("version")) is not int:
        raise ValueError("Only version=1 / explicit m3_primary_legacy_reference policy is supported")
    dependencies = upstream()
    inputs = {key: read_document(ROOT / path) for key, (_, path) in {**ORIGINALS, **DRAFTS}.items()}
    originals = [rule for key in ORIGINALS for rule in flattened(inputs[key])]
    if len(originals) != 17 or {rule["alert"] for rule in originals} != EXPECTED_ORIGINALS:
        raise ValueError("Original inventory changed; review the 17-rule integration mapping")
    for component in DRAFTS:
        expected = {name for name, source in REPLACEMENTS.items() if source == component} if component != "m3_logs" else {"SQLInjection", "DBConnectionLimit"}
        if {rule["alert"] for rule in flattened(inputs[component])} != expected:
            raise ValueError(f"Unexpected or missing generated alert names in {component}")
    documents = {"loki": {"groups": []}, "prometheus": {"groups": []}}
    reference = {"groups": []}
    entries = []
    for component, (engine, source) in {**ORIGINALS, **DRAFTS}.items():
        for group in inputs[component]["groups"]:
            keep = []
            for index, rule in enumerate(group["rules"]):
                if component in ORIGINALS and rule["alert"] in REPLACEMENTS:
                    continue
                if component in ORIGINALS and rule["alert"] == "SQLInjectionAttempt":
                    reference["groups"].append({**deepcopy(group), "name": "m5-reference-legacy-sqli", "rules": [deepcopy(rule)]})
                    continue
                keep.append(deepcopy(rule))
                entries.append({"engine": engine, "alert": rule["alert"], "labels": deepcopy(rule["labels"]), "component": component,
                                "origin": source, "origin_group": group["name"], "origin_index": index,
                                "rule_sha256": hashlib.sha256(json.dumps(rule, ensure_ascii=False, sort_keys=True).encode()).hexdigest()})
            if keep:
                documents[engine]["groups"].append({**deepcopy(group), "name": "m5-" + component + "-" + group["name"], "rules": keep})
    validate_bundle(documents)
    rendered = {f"generated/{engine}.rules.yml": yaml_text(document) for engine, document in documents.items()}
    rendered["reference/loki.legacy-sqli.rules.yml"] = yaml_text(reference)
    m2_web_db = yaml.safe_load((ROOT / "docs/rulepack/m2/targets.yml").read_text(encoding="utf-8"))
    m2_infra = yaml.safe_load((ROOT / "docs/rulepack/m2/infra_targets.yml").read_text(encoding="utf-8"))
    m2_resources = yaml.safe_load((ROOT / "docs/rulepack/m2/resource_targets.yml").read_text(encoding="utf-8"))
    m3_targets = yaml.safe_load((ROOT / "docs/rulepack/m3/targets.yml").read_text(encoding="utf-8"))
    mapping_checks = validate_cross_component_mappings(m2_web_db, m2_infra, m2_resources, m3_targets)
    cpu_aliases = {target["alert_target"] for target in m2_infra["targets"] if "cpu" in target["rules"]}
    host_aliases = {target["alert_target"] for target in m3_targets["postgres_targets"] if target["log_selector"].get("runtime") == "host"}
    warnings = [
        {"id": "MIXED_CONFIGURED_SCOPES", "detail": "Integrated Docker resource inputs and host PG17 log inputs need separate runtime/source acceptance."},
        {"id": "PIPELINE_SOURCE_AND_HOST_ROUTING", "detail": "Existing AlertLabel/dedup do not preserve source identity or reliably classify host fallback; OI-09 remains open."},
        {"id": "BASELINE_NOT_USED", "detail": "No normal interval or threshold candidate is assumed. Every condition is copied from original/M2/M3 definitions."},
        {"id": "LEGACY_MARKER_TELEMETRY", "detail": "Retained stdout markers/command strings do not establish process execution or host compromise."},
    ]
    if cpu_aliases & host_aliases:
        warnings.append({"id": "HOST_CONTAINER_ALIAS_CONFLICT", "aliases": sorted(cpu_aliases & host_aliases),
                         "detail": "The same Pipeline alias is used by integrated Docker CPU and host PostgreSQL logs; this is not an accepted deployment profile."})
    dependency_paths = [ROOT / path for _, path in {**ORIGINALS, **DRAFTS}.values()] + dependencies + [Path(__file__)]
    manifest = {
        "version": 1, "scope": "offline mixed-scope review candidate", "deployment_allowed": False, "policy": deepcopy(config),
        "active_files": ["generated/loki.rules.yml", "generated/prometheus.rules.yml"],
        "reference_only_files": ["reference/loki.legacy-sqli.rules.yml"],
        "counts": {"original_names": 17, "m2_replaced_names": 8, "legacy_sql_reference_names": 1,
                   "retained_original_definitions": sum(entry["component"] in ORIGINALS for entry in entries),
                   "active_definitions": len(entries), "unique_active_names": len({entry["alert"] for entry in entries}),
                   "definitions_by_engine": dict(Counter(entry["engine"] for entry in entries))},
        "original_disposition": [{"alert": rule["alert"], "status": "replaced_by_m2" if rule["alert"] in REPLACEMENTS else "reference_only" if rule["alert"] == "SQLInjectionAttempt" else "retained",
                                  "candidate": REPLACEMENTS.get(rule["alert"], "m3_logs" if rule["alert"] == "SQLInjectionAttempt" else "original")} for rule in originals],
        "deferred": ["LoginBruteForce", "DB connection utilization/max_connections branch"],
        "cross_component_checks": mapping_checks,
        "runtime_acceptance": "UNVERIFIED; mixed source/alias/identity gates remain", "warnings": warnings,
        "group_timing": "Preserved from each input group; unspecified intervals still inherit the server setting. M3 interval=5s remains explicit.",
        "inputs_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(set(dependency_paths))},
        "policy_sha256": hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest(),
        "outputs_sha256": {name: hashlib.sha256(text.encode()).hexdigest() for name, text in rendered.items()}, "entries": entries,
    }
    rendered["manifest.json"] = json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    return rendered


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        result = render(yaml.safe_load(args.config.read_text(encoding="utf-8")))
        if args.check:
            if any(not (OUTPUT / name).is_file() or (OUTPUT / name).read_text(encoding="utf-8") != text for name, text in result.items()):
                raise ValueError("M5 candidate/manifest/reference drift")
            print("M5-A bundle check: PASS; no deployment/runtime claim")
        else:
            for name, text in result.items():
                path = OUTPUT / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            print(f"Rendered offline candidates/reference/manifest in {OUTPUT}; nothing loaded")
    except (ValueError, OSError, TypeError, KeyError, yaml.YAMLError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
