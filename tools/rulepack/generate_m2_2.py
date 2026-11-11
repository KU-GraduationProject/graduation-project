"""Render CPU/restart static drafts outside deployment paths; requires PyYAML.

python tools/rulepack/generate_m2_2.py
python tools/rulepack/generate_m2_2.py --check

M2-1 is independent and unchanged. No service, Docker or network calls are made.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import re

import yaml

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "docs/rulepack/m2/infra_targets.yml"
OUTPUT = ROOT / "docs/rulepack/m2/generated/prometheus.infra.rules.yml"
SOURCE = ROOT / "monitoring/prometheus/rules/alert.rules.yml"
ALERTS = {"cpu": "HighCpuUsage", "restart": "ContainerRestarted"}
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
HEADER = "# Generated M2-2 static draft; not mounted by Compose. Do not edit.\n"


class _Dumper(yaml.SafeDumper):
    pass


def _string(dumper, value):
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|" if "\n" in value else None)


_Dumper.add_representer(str, _string)


def _identifier(value: object, field: str):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError(f"Invalid {field}")


def _scope(value: object):
    # job/instance are supplied by the existing Prometheus scrape configurations.
    # Explicitly pair one Docker scope; do not infer service/role/site labels.
    if not isinstance(value, dict) or set(value) != {"job", "instance"}:
        raise ValueError("Source selector requires exactly job and instance")
    for field, text in value.items():
        if not isinstance(text, str) or not text.strip() or any(ord(c) < 32 or ord(c) == 127 for c in text):
            raise ValueError(f"Invalid source {field}")


def validate_config(config: object) -> dict:
    if not isinstance(config, dict) or set(config) != {"version", "sources", "targets"}:
        raise ValueError("Expected version, sources and targets")
    if type(config["version"]) is not int or config["version"] != 1:
        raise ValueError("Only version 1 is supported")
    sources = config["sources"]
    if not isinstance(sources, dict) or not sources:
        raise ValueError("sources must be a non-empty mapping")
    seen_scopes = {"pipeline": set(), "cadvisor": set()}
    for name, source in sources.items():
        _identifier(name, "source id")
        if not isinstance(source, dict) or set(source) not in ({"pipeline"}, {"pipeline", "cadvisor"}):
            raise ValueError("Each source requires pipeline and optional cadvisor")
        for collector, scope in source.items():
            _scope(scope)
            identity = (scope["job"], scope["instance"])
            if identity in seen_scopes[collector]:
                raise ValueError(f"Overlapping {collector} source selectors")
            seen_scopes[collector].add(identity)
    targets = config["targets"]
    if not isinstance(targets, list) or not targets:
        raise ValueError("targets must be a non-empty list")
    ids, aliases, identities = set(), set(), set()
    for target in targets:
        if not isinstance(target, dict) or set(target) != {"id", "source", "name", "alert_target", "rules"}:
            raise ValueError("Target requires id, source, name, alert_target and rules")
        for field in ("id", "source", "name", "alert_target"):
            _identifier(target[field], field)
        if target["source"] not in sources:
            raise ValueError("Unknown target source")
        enabled = target["rules"]
        if not isinstance(enabled, list) or not enabled or any(not isinstance(r, str) or r not in ALERTS for r in enabled):
            raise ValueError("rules must contain cpu and/or restart")
        if len(set(enabled)) != len(enabled):
            raise ValueError("Duplicate rule selection")
        if "cpu" in enabled and "cadvisor" not in sources[target["source"]]:
            raise ValueError("CPU target requires a cadvisor source")
        identity = (target["source"], target["name"])
        if target["id"] in ids or target["alert_target"] in aliases or identity in identities:
            raise ValueError("Duplicate or ambiguous target identity/alias")
        ids.add(target["id"])
        aliases.add(target["alert_target"])
        identities.add(identity)
    return config


def selector(labels: dict) -> str:
    return "{" + ", ".join(f"{key}={json.dumps(value, ensure_ascii=False)}"
                            for key, value in sorted(labels.items())) + "}"


def source_rules() -> dict:
    document = yaml.safe_load(SOURCE.read_text(encoding="utf-8"))
    result = {}
    for group in document["groups"]:
        for rule in group["rules"]:
            if rule.get("alert") in ALERTS.values():
                if rule["alert"] in result:
                    raise ValueError("Duplicate source alert")
                result[rule["alert"]] = rule
    if set(result) != set(ALERTS.values()):
        raise ValueError("Missing CPU/restart source rules")
    return result


def _cpu_expression(expression: str, target: dict, source: dict) -> str:
    token = 'container_cpu_usage_seconds_total{id=~"/docker/.+",cpu="total"}'
    if expression.count(token) != 1:
        raise ValueError("Review changed CPU metric contract before rendering")
    # Keep /docker/, cpu=total, irate, sum(name), and the original on(id) join.
    cpu_scope = selector(source["cadvisor"])[1:-1]
    expression = expression.replace(token, token[:-1] + ", " + cpu_scope + "}")
    metadata = list(re.finditer(r"container_name_info(?:\{[^{}]*\})?", expression))
    if len(metadata) != 2 or metadata[0].group() != "container_name_info" or not re.fullmatch(
        r'container_name_info\{name=~"[^"\\]+"\}', metadata[1].group()
    ):
        raise ValueError("Review changed CPU metadata join before rendering")
    # Scope the join without prefiltering name: duplicate RHS ids must still fail.
    replacements = [selector(source["pipeline"]), selector({**source["pipeline"], "name": target["name"]})]
    for match, replacement in reversed(list(zip(metadata, replacements))):
        expression = expression[:match.start()] + "container_name_info" + replacement + expression[match.end():]
    return expression


def _restart_expression(expression: str, target: dict, source: dict) -> str:
    # Change only each name selector; retain both branches and reset/gap handling.
    for metric, expected in (("aiops_docker_container_restarts_total", 4),
                             ("aiops_docker_container_started_at_seconds", 1)):
        pattern = re.escape(metric) + r'\{name="[^"\\]+"\}'
        replacement = metric + selector({**source["pipeline"], "name": target["name"]})
        expression, count = re.subn(pattern, lambda _: replacement, expression)
        if count != expected:
            raise ValueError("Review changed restart selectors before rendering")
    return expression


def build_rules(config: dict) -> dict:
    validate_config(config)
    originals = source_rules()
    rules = []
    for target in config["targets"]:
        source = config["sources"][target["source"]]
        for kind in ("cpu", "restart"):
            if kind not in target["rules"]:
                continue
            rule = deepcopy(originals[ALERTS[kind]])
            transform = _cpu_expression if kind == "cpu" else _restart_expression
            rule["expr"] = transform(rule["expr"], target, source)
            rule["labels"]["rulepack_target"] = target["id"]
            rule["annotations"]["container"] = target["alert_target"]
            rules.append(rule)
    return {"groups": [{"name": "m2-2-static-infra", "rules": rules}]}


def render(config: dict) -> str:
    return HEADER + yaml.dump(build_rules(config), Dumper=_Dumper, allow_unicode=True, sort_keys=False, width=110)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--check", action="store_true", help="Verify draft drift without writing")
    args = parser.parse_args()
    try:
        text = render(yaml.safe_load(args.config.read_text(encoding="utf-8")))
        if args.check:
            if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != text:
                raise ValueError("M2-2 generated draft differs")
            print("M2-2 draft check: PASS (runtime unverified)")
        else:
            OUTPUT.parent.mkdir(parents=True, exist_ok=True)
            OUTPUT.write_text(text, encoding="utf-8")
            print(f"Rendered static draft: {OUTPUT}; no reload/deployment performed")
    except (OSError, ValueError, yaml.YAMLError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
