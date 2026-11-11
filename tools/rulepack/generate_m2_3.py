"""Render source-scoped memory/network drafts without changing M2-1/M2-2.

python tools/rulepack/generate_m2_3.py [--check]
Requires PyYAML. Output is fixed outside Compose rule mounts; no services are called.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import re

import yaml

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "docs/rulepack/m2/resource_targets.yml"
OUTPUT = ROOT / "docs/rulepack/m2/generated/prometheus.resources.rules.yml"
SOURCE = ROOT / "monitoring/prometheus/rules/alert.rules.yml"
ALERTS = {"memory": "HighMemoryUsage", "network": "HighNetworkReceive"}
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
HEADER = "# Generated M2-3 static draft; not mounted by Compose. Do not edit.\n"


class _Dumper(yaml.SafeDumper):
    pass


def _string(dumper, value):
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|" if "\n" in value else None)


_Dumper.add_representer(str, _string)


def _scope(value):
    if not isinstance(value, dict) or set(value) != {"job", "instance"}:
        raise ValueError("Source requires exactly job and instance")
    if any(not isinstance(v, str) or not v.strip() or any(ord(c) < 32 or ord(c) == 127 for c in v)
           for v in value.values()):
        raise ValueError("Invalid source label value")


def validate_config(config):
    if not isinstance(config, dict) or set(config) != {"version", "sources"}:
        raise ValueError("Expected version and sources")
    if type(config["version"]) is not int or config["version"] != 1:
        raise ValueError("Only version 1 is supported")
    if not isinstance(config["sources"], dict) or not config["sources"]:
        raise ValueError("sources must be a non-empty mapping")
    seen = {"cadvisor": set(), "pipeline": set()}
    for source_id, source in config["sources"].items():
        if not isinstance(source_id, str) or not IDENTIFIER.fullmatch(source_id):
            raise ValueError("Invalid source id")
        if not isinstance(source, dict):
            raise ValueError("Invalid source")
        kinds = source.get("rules")
        if not isinstance(kinds, list) or not kinds or any(not isinstance(k, str) or k not in ALERTS for k in kinds):
            raise ValueError("rules must contain memory and/or network")
        if len(set(kinds)) != len(kinds):
            raise ValueError("Duplicate rule selection")
        required = {"cadvisor", "rules"} | ({"pipeline"} if "memory" in kinds else set())
        required |= {"network_names"} if "network" in kinds else set()
        if set(source) != required:
            raise ValueError(f"Source requires exactly {sorted(required)}")
        for collector in ("cadvisor", "pipeline"):
            if collector not in source:
                continue
            _scope(source[collector])
            key = (source[collector]["job"], source[collector]["instance"])
            if key in seen[collector]:
                raise ValueError(f"Overlapping {collector} source selectors")
            seen[collector].add(key)
        if "network" in kinds:
            names = source["network_names"]
            if not isinstance(names, list) or not names or any(not isinstance(n, str) or not IDENTIFIER.fullmatch(n) for n in names):
                raise ValueError("network_names must be a non-empty list of exact names")
            if len(set(names)) != len(names):
                raise ValueError("Duplicate network target")
    return config


def selector(labels):
    return "{" + ", ".join(f"{key}={json.dumps(value, ensure_ascii=False)}"
                            for key, value in sorted(labels.items())) + "}"


def source_rules():
    result = {}
    for group in yaml.safe_load(SOURCE.read_text(encoding="utf-8"))["groups"]:
        for rule in group["rules"]:
            if rule.get("alert") in ALERTS.values():
                if rule["alert"] in result:
                    raise ValueError("Duplicate source alert")
                result[rule["alert"]] = rule
    if set(result) != set(ALERTS.values()):
        raise ValueError("Missing source memory/network rule")
    return result


def memory_expression(expression, source):
    names = ("container_memory_working_set_bytes", "container_spec_memory_limit_bytes")
    pattern = r'(?:container_memory_working_set_bytes|container_spec_memory_limit_bytes)\{[^{}]*\}|container_name_info(?:\{[^{}]*\})?'
    matches = list(re.finditer(pattern, expression))
    expected = [name + '{id=~"/docker/.+"}' for name in names] + ["container_name_info"]
    if [m.group() for m in matches] != expected:
        raise ValueError("Review changed memory selector/join contract")
    scope = selector(source["cadvisor"])[1:-1]
    replacements = [name + '{id=~"/docker/.+", ' + scope + "}" for name in names]
    replacements.append("container_name_info" + selector(source["pipeline"]))
    # Retain full-label division, the positive limit filter, all metadata and max(name).
    for match, replacement in reversed(list(zip(matches, replacements))):
        expression = expression[:match.start()] + replacement + expression[match.end():]
    return expression


def network_expression(expression, source):
    matches = list(re.finditer(r"container_network_receive_bytes_total\{[^{}]*\}", expression))
    if len(matches) != 3:
        raise ValueError("Review changed network selectors")
    bodies = [re.sub(r"\s+", "", m.group()) for m in matches]
    if not re.fullmatch(r'container_network_receive_bytes_total\{interface!="lo",id=~"/docker/\.\+",name!="",name=~"[^"\\]+"\}', bodies[0]):
        raise ValueError("Review changed network name contract")
    if bodies[1:] != ['container_network_receive_bytes_total{interface!="lo",id="/"}',
                      'container_network_receive_bytes_total{id=~"/docker/.+"}']:
        raise ValueError("Review changed host fallback contract")
    scope = selector(source["cadvisor"])[1:-1]
    # Dots are literal target-name characters, not regular-expression wildcards.
    names = json.dumps("|".join(name.replace(".", r"\.") for name in source["network_names"]))
    bodies = [f'interface!="lo", id=~"/docker/.+", name!="", name=~{names}',
              'interface!="lo", id="/"', 'id=~"/docker/.+"']
    for match, body in reversed(list(zip(matches, bodies))):
        replacement = "container_network_receive_bytes_total{" + body + ", " + scope + "}"
        expression = expression[:match.start()] + replacement + expression[match.end():]
    return expression


def build_rules(config):
    validate_config(config)
    originals, rules = source_rules(), []
    for source_id, source in config["sources"].items():
        for kind in ("memory", "network"):
            if kind not in source["rules"]:
                continue
            rule = deepcopy(originals[ALERTS[kind]])
            transform = memory_expression if kind == "memory" else network_expression
            rule["expr"] = transform(rule["expr"], source)
            rule["labels"]["rulepack_source"] = source_id
            # Keep original annotations; host-level routing remains an OI-1 gate.
            rules.append(rule)
    return {"groups": [{"name": "m2-3-static-resources", "rules": rules}]}


def render(config):
    return HEADER + yaml.dump(build_rules(config), Dumper=_Dumper, allow_unicode=True, sort_keys=False, width=110)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        text = render(yaml.safe_load(args.config.read_text(encoding="utf-8")))
        if args.check:
            if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != text:
                raise ValueError("M2-3 generated draft differs")
            print("M2-3 draft check: PASS (runtime unverified)")
        else:
            OUTPUT.parent.mkdir(parents=True, exist_ok=True)
            OUTPUT.write_text(text, encoding="utf-8")
            print(f"Rendered static draft: {OUTPUT}; no reload/deployment performed")
    except (OSError, ValueError, yaml.YAMLError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
