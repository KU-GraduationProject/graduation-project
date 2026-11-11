"""Render four existing rules for explicit targets, without loading or deploying them.

Run from the repository root:
    python tools/rulepack/generate_m2.py
    python tools/rulepack/generate_m2.py --check

Requires PyYAML. Thresholds, windows and alert timing come from the existing rules.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import re

import yaml

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = ROOT / "docs/rulepack/m2/targets.yml"
DEFAULT_OUTPUT = ROOT / "docs/rulepack/m2/generated"
SOURCE_FILES = {
    "loki": ROOT / "monitoring/loki/rules/fake/security-rules.yml",
    "prometheus": ROOT / "monitoring/prometheus/rules/alert.rules.yml",
}
WEB_LOG_RULES = ("HighNginxErrorRate", "VulnerabilityScanningDetected")
DB_LOG_RULE = "UnauthorizedDBAccess"
WEB_METRIC_RULE = "HighNginxRequestRate"
LOG_LABELS = {"service", "runtime", "container_name", "source"}
METRIC_LABELS = {"job", "instance", "site"}
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
HEADER = "# Generated M2 static draft; not mounted by Compose. Do not edit.\n"


class _Dumper(yaml.SafeDumper):
    pass


def _string(dumper, value):
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|" if "\n" in value else None)


_Dumper.add_representer(str, _string)


def _selectors(value: object, allowed: set[str], required: str) -> dict:
    if not isinstance(value, dict) or not value or set(value) - allowed:
        raise ValueError(f"Invalid selector; allowed labels: {sorted(allowed)}")
    if required not in value:
        raise ValueError(f"Selector requires {required}")
    for label, text in value.items():
        if not isinstance(text, str) or not text.strip() or any(ord(c) < 32 for c in text):
            raise ValueError(f"Selector {label} must be a non-empty single-line string")
    if required == "service" and (
        value[required] == "unknown" or not IDENTIFIER.fullmatch(value[required])
    ):
        raise ValueError("A known canonical service is required")
    if "runtime" in value and value["runtime"] not in {"container", "host"}:
        raise ValueError("Runtime must be container or host")
    if "container_name" in value and value.get("runtime") != "container":
        raise ValueError("container_name requires runtime=container")
    if "source" in value and value["source"] not in {"stdout", "stderr"}:
        raise ValueError("Source must be stdout or stderr")
    return value


def validate_config(config: object) -> dict:
    if not isinstance(config, dict) or set(config) != {"version", "web_targets", "postgres_targets"}:
        raise ValueError("Expected version, web_targets and postgres_targets")
    if type(config["version"]) is not int or config["version"] != 1:
        raise ValueError("Only version 1 is supported")
    ids, destinations = set(), set()
    for kind in ("web_targets", "postgres_targets"):
        targets = config[kind]
        if not isinstance(targets, list) or not targets:
            raise ValueError(f"{kind} must be a non-empty list")
        keys = {"id", "alert_target", "log_selector"}
        if kind == "web_targets":
            keys.add("metric_selector")
        for target in targets:
            if not isinstance(target, dict) or set(target) != keys:
                raise ValueError(f"{kind} requires exactly {sorted(keys)}")
            for key in ("id", "alert_target"):
                if not isinstance(target[key], str) or not IDENTIFIER.fullmatch(target[key]):
                    raise ValueError(f"Invalid {key}")
            if target["id"] in ids or target["alert_target"] in destinations:
                raise ValueError("Target id and alert_target must each be unique")
            ids.add(target["id"])
            destinations.add(target["alert_target"])
            _selectors(target["log_selector"], LOG_LABELS, "service")
            if kind == "web_targets":
                _selectors(target["metric_selector"], METRIC_LABELS, "job")
        # Equality selectors overlap unless a shared label has conflicting values.
        # Reject ambiguity before two rules can attribute one source to two targets.
        for index, left in enumerate(targets):
            for right in targets[index + 1:]:
                for field in ("log_selector", "metric_selector"):
                    if field not in left:
                        continue
                    a, b = left[field], right[field]
                    if all(a[key] == b[key] for key in a.keys() & b.keys()):
                        raise ValueError(f"Overlapping {field}: {left['id']} / {right['id']}")
    return config


def selector(labels: dict) -> str:
    return "{" + ", ".join(
        f"{name}={json.dumps(value, ensure_ascii=False)}" for name, value in sorted(labels.items())
    ) + "}"


def _source_rules(path: Path, names: tuple[str, ...]) -> dict:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    rules = {}
    for group in document["groups"]:
        for rule in group["rules"]:
            if rule.get("alert") in names:
                if rule["alert"] in rules:
                    raise ValueError(f"Duplicate source rule: {rule['alert']}")
                rules[rule["alert"]] = rule
    if set(rules) != set(names):
        raise ValueError(f"Missing source rules in {path}")
    return rules


def _target_rule(source: dict, target: dict, metric: bool = False) -> dict:
    rule = deepcopy(source)
    if metric:
        token = "nginx_http_requests_total["
        if rule["expr"].count(token) != 1 or "{" in rule["expr"]:
            raise ValueError("Review changed source metric selector before rendering")
        rule["expr"] = rule["expr"].replace(
            token, "nginx_http_requests_total" + selector(target["metric_selector"]) + "[", 1
        )
    else:
        matches = list(re.finditer(r"\{[^{}]*\}", rule["expr"]))
        if len(matches) != 1:
            raise ValueError("Expected one source LogQL stream selector")
        labels = dict(target["log_selector"])
        if rule["alert"] in WEB_LOG_RULES:
            labels["log_format"] = "json"
            # Keep parser and numeric-conversion errors out of metric aggregation.
            expression, count = re.subn(
                r"(\| status [^\[]+?)(\s*\[)",
                r'\1 | __error__=""\2', rule["expr"], count=1,
            )
            if count != 1:
                raise ValueError("Review changed source status filter before rendering")
            rule["expr"] = expression
        start, end = matches[0].span()
        rule["expr"] = rule["expr"][:start] + selector(labels) + rule["expr"][end:]
    rule["labels"]["rulepack_target"] = target["id"]
    rule["annotations"]["container"] = target["alert_target"]
    return rule


def render(config: dict) -> dict[str, str]:
    validate_config(config)
    logs = _source_rules(SOURCE_FILES["loki"], (*WEB_LOG_RULES, DB_LOG_RULE))
    metrics = _source_rules(SOURCE_FILES["prometheus"], (WEB_METRIC_RULE,))
    log_rules, metric_rules = [], []
    for target in config["web_targets"]:
        log_rules.extend(_target_rule(logs[name], target) for name in WEB_LOG_RULES)
        metric_rules.append(_target_rule(metrics[WEB_METRIC_RULE], target, metric=True))
    log_rules.extend(_target_rule(logs[DB_LOG_RULE], target) for target in config["postgres_targets"])
    return {
        f"{engine}.rules.yml": HEADER + yaml.dump(
            {"groups": [{"name": "m2-static-" + engine, "rules": rules}]},
            Dumper=_Dumper, allow_unicode=True, sort_keys=False, width=110,
        )
        for engine, rules in (("loki", log_rules), ("prometheus", metric_rules))
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true", help="Check draft drift without writing")
    args = parser.parse_args()
    try:
        rendered = render(yaml.safe_load(args.config.read_text(encoding="utf-8")))
        if args.check:
            for name, text in rendered.items():
                path = args.output_dir / name
                if not path.is_file() or path.read_text(encoding="utf-8") != text:
                    raise ValueError(f"Generated draft differs: {path}")
            print("M2 draft check: PASS (runtime unverified)")
        else:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            for name, text in rendered.items():
                (args.output_dir / name).write_text(text, encoding="utf-8")
            print(f"Rendered static drafts in {args.output_dir}; nothing loaded or deployed")
    except (ValueError, OSError, yaml.YAMLError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
