"""Generate M3 LogQL drafts outside deployed rule mounts; never contact services.

LoginBruteForce and DB utilization are deferred until their producer contracts exist.
Requires PyYAML. Run with --check for a read-only reproducibility check.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

import yaml

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = ROOT / "docs/rulepack/m3/targets.yml"
OUTPUT = ROOT / "docs/rulepack/m3/generated/loki.rules.yml"
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
LOG_LABELS = {"service", "runtime", "container_name", "source"}
# Research defaults: a matching request is a warning; an actual server refusal is
# an availability symptom. Neither count is derived from injected traffic.
WINDOW = "2m"
THRESHOLD = 0  # strictly > 0, i.e. at least one matching event in WINDOW
SQL_GAP = r"(?:\s|/\*[^*]*\*/)+"
SQL_PATTERN = (
    r"(?is).*(?:\bunion" + SQL_GAP + r"(?:all" + SQL_GAP + r")?select\b"
    r"|\b(?:or|and)\s+(?:1\s*=\s*1\b|'1'\s*=\s*'1'|\"1\"\s*=\s*\"1\")"
    r"|\b(?:pg_sleep|sleep|extractvalue|updatexml)\s*\("
    r"|\binformation_schema\b|;\s*(?:drop|alter|truncate)\s+table\b).*"
)
# 53300 also covers role/database connection caps. Only these instance-wide
# server messages qualify; SQLSTATE alone must not mean max_connections exhaustion.
DB_PATTERN = r"(?i)^(sorry, too many clients already|remaining connection slots are reserved for .+)$"


class _Dumper(yaml.SafeDumper):
    pass


def _string(dumper, value):
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|" if "\n" in value else None)


_Dumper.add_representer(str, _string)


def validate_config(config: object) -> dict:
    if not isinstance(config, dict) or set(config) != {"version", "web_targets", "postgres_targets"}:
        raise ValueError("Expected version, web_targets and postgres_targets")
    if type(config["version"]) is not int or config["version"] != 1:
        raise ValueError("Only version 1 is supported")
    ids, aliases = set(), set()
    for kind in ("web_targets", "postgres_targets"):
        targets = config[kind]
        if not isinstance(targets, list):
            raise ValueError(f"{kind} must be a list (empty explicitly disables that kind)")
        for target in targets:
            if not isinstance(target, dict) or set(target) != {"id", "alert_target", "log_selector"}:
                raise ValueError("Target requires id, alert_target, log_selector")
            for key in ("id", "alert_target"):
                if not isinstance(target[key], str) or not IDENTIFIER.fullmatch(target[key]):
                    raise ValueError(f"Invalid {key}")
            if target["id"] in ids or target["alert_target"] in aliases:
                raise ValueError("Target id and alert_target must be unique")
            ids.add(target["id"])
            aliases.add(target["alert_target"])
            labels = target["log_selector"]
            if not isinstance(labels, dict) or set(labels) - LOG_LABELS or not {"service", "runtime"} <= set(labels):
                raise ValueError("Selector requires service/runtime and only supported log labels")
            for value in labels.values():
                if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value):
                    raise ValueError("Selector values must be nonempty single-line strings")
            if labels["service"] == "unknown" or not IDENTIFIER.fullmatch(labels["service"]):
                raise ValueError("Known canonical service required")
            expected = "container" if kind == "web_targets" else "host"
            if labels["runtime"] != expected:
                raise ValueError(f"{kind} supports runtime={expected} only")
            if "container_name" in labels and labels["runtime"] != "container":
                raise ValueError("Host PostgreSQL has no container_name contract")
            if "source" in labels and (labels["runtime"] != "container" or labels["source"] not in {"stdout", "stderr"}):
                raise ValueError("source is a Docker stdout/stderr label")
        for index, left in enumerate(targets):
            for right in targets[index + 1:]:
                a, b = left["log_selector"], right["log_selector"]
                if all(a[key] == b[key] for key in a.keys() & b.keys()):
                    raise ValueError("Overlapping log selectors")
    if not ids:
        raise ValueError("At least one supported target required")
    return config


def selector(labels: dict) -> str:
    return "{" + ", ".join(f"{key}={json.dumps(value, ensure_ascii=False)}" for key, value in sorted(labels.items())) + "}"


def pipeline(kind: str, target: dict) -> str:
    stream = selector({**target["log_selector"], "log_format": "json"})
    # Parameterized Loki JSON extraction can stop before noticing a truncated
    # suffix, and converts object/array fields to strings. Validate the full
    # object and original string types before extraction. These are Go template
    # builtins plus Loki fromJson, not labels supplied by a collector.
    fields = ("request_uri",) if kind == "SQLInjection" else ("error_severity", "state_code", "message")
    checks = " ".join(f'(eq (printf "%T" (index $o "{field}")) "string")' for field in fields)
    valid_json = (
        '\n  | label_format m3_json_ok=`{{ $o := fromJson (__line__) }}'
        '{{ if eq (printf "%T" $o) "map[string]interface {}" }}{{ if and ' + checks
        + ' }}true{{end}}{{end}}`\n  | m3_json_ok="true"'
    )
    if kind == "SQLInjection":
        return (
            stream + valid_json + '\n  | json m3_uri="request_uri"\n  | __error__="" | m3_uri!=""'
            '\n  | label_format m3_decoded=`{{ .m3_uri | urldecode }}`'
            '\n  | __error__=""\n  | m3_decoded=~' + json.dumps(SQL_PATTERN)
            + '\n  | drop m3_json_ok, m3_uri, m3_decoded'
        )
    if kind == "DBConnectionLimit":
        return (
            stream + valid_json + '\n  | json m3_severity="error_severity", m3_code="state_code", m3_message="message"'
            '\n  | __error__=""\n  | m3_severity="FATAL" | m3_code="53300"'
            '\n  | m3_message=~' + json.dumps(DB_PATTERN)
            + '\n  | drop m3_json_ok, m3_severity, m3_code, m3_message'
        )
    raise ValueError(f"Unsupported/deferred rule: {kind}")


def rule(kind: str, target: dict) -> dict:
    sql = kind == "SQLInjection"
    return {
        "alert": kind,
        "expr": f"sum(count_over_time(\n  {pipeline(kind, target)}\n  [{WINDOW}]\n)) > {THRESHOLD}",
        "for": "0m",
        "labels": {"severity": "warning" if sql else "critical", "category": "security" if sql else "infra",
                   "rulepack_target": target["id"]},
        "annotations": {
            "summary": "Nginx 요청 URI의 SQL Injection 의심 패턴" if sql else "PostgreSQL 서버 연결 슬롯 부족으로 접속 거부",
            "description": (
                "2분 내 1회 이상 URI 패턴 일치. SQL 실행·침해 성공의 증거는 아니다."
                if sql else "2분 내 1회 이상 FATAL/53300 서버 슬롯 거부. Hikari 풀 고갈·전체 연결 사용률은 판정하지 않는다."
            ),
            "container": target["alert_target"],
        },
    }


def render(config: dict) -> str:
    validate_config(config)
    rules = [rule(kind, target) for key, kind in (("web_targets", "SQLInjection"), ("postgres_targets", "DBConnectionLimit"))
             for target in config[key]]
    return "# Generated M3 static draft; not mounted by Compose. Do not edit.\n" + yaml.dump(
        {"groups": [{"name": "m3-new-detection-static", "interval": "5s", "rules": rules}]},
        Dumper=_Dumper, allow_unicode=True, sort_keys=False, width=110,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        rendered = render(yaml.safe_load(args.config.read_text(encoding="utf-8")))
        if args.check:
            if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != rendered:
                raise ValueError("Generated M3 draft differs")
            print("M3 draft check: PASS; runtime acceptance pending")
        else:
            OUTPUT.parent.mkdir(parents=True, exist_ok=True)
            OUTPUT.write_text(rendered, encoding="utf-8")
            print(f"Rendered {OUTPUT}; nothing loaded or deployed")
    except (ValueError, OSError, yaml.YAMLError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
