"""Source-bound scenario-v2 signal rules; no evaluation labels or service IO."""
from __future__ import annotations

import ipaddress
import json
import re

import yaml

FIELDS = ("site", "source", "service", "runtime", "target")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
DEFAULTS = {"external_connections": 3, "internal_endpoints": 6,
            "login_failures": 6, "dependency_errors": 5, "db_rows_per_second": 10000}
DEPENDENCY_PATTERN = r"(?i)(MinioException|io\.minio\.|S3Exception|Unable to execute HTTP request|Connection refused.*(?:minio|9000)|(?:minio|9000).*Connection refused)"


def selector(labels):
    return "{" + ", ".join(k + "=" + json.dumps(v) for k, v in sorted(labels.items())) + "}"


def validate(config, release, allowlist):
    if not isinstance(config, dict) or set(config) != {"version", "thresholds", "network", "postgres_exporter"}:
        raise ValueError("scenario profile requires version/thresholds/network/postgres_exporter")
    if type(config["version"]) is not int or config["version"] != 1:
        raise ValueError("scenario profile version must be 1")
    if not isinstance(config["thresholds"], dict) or set(config["thresholds"]) != set(DEFAULTS):
        raise ValueError("explicit signal thresholds required")
    if any(type(v) is not int or not 1 <= v <= 10**9 for v in config["thresholds"].values()):
        raise ValueError("thresholds must be positive bounded integers")
    net = config["network"]
    if net is not None:
        if (not isinstance(net, dict) or set(net) != {"observer", "observer_instance", "mapping_verified"}
                or net["mapping_verified"] is not True
                or any(not isinstance(net[k], str) or not NAME.fullmatch(net[k]) or "REPLACE" in net[k].upper()
                       for k in ("observer", "observer_instance"))
                or "backend" not in release["gc"]["targets"]):
            raise ValueError("verified backend-to-observer mapping required")
        if (not isinstance(allowlist, dict) or allowlist.get("version") != 1
                or "backend" not in allowlist.get("sources", []) or not isinstance(allowlist.get("allow"), list)):
            raise ValueError("backend allowlist policy required")
        thresholds = allowlist.get("thresholds", {})
        if (type(thresholds.get("min_transfer_bytes")) is not int or thresholds["min_transfer_bytes"] < 1
                or not re.fullmatch(r"[1-9][0-9]*(?:s|m|h)", str(thresholds.get("window", "")))):
            raise ValueError("bounded allowlist transfer threshold/window required")
        for entry in allowlist["allow"]:
            if entry.get("match") == "endpoint":
                ipaddress.ip_address(entry["ip"])
                if type(entry["port"]) is not int or not 1 <= entry["port"] <= 65535:
                    raise ValueError("invalid allowlist endpoint")
            elif entry.get("match") == "service":
                if not NAME.fullmatch(str(entry.get("service", ""))):
                    raise ValueError("invalid allowlist service")
            else:
                raise ValueError("unsupported allowlist match")
    pg = config["postgres_exporter"]
    if pg is not None:
        if (not release["host_postgres"] or not isinstance(pg, dict)
                or set(pg) != {"job", "instance", "database", "metrics_verified"}
                or pg["metrics_verified"] is not True):
            raise ValueError("verified host PostgreSQL exporter required")
        for key in ("job", "database"):
            if not NAME.fullmatch(str(pg[key])) or "REPLACE" in pg[key].upper():
                raise ValueError("invalid PostgreSQL exporter label")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+:[0-9]{1,5}", str(pg["instance"])) or "REPLACE" in pg["instance"].upper():
            raise ValueError("exporter instance must be a verified host:port")
        if not 1 <= int(pg["instance"].rsplit(":", 1)[1]) <= 65535:
            raise ValueError("invalid exporter port")
        if pg["job"] == release["telemetry"]["job"]:
            raise ValueError("PostgreSQL exporter job must be separate from collector")


def rule(name, expr, ident, description, category="security", hold="0m"):
    return {"alert": name, "expr": expr, "for": hold,
            "labels": {**ident, "severity": "warning", "category": category, "rulepack": "scenario-v2"},
            "annotations": {"container": ident["target"], "summary": name, "description": description}}


def json_fields(stream, strings, numbers=()):
    # Validate the entire JSON object and original field types before extracting.
    # Aliases keep attacker-controlled body keys from shadowing trusted labels.
    checks = [f'(eq (printf "%T" (index $o "{k}")) "string")' for k in strings]
    checks += [f'(eq (printf "%T" (index $o "{k}")) "float64")' for k in numbers]
    valid = (' | label_format v2_valid=`{{ $o := fromJson (__line__) }}'
             '{{ if eq (printf "%T" $o) "map[string]interface {}" }}{{ if and '
             + ' '.join(checks) + ' }}true{{end}}{{end}}` | v2_valid="true"')
    extraction = ", ".join(f'v2_{k}="{k}"' for k in (*strings, *numbers))
    return stream + valid + " | json " + extraction + ' | __error__=""'


def network_pipeline(release, config, event_type="connection"):
    name = release["gc"]["targets"]["backend"]["name"]
    p = json_fields(selector({"log_type": "network", "src_service": "backend", "event_type": event_type}),
                    ("observer", "observer_instance", "src_container", "src_service", "event_type", "dst_service", "dst_ip", "connection_id"),
                    ("dst_port",))
    return (p + ' | v2_observer_instance=' + json.dumps(config["network"]["observer_instance"])
            + ' | v2_observer=' + json.dumps(config["network"]["observer"])
            + ' | v2_src_container=' + json.dumps(name)
            + ' | v2_src_service="backend" | v2_event_type=' + json.dumps(event_type)
            + ' | v2_connection_id!="" | v2_dst_ip!="" | v2_dst_port >= 1 | v2_dst_port <= 65535 | __error__=""')


def unauthorized(p, policy):
    for entry in policy["allow"]:
        if entry["match"] == "service":
            p += " | v2_dst_service!=" + json.dumps(entry["service"])
        else:
            p += " | (v2_dst_ip!=" + json.dumps(entry["ip"]) + " or v2_dst_port!=" + str(entry["port"]) + ")"
    return p


def build(release, config, allowlist):
    validate(config, release, allowlist)
    gc = release["gc"]
    t = config["thresholds"]
    logs, prom, excluded = [], [], []
    def ident(service):
        return {"site": gc["site"], "source": gc["source"], "service": service,
                "runtime": "container", "target": gc["targets"][service]["name"]}
    if "frontend" in gc["targets"]:
        i = ident("frontend")
        p = json_fields(selector({**i, "log_format": "json"}), ("status",))
        p += ' | v2_status >= 400 | v2_status < 500 | __error__=""'
        logs.append(rule("V2ReconScan", f"sum(count_over_time({p} [1m])) > 50", i,
                         "4xx surge is a scan symptom; compare normal broken links. Notify only."))
    if "backend" in gc["targets"]:
        i = ident("backend")
        stream = selector(i)
        logs.append(rule("V2LoginBruteForce", f'sum(count_over_time({stream} |= "[AUTH] 로그인 실패" [2m])) >= {t["login_failures"]}', i,
                         "Aggregate authentication failures; no account identity or lock permission."))
        logs.append(rule("V2DependencyErrors", f'sum(count_over_time({stream} |~ {json.dumps(DEPENDENCY_PATTERN)} [2m])) >= {t["dependency_errors"]}', i,
                         "Object-store/SDK connection errors; inspect outage versus deployment/configuration failure.", "infra"))
    if config["network"]:
        p = network_pipeline(release, config)
        # A failed probe may have null orig_bytes; scanning still counts it.
        # Only the small-connection rule requires a nonnegative numeric byte count.
        ext = unauthorized(p, allowlist)
        ext += ' | json v2_bytes_sent="bytes_sent" | v2_bytes_sent!="" | v2_bytes_sent >= 0 | v2_bytes_sent <= 4096 | __error__=""'
        # Distinct connection IDs prevent duplicate delivery of one Zeek event
        # from looking like many probes. Counts are evidence, not ground truth.
        conns = f'sum by (v2_dst_ip, v2_dst_port, v2_connection_id) (count_over_time({ext} [5m]))'
        expr = f'count by (v2_dst_ip, v2_dst_port) ({conns}) >= {t["external_connections"]}'
        logs.append(rule("V2RepeatedExternalConnections", expr, ident("backend"),
                         "Repeated small connections outside allowlist; periodicity/C2 intent require RCA."))
        window = allowlist["thresholds"]["window"]
        minimum = allowlist["thresholds"]["min_transfer_bytes"]
        transfer = unauthorized(p, allowlist)
        transfer += ' | json v2_bytes_sent="bytes_sent" | v2_bytes_sent!="" | v2_bytes_sent >= 0 | __error__="" | unwrap v2_bytes_sent | __error__=""'
        per_connection = f'max by (v2_dst_ip, v2_dst_port, v2_connection_id) (max_over_time({transfer} [{window}]))'
        logs.append(rule("V2UnauthorizedDataTransfer", f'sum by (v2_dst_ip, v2_dst_port) ({per_connection}) > {minimum}', ident("backend"),
                         "Final connection bytes outside shared allowlist; one maximum per connection prevents duplicate delivery inflation."))
        early = unauthorized(network_pipeline(release, config, "connection_threshold"), allowlist)
        early += ' | json v2_threshold="observer_meta.bytes_threshold" | v2_threshold!="" | v2_threshold >= ' + str(minimum) + ' | __error__=""'
        logs.append(rule("V2UnauthorizedTransferEarly", f'count(count_over_time({early} [{window}])) > 0', ident("backend"),
                         "Observer byte-threshold event for unauthorized destination; verify observer threshold matches the shared policy."))
        # RFC1918 IPv4 only. Count endpoint diversity, not ordinary requests to
        # one DB port. Scan monitoring deliberately does NOT exclude allowed peers.
        private = r"^(10\..*|192\.168\..*|172\.(1[6-9]|2[0-9]|3[01])\..*)$"
        scan = p + ' | v2_dst_ip=~' + json.dumps(private)
        endpoints = f'sum by (v2_dst_ip, v2_dst_port) (count_over_time({scan} [2m]))'
        logs.append(rule("V2InternalPortScan", f'count({endpoints}) >= {t["internal_endpoints"]}', ident("backend"),
                         "Distinct internal IP/port fan-out; verify authorized maintenance before isolation."))
    else:
        excluded.append("Network signals: verified observer mapping missing")
    if config["postgres_exporter"]:
        pg = release["host_postgres"]
        i = {k: pg[k] for k in ("site", "source", "target")}
        i.update(service="db", runtime="host")
        labels = {**i, **{k: config["postgres_exporter"][k] for k in ("job", "instance")},
                  "datname": config["postgres_exporter"]["database"]}
        expr = f'sum(rate(pg_stat_database_tup_returned{selector(labels)}[2m])) > {t["db_rows_per_second"]}'
        prom.append(rule("V2DBReadSurge", expr, i,
                         "Database rows visited per second, not rows exfiltrated. Backup can also match; notify only.", hold="30s"))
    else:
        excluded.append("DB read surge: verified pg_stat_database_tup_returned exporter missing")
    return logs, prom, excluded
