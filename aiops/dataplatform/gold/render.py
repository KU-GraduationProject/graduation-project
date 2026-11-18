"""Prompt-line rendering and Network flow aggregation ported from the Pipeline (05 §3.2).

Ported (not imported) because they are private there: `prompt.log_line` record/summary helpers
(to tell whether masking changed a line) and `prompt.network_section._aggregate/_flow_line`.
`tests/gold/test_parity.py` pins these ports to the Pipeline functions; a Pipeline change that
alters their output breaks that test. `mask_secrets` itself is the public Pipeline function.
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict

from contracts import pipeline_compat

LINE_CHARS = 200
VALUE_CHARS = 300
_SEVERITY_KEYS = ("error_severity", "level")
_MESSAGE_KEYS = ("message",)
_TIME_KEYS = ("timestamp", "@timestamp", "time_iso8601", "time")
_DETAIL_GROUPS = (
    ("state_code", "sql_state_code"), ("status",), ("request_method", "http_method"), ("request_uri", "uri"),
    ("exception_class",), ("exception_message",), ("user", "principal"), ("dbname",),
    ("source_ip", "remote_addr", "remote_host"), ("query_decoded",), ("http_user_agent", "user_agent"),
    ("duration_ms", "request_time"), ("request_id",), ("detail",),
)
_WHITESPACE = re.compile(r"\s+")
_THRESHOLD = "connection_threshold"
MAX_FLOWS = 8


def _record(labels: dict, line: str):
    if "log_format" not in labels:
        return None
    try:
        rec = json.loads(line)
    except ValueError:
        return None
    return rec if isinstance(rec, dict) else None


def _first(rec, keys):
    for key in keys:
        if rec.get(key) not in (None, "", "-"):
            return key, rec[key]
    return None


def _summarize(rec: dict) -> str:
    head = []
    for keys in (_SEVERITY_KEYS, _TIME_KEYS):
        found = _first(rec, keys)
        if found:
            head.append(str(found[1]))
    message = _first(rec, _MESSAGE_KEYS)
    message_text = str(message[1])[:VALUE_CHARS] if message else ""
    if message_text:
        head.append(message_text)
    details = []
    for keys in _DETAIL_GROUPS:
        found = _first(rec, keys)
        if not found:
            continue
        value = str(found[1])[:VALUE_CHARS]
        if message_text and value in message_text:
            continue
        details.append(f"{found[0]}={value}")
    text = " ".join(head)
    if details:
        text += " | " + " ".join(details)
    return text


def render_log_line(labels: dict, line: str, mask: bool = True) -> str:
    """`prompt.log_line.render_log_line` with masking optional (mask=True is the Pipeline output)."""
    masker = pipeline_compat.log_line().mask_secrets if mask else (lambda text: text)
    prefix = labels.get("container") or labels.get("service") or "?"
    rec = _record(labels, line)
    if rec is None:
        return f"[{prefix}] {masker(line)[:LINE_CHARS]}"
    if labels.get("log_format") in ("text", "json_invalid"):
        body = str(rec.get("message", rec.get("log", "")))[:VALUE_CHARS]
    else:
        body = _summarize(rec)
    return f"[{prefix}] {masker(_WHITESPACE.sub(' ', body).strip())[:LINE_CHARS]}"


def render_with_mask_flag(labels: dict, line: str) -> tuple[str, bool]:
    rendered = render_log_line(labels, line)
    return rendered, rendered != render_log_line(labels, line, mask=False)


def aggregate_flows(events) -> list:
    """`network_section._aggregate`: (src, dst, dst_ip, dst_port, proto) flows, final events counted only."""
    flows = defaultdict(lambda: {"conns": 0, "states": Counter(), "apps": Counter(), "sent": [], "recv": [],
                                 "dur": [], "early_ts": [], "early_bytes": [], "src": None, "dst": None,
                                 "dst_ip": None, "dst_port": None, "proto": None, "events": []})
    for e in events:
        src = e.get("src_service") or "unknown"
        dst = e.get("dst_service") or "unknown"
        proto = e.get("protocol") or "other"
        st = flows[(src, dst, e.get("dst_ip"), e.get("dst_port"), proto)]
        st["src"], st["dst"], st["dst_ip"], st["dst_port"], st["proto"] = src, dst, e.get("dst_ip"), e.get("dst_port"), proto
        st["events"].append(e)
        if e.get("event_type") == _THRESHOLD:
            if e.get("timestamp"):
                st["early_ts"].append(e["timestamp"])
            meta = e.get("observer_meta") or {}
            b = meta.get("bytes_threshold")
            if b is None:
                b = e.get("bytes_sent")
            if isinstance(b, (int, float)):
                st["early_bytes"].append(b)
            continue
        st["conns"] += 1
        st["states"][e.get("connection_state") or "unknown"] += 1
        if e.get("app_protocol"):
            st["apps"][e["app_protocol"]] += 1
        for name, bucket in (("bytes_sent", "sent"), ("bytes_received", "recv"), ("duration_ms", "dur")):
            if isinstance(e.get(name), (int, float)):
                st[bucket].append(e[name])

    def order(kv):
        st = kv[1]
        return (-st["conns"], st["src"], st["dst"], str(st["dst_ip"] or ""), str(st["dst_port"] or ""), st["proto"])

    return sorted(flows.items(), key=order)


def flow_line(st: dict, policy) -> str:
    """`network_section._flow_line`."""
    src, dst, proto = st["src"], st["dst"], st["proto"]
    app = "/" + ",".join(a for a, _ in st["apps"].most_common(2)) if st["apps"] else ""
    states = " ".join(f"{s}={n}" for s, n in st["states"].most_common())
    sent = sum(st["sent"]) if st["sent"] else "n/a"
    recv = sum(st["recv"]) if st["recv"] else "n/a"
    dur = f"avg={sum(st['dur']) / len(st['dur']):.0f} max={max(st['dur'])}" if st["dur"] else "n/a"
    base = (f"- {src} -> {dst} {proto}{app}: conns={st['conns']} states[{states}] "
            f"bytes_sent={sent} bytes_recv={recv} duration_ms[{dur}]")
    extras = []
    if st["dst_ip"] and st["dst_port"] is not None:
        extras.append(f"dst={st['dst_ip']}:{st['dst_port']}")
    if policy is not None:
        decision = policy.evaluate({"src_service": src, "dst_service": dst, "dst_ip": st["dst_ip"],
                                    "dst_port": st["dst_port"]})
        if decision.applicable:
            extras.append("allowlist=ok" if decision.authorized else f"allowlist=VIOLATION({decision.reason})")
    if st["early_ts"]:
        earliest = min(st["early_ts"])
        peak = max(st["early_bytes"]) if st["early_bytes"] else None
        tag = f"early={len(st['early_ts'])}@{earliest}"
        if peak is not None:
            tag += f"(>={peak}B)"
        extras.append(tag)
    return base + ("".join(f" | {x}" for x in extras) if extras else "")


def metric_line(name: str, latest, peak, samples: int) -> str:
    """`PromptBuilder.build` METRICS line."""
    try:
        return f"{name}: latest={latest:.4f}, peak={peak:.4f}, samples={samples}"
    except (ValueError, OverflowError, TypeError):
        return f"{name}: latest={latest}, peak={peak}, samples={samples}"
