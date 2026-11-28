"""Loki/Prometheus HTTP answers rebuilt from the fixture Bronze rows (10/11/12).

Responses are serialized like the fixture raw pages (compact JSON, source key order), so the
raw page sha256 recorded in `10_bronze_acquisition.jsonl` is reproduced byte for byte. The
fixture stored labels sorted; the two raw pages whose producer used another label order are
listed in `LABEL_ORDER` (recovered from their recorded `raw_sha256`).

Series preflight: streams that returned rows exist inside the window. An acquisition whose
preflight was `present` but returned nothing exists only outside the window (lookback), and
one recorded `absent` does not exist at all — the same three cases 04 §2 distinguishes.

Discovery (`dp_incident_discover`) queries the bare selector `{job="aiops-llm"}`, which no fixture
acquisition used. A query that is not a recorded acquisition query but selects `job="aiops-llm"` is
answered by label match over every fixture entry plus entries added with `add_loki_entry` (tests).

Remediation streams (`job="aiops-remediation"`/`"aiops-timeline"`, #77) are served from the hand-written input
`03_remediation_events.jsonl` by label match (`=` and `=~` matchers). Loki only holds what was pushed before the
query: with `now_ns` set, entries after it are not returned (fixture history replays an acquisition at its time).
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from urllib.parse import parse_qs

DEFAULT_FIXTURE = Path(__file__).resolve().parents[3] / "docs/data-platform/examples/db-connection-limit"

LABEL_ORDER = {
    "rca_result": ["job", "target_container", "alert", "site", "service", "runtime", "source", "target",
                   "threat_level"],
    "cpu_usage": ["job", "instance", "id", "site", "source", "service", "runtime", "target", "cpu"],
}
_LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*("(?:[^"\\]|\\.)*")')
_MATCHER = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*(=~|=)\s*("(?:[^"\\]|\\.)*")')
REMEDIATION_FILE = "03_remediation_events.jsonl"
REMEDIATION_JOBS = ("aiops-remediation", "aiops-timeline")


def dumps(value) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def parse_selector(selector: str) -> dict:
    """`{a="x", b="y"} | json …` -> {"a": "x", "b": "y"} (exact matchers of the stream selector only)."""
    head = selector.split("}", 1)[0].lstrip("{")
    return {k: json.loads(v) for k, v in _LABEL.findall(head)}


def _matches_selector(labels: dict, selector: str) -> bool:
    """Exact (`=`) and regex (`=~`, fully anchored as in Loki) matchers of the stream selector."""
    head = selector.split("}", 1)[0].lstrip("{")
    for key, op, raw in _MATCHER.findall(head):
        value, actual = json.loads(raw), labels.get(key)
        if actual is None or (actual != value if op == "=" else re.fullmatch(value, actual) is None):
            return False
    return True


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text("utf-8").splitlines() if line.strip()]


def _ordered(labels: dict, order: list[str] | None) -> dict:
    if not order or set(order) != set(labels):
        return labels
    return {k: labels[k] for k in order}


class FixtureSources:
    def __init__(self, fixture_dir: str | Path | None = None):
        root = Path(fixture_dir or os.environ.get("DP_FIXTURE_DIR", DEFAULT_FIXTURE))
        acquisitions = _jsonl(root / "10_bronze_acquisition.jsonl")
        entries = _jsonl(root / "11_bronze_loki_entry.jsonl")
        samples = _jsonl(root / "12_bronze_prometheus_sample.jsonl")
        by_acq = {a["acquisition_id"]: a for a in acquisitions}
        self.loki: dict[str, list[tuple[int, dict, str, str]]] = {}
        self.loki_order: dict[str, list[str] | None] = {}
        seen = set()
        for row in entries:
            acq = by_acq[row["acquisition_id"]]
            if (acq["query_text"], row["record_key"]) in seen:
                continue  # re-acquisitions of the same query return the same entries
            seen.add((acq["query_text"], row["record_key"]))
            self.loki.setdefault(acq["query_text"], []).append(
                (row["entry_ts_ns"], json.loads(row["stream_labels"]), row["line"], row["record_key"]))
            self.loki_order[acq["query_text"]] = LABEL_ORDER.get(acq["stream_class"])
        for rows in self.loki.values():
            rows.sort(key=lambda r: r[0])
        self.prom: dict[str, list[tuple[dict, int, str]]] = {}
        self.prom_order: dict[str, list[str] | None] = {}
        for row in samples:
            acq = by_acq[row["acquisition_id"]]
            if any(s[1] == row["sample_ts_ms"] and s[0] == json.loads(row["series_labels"])
                   for s in self.prom.get(acq["query_text"], [])):
                continue
            self.prom.setdefault(acq["query_text"], []).append(
                (json.loads(row["series_labels"]), row["sample_ts_ms"], row["value_raw"]))
            self.prom_order[acq["query_text"]] = LABEL_ORDER.get(row["query_name"])
        # Streams that exist only before the window (preflight present, no rows).
        self.lookback_only = [parse_selector(a["query_text"]) for a in acquisitions
                              if a["source_system"] == "loki" and a["series_preflight"] == "present"
                              and a["row_count"] == 0 and a["query_text"]]
        self.lookback_start = {json.dumps(parse_selector(a["query_text"]), sort_keys=True): a["window_start"]
                               for a in acquisitions if a["source_system"] == "loki" and a["query_text"]}
        self.calls: list[tuple[str, dict]] = []
        self.extra_loki: list[tuple[int, dict, str, str]] = []
        self.remediation: list[tuple[int, dict, str, str]] = []
        if (root / REMEDIATION_FILE).exists():
            for i, row in enumerate(_jsonl(root / REMEDIATION_FILE)):
                # the line exactly as remediation/main.py `_push_soc_event` writes it (json.dumps defaults)
                line = json.dumps(row["body"], ensure_ascii=False)
                self.remediation.append((row["ts_ns"], row["labels"], line, f"remediation:{i}"))
        self.now_ns: int | None = None

    def add_loki_entry(self, ts_ns: int, labels: dict, line: str) -> None:
        """Extra Loki entry answered only to label-matched `job="aiops-llm"` queries (discovery tests)."""
        self.extra_loki.append((ts_ns, labels, line, f"extra:{len(self.extra_loki)}"))

    def _remediation_rows(self, selector: str) -> list[tuple[int, dict, str, str]]:
        return [r for r in self.remediation if (self.now_ns is None or r[0] <= self.now_ns)
                and _matches_selector(r[1], selector)]

    def _loki_rows(self, query: str) -> list[tuple[int, dict, str, str]]:
        if parse_selector(query).get("job") in REMEDIATION_JOBS:
            return self._remediation_rows(query)
        if query in self.loki:
            return self.loki[query]
        wanted = parse_selector(query)
        if wanted.get("job") != "aiops-llm":
            return []
        found = {r[3]: r for rows in self.loki.values() for r in rows}
        found.update({r[3]: r for r in self.extra_loki})
        return sorted((r for r in found.values() if all(r[1].get(k) == v for k, v in wanted.items())),
                      key=lambda r: (r[0], r[3]))

    # ---- request dispatch -------------------------------------------------------------
    def handle(self, path: str, query: str | dict) -> tuple[int, bytes]:
        params = parse_qs(query, keep_blank_values=True) if isinstance(query, str) else query
        one = {k: (v[0] if isinstance(v, list) else v) for k, v in params.items()}
        self.calls.append((path, one))
        if path == "/loki/api/v1/query_range":
            return 200, self.loki_query_range(one)
        if path == "/loki/api/v1/series":
            return 200, self.loki_series(one)
        if path == "/api/v1/query_range":
            return 200, self.prom_query_range(one)
        if path == "/api/v1/series":
            return 200, self.prom_series(one)
        if path in ("/ready", "/-/ready", "/healthz"):
            return 200, b"ready"
        return 404, dumps({"status": "error", "error": f"unknown path {path}"})

    def loki_query_range(self, p: dict) -> bytes:
        start, end, limit = int(p["start"]), int(p["end"]), int(p.get("limit", 100))
        rows = [r for r in self._loki_rows(p["query"]) if start <= r[0] <= end][:limit]
        order = self.loki_order.get(p["query"])
        streams: dict[str, dict] = {}
        for ts, labels, line, _ in rows:
            key = json.dumps(labels, sort_keys=True)
            stream = streams.setdefault(key, {"stream": _ordered(labels, order), "values": []})
            stream["values"].append([str(ts), line])
        return dumps({"status": "success", "data": {"resultType": "streams", "result": list(streams.values()),
                                                    "stats": {"summary": {"totalEntriesReturned": len(rows)}}}})

    def loki_series(self, p: dict) -> bytes:
        wanted = parse_selector(p["match[]"])
        start, end = int(p["start"]), int(p["end"])
        found = {}
        if wanted.get("job") in REMEDIATION_JOBS:
            for ts, labels, _, _ in self._remediation_rows(p["match[]"]):
                if start <= ts <= end:
                    found[json.dumps(labels, sort_keys=True)] = labels
            return dumps({"status": "success", "data": list(found.values())})
        for rows in self.loki.values():
            for ts, labels, _, _ in rows:
                if start <= ts <= end and all(labels.get(k) == v for k, v in wanted.items()):
                    found[json.dumps(labels, sort_keys=True)] = labels
        if not found:
            for labels in self.lookback_only:
                if labels == wanted and start < self._window_start_ns(wanted):
                    found[json.dumps(labels, sort_keys=True)] = labels
        return dumps({"status": "success", "data": list(found.values())})

    def _window_start_ns(self, labels: dict) -> int:
        from datetime import datetime
        ts = self.lookback_start[json.dumps(labels, sort_keys=True)]
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return int(dt.timestamp()) * 10**9 + dt.microsecond * 1000

    def prom_query_range(self, p: dict) -> bytes:
        from decimal import Decimal
        start_ms, end_ms = int(Decimal(p["start"]) * 1000), int(Decimal(p["end"]) * 1000)
        order = self.prom_order.get(p["query"])
        series: dict[str, dict] = {}
        for labels, ts_ms, value in self.prom.get(p["query"], []):
            if start_ms <= ts_ms <= end_ms:
                key = json.dumps(labels, sort_keys=True)
                entry = series.setdefault(key, {"metric": _ordered(labels, order), "values": []})
                entry["values"].append([ts_ms / 1000, value])
        return dumps({"status": "success", "data": {"resultType": "matrix", "result": list(series.values())}})

    def prom_series(self, p: dict) -> bytes:
        wanted = parse_selector(p["match[]"])
        found = {}
        for rows in self.prom.values():
            for labels, _, _ in rows:
                if all(labels.get(k) == v for k, v in wanted.items()):
                    found[json.dumps(labels, sort_keys=True)] = labels
        return dumps({"status": "success", "data": list(found.values())})


def mock_transport(sources: FixtureSources, fault=None):
    """`httpx.MockTransport` over the fixture. `fault(request, call_no)` may raise or return a Response."""
    import httpx

    counter = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        counter["n"] += 1
        if fault is not None:
            injected = fault(request, counter["n"])
            if injected is not None:
                return injected
        status, body = sources.handle(request.url.path, request.url.query.decode("utf-8"))
        return httpx.Response(status, content=body, headers={"content-type": "application/json"})

    return httpx.MockTransport(handler)
