"""Incident discovery from Loki `{job="aiops-llm"}` (Track D follow-up, 05 §5·§6). Pure functions, no Airflow.

The realtime Pipeline pushes one RCA envelope (schema 2.x) per analysed alert. Discovery reads those
envelopes **read-only** (GET only, no push), rebuilds an IncidentRequest from the alert fields the
envelope carries, and hands an incident to `dp_bronze_acquire` only after its acquisition window is
closed (window end + `lateness_margin_s`, default 10 min — the same rule Bronze uses for
`window_closed`, so the acquisitions of a discovered incident are reusable).

Load limits (05 §6): each Loki request covers at most 15 min, 30 s timeout, a delay between pages,
a bounded number of windows per run, and the scan stops `ingest_delay_s` before now. The DAG runs the
scan in the `loki_read` pool, so it is serialized with Bronze reads.

State under `<lake>/lake-meta/discover/` (outside data buckets, so `find_orphans` ignores it):
- `state.json`: `scanned_until` cursor and `pending` incidents seen but not yet due.
- `triggered/{incident_id}.json`: write-once marker; an incident is triggered at most once.
An incident whose plan record already exists (e.g. a manual run) is not triggered again either.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from bronze.acquire import SourceError, TIMEOUT_S, _get, endpoints_from_env
from bronze.plan import incident_window
from contracts import canonical
from contracts.canonical import fmt_ts
from storage.store import LocalFsStore

QUERY = '{job="aiops-llm"}'
MAX_WINDOW = timedelta(minutes=15)
REQUEST_DEFAULTS = {"request_schema_version": "1.0", "trigger": "discover", "window_policy": "symmetric_5m",
                    "acquisition_padding_s": 60, "lateness_margin_s": 600, "force_reacquire": False}


def _env_int(name: str, default: int) -> int:
    return int(os.environ.get(name) or default)


def settings_from_env() -> dict:
    return {
        "window_s": min(_env_int("DP_DISCOVER_WINDOW_S", 900), int(MAX_WINDOW.total_seconds())),
        "max_windows": _env_int("DP_DISCOVER_MAX_WINDOWS", 8),
        "lookback_s": _env_int("DP_DISCOVER_LOOKBACK_S", 3600),
        "ingest_delay_s": _env_int("DP_DISCOVER_INGEST_DELAY_S", 60),
        "page_limit": _env_int("DP_DISCOVER_PAGE_LIMIT", 500),
        "max_pages": _env_int("DP_DISCOVER_MAX_PAGES", 20),
        "page_delay_s": float(os.environ.get("DP_DISCOVER_PAGE_DELAY_S") or 1.0),
        "start": os.environ.get("DP_DISCOVER_START") or None,
        "related": json.loads(os.environ.get("DP_DISCOVER_RELATED") or "[]"),
    }


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _ns(at: datetime) -> int:
    return int(at.timestamp()) * 10**9 + at.microsecond * 1000


# ---- envelope -> IncidentRequest ---------------------------------------------------------

def alert_from_envelope(line: str) -> dict | None:
    """Alert part of an RCA envelope (schema 2.x), or None when the line is not an alert result."""
    try:
        env = json.loads(line)
    except ValueError:
        return None
    if not isinstance(env, dict) or not str(env.get("schema_version", "")).startswith("2."):
        return None
    labels, starts_at = env.get("alert_labels"), env.get("alert_starts_at")
    if not isinstance(labels, dict) or not labels.get("alertname") or not isinstance(starts_at, str):
        return None
    alert = {"labels": labels, "annotations": env.get("alert_annotations") or {}, "starts_at": starts_at}
    if env.get("alert_fingerprint"):
        alert["fingerprint"] = env["alert_fingerprint"]
    return alert


def related_scopes(labels: dict, rules: list[dict]) -> list[dict]:
    """`DP_DISCOVER_RELATED` rules: `[{"match": {label: value}, "related_scopes": [...]}]`, first match wins."""
    for rule in rules:
        if all(labels.get(k) == v for k, v in rule.get("match", {}).items()):
            return list(rule.get("related_scopes", []))
    return []


def build_request(alert: dict, rules: list[dict] | None = None, entry_ts: str | None = None) -> dict:
    request = {**REQUEST_DEFAULTS, "alert": alert}
    related = related_scopes(alert["labels"], rules or [])
    request["scope_policy"] = "alert_identity_plus_related" if related else "alert_identity_only"
    if related:
        request["related_scopes"] = related
    anchor, _, _ = incident_window(request)
    request["expected_incident_id"] = canonical.incident_id(canonical.alert_event_id(alert["labels"], anchor))
    if entry_ts:
        request["discovery"] = {"source": f"loki:{QUERY}", "entry_ts": entry_ts}
    return request


def ready_at(request: dict) -> datetime:
    """Acquisition window end + lateness margin: from then on Bronze treats the window as closed."""
    _, _, (_, window_end) = incident_window(request)
    return window_end + timedelta(seconds=int(request.get("lateness_margin_s", 600)))


def run_id_for(incident_id: str) -> str:
    return f"discover__{incident_id}"


# ---- state -------------------------------------------------------------------------------

def _dir(lake: LocalFsStore) -> Path:
    return lake.root / "lake-meta" / "discover"


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True), "utf-8")
    os.replace(tmp, path)


def load_state(lake: LocalFsStore) -> dict:
    path = _dir(lake) / "state.json"
    return json.loads(path.read_text("utf-8")) if path.exists() else {"scanned_until": None, "pending": {}}


def save_state(lake: LocalFsStore, state: dict) -> None:
    _write(_dir(lake) / "state.json", state)


def triggered_path(lake: LocalFsStore, incident_id: str) -> Path:
    return _dir(lake) / "triggered" / f"{incident_id}.json"


def already_handled(lake: LocalFsStore, incident_id: str) -> bool:
    return triggered_path(lake, incident_id).exists() or lake.read_plan(incident_id) is not None


# ---- Loki scan ---------------------------------------------------------------------------

def scan_windows(start: datetime, end: datetime, window: timedelta, max_windows: int) -> list[tuple[datetime, datetime]]:
    """Half-open windows [a, b) of at most `window` from start toward end, oldest first."""
    window = min(window, MAX_WINDOW)
    out, cursor = [], start
    while cursor < end and len(out) < max_windows:
        nxt = min(cursor + window, end)
        out.append((cursor, nxt))
        cursor = nxt
    return out


def query_window(client: httpx.Client, base: str, start: datetime, end: datetime, settings: dict,
                 sleep=time.sleep) -> list[tuple[int, str]]:
    """All `(entry_ts_ns, line)` of the window, forward paging. Raises SourceError on any failed page."""
    url = f"{base}/loki/api/v1/query_range"
    cursor, end_ns, seen, out = _ns(start), _ns(end) - 1, set(), []
    for page in range(settings["max_pages"]):
        if page:
            sleep(settings["page_delay_s"])
        params = {"query": QUERY, "start": str(cursor), "end": str(end_ns), "limit": settings["page_limit"],
                  "direction": "forward"}
        _, data, status = _get(client, url, params)
        if data.get("data", {}).get("resultType") != "streams":
            raise SourceError("invalid_response", status)
        entries = sorted((int(ts), line) for s in data["data"]["result"] for ts, line in s.get("values", []))
        fresh = [e for e in entries if e not in seen]
        seen.update(fresh)
        out.extend(fresh)
        if len(entries) < settings["page_limit"]:
            return out
        # Start is inclusive: re-read the last ns (dropped by `seen`); a full page with nothing new steps past it.
        cursor = entries[-1][0] + (0 if fresh else 1)
    raise SourceError("max_pages")


def discover(lake: LocalFsStore, now: datetime, settings: dict | None = None, transport=None,
             endpoints: dict | None = None, scan_range: tuple[datetime, datetime] | None = None,
             sleep=time.sleep) -> dict:
    """Scan new Loki windows, remember incidents, and return the ones due for Bronze.

    `scan_range` scans an explicit range (backfill) without moving the cursor. A failed window stops
    the scan there; the cursor only advances over windows that were read completely.
    """
    settings = settings or settings_from_env()
    endpoints = endpoints or endpoints_from_env()
    state = load_state(lake)
    horizon = now - timedelta(seconds=settings["ingest_delay_s"])
    if scan_range:
        start, end = scan_range
    else:
        start = parse_ts(state["scanned_until"] or settings["start"] or fmt_ts(now - timedelta(seconds=settings["lookback_s"])))
        end = horizon
    windows = scan_windows(start, min(end, horizon), timedelta(seconds=settings["window_s"]),
                           settings["max_windows"])
    stats = {"windows": 0, "entries": 0, "skipped_lines": 0, "new_incidents": 0, "error": None}
    with httpx.Client(transport=transport, timeout=TIMEOUT_S) as client:
        for i, (a, b) in enumerate(windows):
            if i:
                sleep(settings["page_delay_s"])
            try:
                entries = query_window(client, endpoints["loki"], a, b, settings, sleep)
            except SourceError as err:
                stats["error"] = f"{fmt_ts(a)}: {err.reason}"
                break
            stats["windows"] += 1
            stats["entries"] += len(entries)
            for ts, line in entries:
                alert = alert_from_envelope(line)
                if alert is None:
                    stats["skipped_lines"] += 1
                    continue
                request = build_request(alert, settings["related"], fmt_ts(datetime.fromtimestamp(ts / 1e9, timezone.utc)))
                incident = request["expected_incident_id"]
                if incident in state["pending"] or already_handled(lake, incident):
                    continue
                state["pending"][incident] = {"request": request, "ready_at": fmt_ts(ready_at(request)),
                                              "first_seen": fmt_ts(now)}
                stats["new_incidents"] += 1
            if not scan_range:
                state["scanned_until"] = fmt_ts(b)
    due = []
    for incident, item in sorted(state["pending"].items(), key=lambda kv: kv[1]["ready_at"]):
        if already_handled(lake, incident):
            continue
        if parse_ts(item["ready_at"]) <= now:
            due.append({"trigger_run_id": run_id_for(incident), "conf": item["request"]})
    save_state(lake, state)
    return {"due": due, "pending": len(state["pending"]) - len(due), "stats": stats,
            "scanned_until": state["scanned_until"]}


def mark_triggered(lake: LocalFsStore, due: list[dict], now: datetime, discover_run_id: str | None = None) -> list[str]:
    """Record the triggered incidents (write-once) and drop them from `pending`."""
    state = load_state(lake)
    done = []
    for item in due:
        incident = item["conf"]["expected_incident_id"]
        path = triggered_path(lake, incident)
        if not path.exists():
            _write(path, {"incident_id": incident, "trigger_run_id": item["trigger_run_id"],
                          "triggered_at": fmt_ts(now), "discover_run_id": discover_run_id,
                          "request": item["conf"]})
        state["pending"].pop(incident, None)
        done.append(incident)
    save_state(lake, state)
    return done
