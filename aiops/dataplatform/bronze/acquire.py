"""`acquire`: one plan item -> raw pages + Bronze rows + acquisition row -> committed manifest.

Bronze keeps what the source returned, uninterpreted (01 §2). Every executed query leaves an
acquisition row, failures included (DQ-B01). Pages already received are kept when a later page
fails (`partial`). Loki pages move forward by the last entry ns (inclusive) and boundary
duplicates are dropped by `record_key`; a full page that is all one ns stops as
`truncated`/`same_ts_overflow` because the cursor cannot advance without skipping entries.
"""
from __future__ import annotations

import json
import os
import re
import time
from datetime import timedelta
from pathlib import Path

import httpx

from contracts import canonical, enums, pipeline_compat
from contracts.canonical import canonical_str, fmt_ts, h, parse_ts, sha256_text
from contracts.runtime import RunContext
from storage import lineage_writer, paths
from storage.manifest import commit_build, output_rows, ref
from storage.store import LocalFsStore

TIMEOUT_S = 30
LOOKBACK = timedelta(hours=24)


def endpoints_from_env() -> dict:
    return {"loki": os.environ.get("DP_LOKI_URL", "http://loki:3100"),
            "prometheus": os.environ.get("DP_PROMETHEUS_URL", "http://prometheus:9090")}


class SourceError(Exception):
    def __init__(self, reason: str, http_status: int | None = None):
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status


def _get(client: httpx.Client, url: str, params) -> tuple[bytes, dict, int]:
    try:
        resp = client.get(url, params=params)
    except httpx.TimeoutException as exc:
        raise SourceError("timeout") from exc
    except httpx.TransportError as exc:
        raise SourceError("connection_error") from exc
    if resp.status_code in (401, 403):
        raise SourceError("auth_error", resp.status_code)
    if resp.status_code >= 400:
        raise SourceError("api_error", resp.status_code)
    try:
        data = resp.json()
    except ValueError as exc:
        raise SourceError("invalid_response", resp.status_code) from exc
    if not isinstance(data, dict) or data.get("status") != "success":
        raise SourceError("api_error" if isinstance(data, dict) else "invalid_response", resp.status_code)
    return resp.content, data, resp.status_code


def _warnings(data: dict) -> list[str]:
    return [str(w) for key in ("warnings", "infos") for w in (data.get(key) or [])]


def _matches(actual: dict, expected: dict) -> bool:
    return pipeline_compat.identity().matches(actual, expected)


def _forbidden_stream(labels: dict) -> bool:
    text = canonical_str(labels)
    return any(token in text for token in ("network-experiment", "heldout", "Heldout"))


def find_reusable(store: LocalFsStore, acquisition_key: str) -> dict | None:
    """Incident mode skips a key already acquired `ok` from a closed window (02 §5)."""
    for manifest in reversed(store.manifests("bronze")):
        if manifest["build_status"] != "ok":
            continue
        row = output_rows(store, manifest, "bronze.acquisition")[0]
        if row["acquisition_key"] == acquisition_key and row["window_closed"]:
            return manifest
    return None


def acquire(item: dict, store: LocalFsStore, run: RunContext, transport: httpx.BaseTransport | None = None,
            endpoints: dict | None = None, sleep=time.sleep, page_delay_s: float | None = None,
            run_log_path: str | None = None) -> dict:
    if any(token in (item.get("query_text") or "") for token in enums.FORBIDDEN_SELECTOR_TOKENS):
        raise ValueError(f"forbidden stream in selector (DQ-B06): {item['query_text']}")
    if not item["force_reacquire"] and item["unavailable_reason"] is None:
        reusable = find_reusable(store, item["acquisition_key"])
        if reusable:
            return {**ref(reusable), "status": "reused"}

    endpoints = endpoints or endpoints_from_env()
    delay = float(os.environ.get("DP_PAGE_DELAY_S", "0.2")) if page_delay_s is None else page_delay_s
    requested_at = run.now()
    acquisition_id = run.new_build_id("acq", requested_at)
    result = {"page_count": 0, "response_bytes": 0, "http_status_last": None, "status": None,
              "status_reason": None, "limit_hit": False, "series_preflight": "not_run", "warnings": [],
              "raw_pages": [], "raw_sha256": [], "rows": []}

    if item["unavailable_reason"] is not None:
        result.update(status="scope_unavailable", status_reason=item["unavailable_reason"])
        completed_at = requested_at
    elif item["source_system"] == "scenario_run_log":
        _acquire_run_log(run_log_path or os.environ.get("DP_SCENARIO_RUN_LOG"), acquisition_id, store, result)
        completed_at = run.now()
    else:
        with httpx.Client(transport=transport, timeout=TIMEOUT_S) as client:
            if item["source_system"] == "loki":
                _acquire_loki(item, client, endpoints["loki"], acquisition_id, store, result, sleep, delay)
            else:
                _acquire_prometheus(item, client, endpoints["prometheus"], acquisition_id, store, result)
        completed_at = run.now()

    window_end = parse_ts(item["window_end"])
    acquisition = {
        "acquisition_id": acquisition_id, "acquisition_key": item["acquisition_key"], "plan_id": item["plan_id"],
        "incident_id": item["incident_id"], "scope_role": item["scope_role"],
        "source_system": item["source_system"], "api": item["api"], "stream_class": item["stream_class"],
        "query_name": item["query_name"], "query_text": item["query_text"],
        "query_params": canonical_str(item["query_params"]), "window_start": item["window_start"],
        "window_end": item["window_end"], "scope_identity": canonical_str(item["scope_identity"]),
        "scope_selector": canonical_str(item["scope_selector"]), "binding_sha256": item["binding_sha256"],
        "requested_at": fmt_ts(requested_at), "completed_at": fmt_ts(completed_at),
        "page_count": result["page_count"], "row_count": len(result["rows"]),
        "response_bytes": result["response_bytes"], "http_status_last": result["http_status_last"],
        "status": result["status"], "status_reason": result["status_reason"], "limit_hit": result["limit_hit"],
        "series_preflight": result["series_preflight"], "warnings": result["warnings"],
        "raw_pages": result["raw_pages"], "raw_sha256": result["raw_sha256"],
        "window_closed": requested_at >= window_end + timedelta(seconds=item["lateness_margin_s"]),
        "lateness_margin_s": item["lateness_margin_s"], "run_id": run.run_id, "_schema_version": "1.0",
    }
    outputs = [("bronze.acquisition", paths.acquisition_file(acquisition_id), [acquisition])]
    if result["rows"]:
        if item["source_system"] == "loki":
            outputs.append(("bronze.loki_entry", paths.loki_entry_file(acquisition_id, item["stream_class"]),
                            result["rows"]))
        elif item["source_system"] == "scenario_run_log":
            outputs.append(("bronze.scenario_run_entry", paths.scenario_run_entry_file(acquisition_id),
                            result["rows"]))
        else:
            outputs.append(("bronze.prometheus_sample", paths.prometheus_sample_file(acquisition_id),
                            result["rows"]))
    manifest = commit_build(
        store, run, layer="bronze", build_id=acquisition_id, plan_id=item["plan_id"],
        incident_id=item["incident_id"], coverage_id=None, build_status=acquisition["status"], inputs=[],
        outputs=outputs, quality={"status_counts": {acquisition["status"]: 1}}, supersedes=None,
        created_at=completed_at)
    return ref(manifest)


def _store_page(store, source_system, acquisition_id, result, body: bytes) -> int:
    page = result["page_count"]
    uri = paths.raw_page(source_system, acquisition_id, page)
    store.put_raw(uri, body)
    result["raw_pages"].append(uri)
    result["raw_sha256"].append(canonical.sha256_bytes(body))
    result["response_bytes"] += len(body)
    result["page_count"] += 1
    return page


def _loki_preflight(item, client, base) -> str:
    url = f"{base}/loki/api/v1/series"
    for start in (item["start_ns"], item["start_ns"] - int(LOOKBACK.total_seconds()) * 10**9):
        _, data, _ = _get(client, url, {"match[]": item["preflight_selector"], "start": str(start),
                                        "end": str(item["end_ns"])})
        if not isinstance(data.get("data"), list):
            raise SourceError("invalid_response")
        if data["data"]:
            return "present"
    return "absent"


def _acquire_loki(item, client, base, acquisition_id, store, result, sleep, delay) -> None:
    try:
        result["series_preflight"] = _loki_preflight(item, client, base)
    except SourceError as err:
        result.update(status="failed", status_reason=err.reason, http_status_last=err.http_status)
        return
    url = f"{base}/loki/api/v1/query_range"
    limit, cursor, seen = item["limit"], item["start_ns"], set()
    mismatch = truncated_reason = failure = None
    while True:
        if result["page_count"] >= item["max_pages"]:
            truncated_reason = "max_pages"
            break
        if result["page_count"]:
            sleep(delay)
        params = {"query": item["query_text"], "start": str(cursor), "end": str(item["end_ns"]),
                  "limit": limit, "direction": "forward"}
        try:
            body, data, status = _get(client, url, params)
            if data.get("data", {}).get("resultType") != "streams":
                raise SourceError("invalid_response", status)
        except SourceError as err:
            failure = err
            result["http_status_last"] = err.http_status
            break
        result["http_status_last"] = status
        page = _store_page(store, "loki", acquisition_id, result, body)
        result["warnings"].extend(_warnings(data))
        entries = []
        for stream in data["data"]["result"]:
            labels = stream.get("stream") or {}
            if _forbidden_stream(labels):
                raise ValueError(f"forbidden stream returned (DQ-B06): {labels}")
            if not _matches(labels, item["expected_labels"]):
                mismatch = True
            for ts, line in stream.get("values", []):
                entries.append((int(ts), labels, line))
        for row_index, (ts, labels, line) in enumerate(entries):
            key = canonical.loki_record_key(labels, ts, line)
            if key in seen:
                continue  # page-boundary duplicate (cursor is inclusive)
            seen.add(key)
            if item["body_filter"]:
                try:
                    body_obj = json.loads(line)
                except ValueError:
                    body_obj = None
                if isinstance(body_obj, dict) and not _matches(body_obj, item["body_filter"]):
                    mismatch = True
            result["rows"].append({
                "bronze_id": canonical.bronze_id(acquisition_id, page, row_index), "acquisition_id": acquisition_id,
                "stream_class": item["stream_class"], "stream_labels": canonical_str(labels),
                "stream_labels_sha256": h(labels), "entry_ts_ns": ts, "line": line,
                "line_sha256": sha256_text(line), "record_key": key, "_schema_version": "1.0"})
        if len(entries) < limit:
            break
        result["limit_hit"] = True
        stamps = {ts for ts, _, _ in entries}
        if len(stamps) == 1:
            truncated_reason = "same_ts_overflow"
            break
        cursor = max(stamps)

    if failure is not None and result["page_count"] == 0:
        result.update(status="failed", status_reason=failure.reason)
    elif mismatch:
        result.update(status="source_mismatch")
    elif failure is not None:
        result.update(status="partial", status_reason=f"page_failed:{failure.reason}")
    elif truncated_reason:
        result.update(status="truncated", status_reason=truncated_reason)
    elif result["warnings"]:
        result.update(status="partial", status_reason="source_warnings")
    elif result["rows"]:
        result.update(status="ok")
    else:
        result.update(status="empty_verified" if result["series_preflight"] == "present" else "empty_unverified")


def _acquire_prometheus(item, client, base, acquisition_id, store, result) -> None:
    params = dict(item["query_params"])
    try:
        _, data, _ = _get(client, f"{base}/api/v1/series", {"match[]": item["preflight_selector"],
                                                            "start": params["start"], "end": params["end"]})
        if not isinstance(data.get("data"), list):
            raise SourceError("invalid_response")
        result["series_preflight"] = "present" if data["data"] else "absent"
        body, data, status = _get(client, f"{base}/api/v1/query_range", {"query": item["query_text"], **params})
        if data.get("data", {}).get("resultType") != "matrix":
            raise SourceError("invalid_response", status)
    except SourceError as err:
        result.update(status="failed", status_reason=err.reason, http_status_last=err.http_status)
        return
    result["http_status_last"] = status
    page = _store_page(store, "prometheus", acquisition_id, result, body)
    result["warnings"].extend(_warnings(data))
    query_sha = sha256_text(item["query_text"])
    mismatch = False
    row_index = 0
    for series in data["data"]["result"]:
        labels = series.get("metric") or {}
        if not _matches(labels, item["expected_labels"]):
            mismatch = True
        for t, value in series.get("values", []):
            ts_ms = canonical.prom_ts_ms(t)
            result["rows"].append({
                "bronze_id": canonical.bronze_id(acquisition_id, page, row_index), "acquisition_id": acquisition_id,
                "query_name": item["query_name"], "query_text_sha256": query_sha,
                "series_labels": canonical_str(labels), "series_labels_sha256": h(labels), "sample_ts_ms": ts_ms,
                "value_raw": str(value), "record_key": canonical.prom_record_key(query_sha, labels, ts_ms, str(value)),
                "_schema_version": "1.0"})
            row_index += 1
    if mismatch:
        result.update(status="source_mismatch")
    elif result["warnings"]:
        result.update(status="partial", status_reason="source_warnings")
    elif result["rows"]:
        result.update(status="ok")
    else:
        result.update(status="empty_verified" if result["series_preflight"] == "present" else "empty_unverified")


def _acquire_run_log(path: str | None, acquisition_id, store, result) -> None:
    """scenarios/v2 run log: the whole file is one raw page and every non-empty line one Bronze row, read the
    way `scenarios/v2/fixtures.py` reads it (universal newlines, blank lines skipped). Nothing is parsed here."""
    if not path:
        result.update(status="not_attempted", status_reason="run_log_unconfigured")
        return
    try:
        body = Path(path).read_bytes()
    except FileNotFoundError:
        result.update(status="failed", status_reason="file_not_found")
        return
    except OSError:
        result.update(status="failed", status_reason="read_error")
        return
    page = _store_page(store, "scenario_run_log", acquisition_id, result, body)
    try:
        lines = re.split(r"\r\n|\r|\n", body.decode("utf-8"))
    except UnicodeDecodeError:
        result.update(status="failed", status_reason="read_error")
        return
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        result["rows"].append({
            "bronze_id": canonical.bronze_id(acquisition_id, page, len(result["rows"])),
            "acquisition_id": acquisition_id, "line_no": line_no, "line": line, "line_sha256": sha256_text(line),
            "record_key": canonical.scenario_run_record_key(line), "_schema_version": "1.0"})
    result.update(status="ok" if result["rows"] else "empty_verified")


def record_run(store: LocalFsStore, run: RunContext, refs: list[dict]) -> dict:
    statuses = {r["build_status"] for r in refs}
    status = "failed" if statuses == {"failed"} else "partial" if statuses & {"partial", "failed", "truncated"} \
        else "success"
    return lineage_writer.write_run(store, run, status)
