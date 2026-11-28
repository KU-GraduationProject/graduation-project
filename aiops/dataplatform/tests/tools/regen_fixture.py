"""Recompute the STEP 0 fixture's derived values with the data platform code itself (#70, #71, #77).

The fixture (docs/data-platform/examples/db-connection-limit) has no hand-editable derived
values: a Bronze line change moves its raw page sha, record key, Silver/Gold rows, lineage
edges and manifest sha. Hand-written inputs are `00`~`03` (request, bindings, scenario run log,
Remediation events) and the history spec below (extra RCA envelopes, the 04:32 runs).
This script
  - sets the RCA envelope to the current Pipeline output shape (`LLMAnalysisResult.model_dump()`),
    adds the RCA envelopes that carry a `remediation_id` (`RCA_EXTRA`, #77) and re-acquires that
    query from the mock sources (#70),
  - acquires `02_scenario_runs.jsonl` as the plan's `scenario_run` item (#71),
  - acquires the remediation chunks of `03_remediation_events.jsonl` in the first run, then the chunks
    still open in the 04:32 pre-evaluation re-acquisition (docs/data-platform/09 §9.1, #77),
  - replays the fixture history (tests/fixture_data.replay_fixture) and writes every Silver/Gold
    build's rows, edges, manifest and current pointer back in manifest order.
Rows keep the fixture serialization (schema column order, manifest and pointer key order).

Writes only inside the fixture directory (intermediate stores are temporary directories that are
removed on exit, and no bytecode is written). Running it on an up-to-date fixture changes nothing:

    python aiops/dataplatform/tests/tools/regen_fixture.py && git diff --exit-code docs/data-platform/examples
"""
import sys

sys.dont_write_bytecode = True

import json  # noqa: E402
import os  # noqa: E402
import tempfile  # noqa: E402
from collections import defaultdict  # noqa: E402
from pathlib import Path  # noqa: E402

DATAPLATFORM = Path(__file__).resolve().parents[2]
FIXTURE = DATAPLATFORM.parents[1] / "docs/data-platform/examples/db-connection-limit"
RCA_ACQ = "acq_20261110T032007Z_ba6da055"
SCENARIO_ACQ, SCENARIO_REQUESTED = "acq_20261110T032009Z_5a3e91c4", "2026-11-10T03:20:09.000000Z"
SCENARIO_SILVER, SCENARIO_SILVER_CREATED = "sb_20261110T032010Z_e3b7c215", "2026-11-10T03:20:13.600000Z"
LAYERS = ("bronze", "silver", "gold")
# #77: RCA envelopes after the existing one, same alert episode. handoff = pipeline/main.py `forward_to_remediation`
# with an accepted manual proposal. B is the record Remediation answered as `existing` (an earlier firing).
RCA_EXTRA = (  # (envelope timestamp, entry lag µs, action_type, action_targets, remediation_id)
    ("2026-11-10T03:01:28.604117+00:00", 8121, "KILL_SESSIONS", ["fixture-pg17"], "3c1e9a7b5d2f4e60a8b1c9d7e5f3a201"),
    ("2026-11-10T03:03:58.118530+00:00", 7954, "THROTTLE", ["fixture-backend"], "7a2d4c6e8f0b1d3e5a7c9e1b3d5f7a90"),
    ("2026-11-10T03:05:28.977402+00:00", 8306, "PAUSE", ["fixture-backend"], "e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4"),
)
REMEDIATION_FIRST_AT = "2026-11-10T03:20:09.100000Z"  # after the scenario run log, inside the first Bronze run
REMEDIATION_EVAL_AT = "2026-11-10T04:32:00.100000Z"  # >= remediation window end + lateness margin (04:31:20.512)
# 04:32 runs: dp_reprocess conf {"stream_classes": ["remediation_event"]} (09 §9.1). (task, params, start, end)
EVAL_AIRFLOW_RUN = "manual__2026-11-10T04:32:00+00:00"
EVAL_RUNS = (("acquire_bronze", {"incident_id": "inc_3f9a00917bce9babb36e68f4", "stream_classes": ["remediation_event"]},
              "2026-11-10T04:32:00.000000Z", "2026-11-10T04:32:00.400000Z", "success"),
             ("build_silver", {"datasets": ["silver.remediation_event"], "incident_id": "inc_3f9a00917bce9babb36e68f4"},
              "2026-11-10T04:32:10.000000Z", "2026-11-10T04:32:10.900000Z", "success"),
             ("build_gold", {"incident_id": "inc_3f9a00917bce9babb36e68f4"},
              "2026-11-10T04:32:15.000000Z", "2026-11-10T04:32:16.300000Z", "success"))
# Silver/Gold builds new in #77: (build id, run id, manifest created_at, main dataset). The replay rewrites the rest.
NEW_BUILDS = (("FIRST_REMEDIATION_SILVER", "run_4069680f5feed7639ed0", "2026-11-10T03:20:14.050000Z",
               "silver.remediation_event"),
              ("EVAL_REMEDIATION_SILVER", "EVAL_SILVER_RUN", "2026-11-10T04:32:10.600000Z", "silver.remediation_event"),
              ("CURRENT_GOLD", "EVAL_GOLD_RUN", "2026-11-10T04:32:16.200000Z", "gold.incident"))
POINTER_AT = {"EVAL_SILVER_RUN": "2026-11-10T04:32:10.800000Z", "EVAL_GOLD_RUN": "2026-11-10T04:32:16.250000Z"}
os.environ["DP_FIXTURE_DIR"] = str(FIXTURE)
sys.path[:0] = [str(DATAPLATFORM), str(DATAPLATFORM / "tests")]

import fixture_data as fx  # noqa: E402
from bronze.acquire import acquire, find_reusable  # noqa: E402
from bronze.plan import plan_incident  # noqa: E402
from contracts import canonical, pipeline_compat, schemas  # noqa: E402
from mock_sources.fixture_backend import FixtureSources, mock_transport  # noqa: E402
from storage.manifest import output_rows  # noqa: E402
from storage.store import LocalFsStore  # noqa: E402


def write_rows(name: str, rows: list[dict]) -> None:
    (FIXTURE / name).write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), "utf-8")


def write_json(name: str, value) -> None:
    (FIXTURE / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", "utf-8")


def shaped(new, template):
    """`new` with the key order of `template` (fixture serialization); keys `template` lacks go last, sorted."""
    if isinstance(new, dict) and isinstance(template, dict):
        keys = [k for k in template if k in new] + sorted(k for k in new if k not in template)
        return {k: shaped(new[k], template.get(k)) for k in keys}
    if isinstance(new, list) and isinstance(template, list) and template:
        return [shaped(n, template[min(i, len(template) - 1)]) for i, n in enumerate(new)]
    return new


def ordered(dataset: str, row: dict) -> dict:
    cols = [c for c, _, _ in schemas.columns(dataset)]
    assert set(row) == set(cols), (dataset, set(row) ^ set(cols))
    return {c: row[c] for c in cols}


def upsert_manifest(manifests: list[dict], manifest: dict) -> list[dict]:
    """50 is ordered by layer, then creation time."""
    rest = [m for m in manifests if m["build_id"] != manifest["build_id"]]
    rank = lambda m: (LAYERS.index(m["layer"]), m["created_at"])  # noqa: E731
    at = next((i for i, m in enumerate(rest) if rank(m) > rank(manifest)), len(rest))
    return rest[:at] + [manifest] + rest[at:]


def check_roundtrip() -> None:
    """The rewrite below reproduces untouched files byte for byte only if this holds."""
    for name in list(fx.DATASET_FILE.values()) + ["50_manifests.jsonl"]:
        if not (FIXTURE / name).exists():
            continue  # created by this script
        text = (FIXTURE / name).read_text("utf-8")
        again = "".join(json.dumps(json.loads(line), ensure_ascii=False) + "\n" for line in text.splitlines())
        assert again == text, f"{name}: not in the fixture serialization"


def rca_line() -> dict:
    """A. The RCA envelope `result` = what the current Pipeline writes, plus the `RCA_EXTRA` envelopes (written as
    candidate Bronze rows for the mock; `rca_acquisition` replaces them by the acquired rows). Returns the model dump."""
    entries = [r for r in fx.jsonl("11_bronze_loki_entry.jsonl")
               if r["acquisition_id"] != RCA_ACQ or r["bronze_id"].endswith(":0000:000000")]
    row = next(r for r in entries if r["acquisition_id"] == RCA_ACQ)
    envelope = json.loads(row["line"])
    assert json.dumps(envelope, ensure_ascii=False, separators=(",", ":")) == row["line"], "line encoding"
    old = envelope["result"]
    result = {"root_cause": old["root_cause"], "incident_class": "failure", "action_type": old["action_type"],
              "action_targets": old["action_targets"], "threat_level": old["threat_level"],
              "evidence": old["evidence"], "confidence": old["confidence"],
              "analysis_status": "valid", "invalid_reasons": []}
    dump = pipeline_compat.llm_output().LLMAnalysisResult(**result).model_dump()
    # The model may add default-valued fields (e.g. target_evidence, #72); the given values must survive.
    assert {k: dump[k] for k in result} == result, (dump, result)
    envelope["result"] = dump
    row["line"] = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))
    row["line_sha256"] = canonical.sha256_text(row["line"])
    row["record_key"] = canonical.loki_record_key(json.loads(row["stream_labels"]), row["entry_ts_ns"], row["line"])
    at = entries.index(row) + 1
    for stamp, lag_us, action, targets, remediation_id in RCA_EXTRA:
        result = pipeline_compat.llm_output().LLMAnalysisResult(
            **{**dump, "action_type": action, "action_targets": targets}).model_dump()
        extra = {**envelope, "timestamp": stamp, "result": result, "handoff_status": "approval_pending",
                 "remediation_dispatched": True, "remediation_id": remediation_id, "execution_attempted": False,
                 "approval_notification_dispatched": True}
        line = json.dumps(extra, ensure_ascii=False, separators=(",", ":"))
        ts_ns = canonical.ns_of(canonical.parse_ts(stamp)) + lag_us * 1000
        labels = json.loads(row["stream_labels"])
        entries.insert(at, {**row, "bronze_id": f"{RCA_ACQ}:candidate", "entry_ts_ns": ts_ns, "line": line,
                            "line_sha256": canonical.sha256_text(line),
                            "record_key": canonical.loki_record_key(labels, ts_ns, line)})
        at += 1
    write_rows("11_bronze_loki_entry.jsonl", entries)
    return dump


def rca_acquisition() -> None:
    """B. Re-acquire the RCA query from the mock sources: raw page bytes/sha, then the Bronze manifest."""
    acqs = fx.jsonl("10_bronze_acquisition.jsonl")
    want = next(a for a in acqs if a["acquisition_id"] == RCA_ACQ)
    item = next(i for i in plan_incident(fx.request(), fx.bindings_raw())
                if i["acquisition_key"] == want["acquisition_key"])
    entries = fx.jsonl("11_bronze_loki_entry.jsonl")
    candidates = [r for r in entries if r["acquisition_id"] == RCA_ACQ]
    with tempfile.TemporaryDirectory() as tmp:
        store = LocalFsStore(tmp)
        run = fx.run_context(fx.runs()[want["run_id"]], clock=fx.Clock(want["requested_at"]),
                             hex8=fx.Hex([RCA_ACQ[-8:]]))
        res = acquire(item, store, run, transport=mock_transport(FixtureSources(FIXTURE)), page_delay_s=0)
        built = store.read_manifest("bronze", res["build_id"])
        acq = output_rows(store, built, "bronze.acquisition")[0]
        rows = output_rows(store, built, "bronze.loki_entry")
    assert [(r["entry_ts_ns"], r["line"]) for r in rows] == [(r["entry_ts_ns"], r["line"]) for r in candidates]
    at = entries.index(candidates[0])
    entries = [r for r in entries if r["acquisition_id"] != RCA_ACQ]
    write_rows("11_bronze_loki_entry.jsonl", entries[:at] + rows + entries[at:])
    changed = {k for k in want if want[k] != acq[k]}
    assert changed <= {"response_bytes", "raw_sha256", "row_count", "requested_at", "completed_at"}, changed
    want.update({k: acq[k] for k in ("response_bytes", "raw_sha256", "row_count")})  # the times stay the fixture's
    write_rows("10_bronze_acquisition.jsonl", acqs)

    manifests = fx.manifests()
    manifest = next(m for m in manifests if m["build_id"] == RCA_ACQ)
    assert [o["dataset"] for o in manifest["outputs"]] == [o["dataset"] for o in built["outputs"]]
    with tempfile.TemporaryDirectory() as tmp:
        scratch = LocalFsStore(tmp)
        for o in manifest["outputs"]:
            for f in o["files"]:
                rows = fx.build_rows(o["dataset"], RCA_ACQ)
                f["rows"] = len(rows)
                f["bytes"], f["sha256"] = scratch.write_rows(f["path"], rows)
            o["rows"] = sum(f["rows"] for f in o["files"])
    write_rows("50_manifests.jsonl", manifests)


def scenario_acquisition() -> None:
    """C. (#71) Acquire `02_scenario_runs.jsonl` as the plan's `scenario_run` item in the first run."""
    item = next(i for i in plan_incident(fx.request(), fx.bindings_raw()) if i["stream_class"] == "scenario_run")
    with tempfile.TemporaryDirectory() as tmp:
        store = LocalFsStore(tmp)
        run = fx.run_context(fx.runs()[fx.FIRST_RUN], clock=fx.Clock(SCENARIO_REQUESTED),
                             hex8=fx.Hex([SCENARIO_ACQ[-8:]]))
        res = acquire(item, store, run, run_log_path=str(FIXTURE / "02_scenario_runs.jsonl"))
        built = store.read_manifest("bronze", res["build_id"])
        assert built["build_id"] == SCENARIO_ACQ and built["build_status"] == "ok", built["build_status"]
        acq = output_rows(store, built, "bronze.acquisition")[0]
        rows = output_rows(store, built, "bronze.scenario_run_entry")
    acqs = [a for a in fx.jsonl("10_bronze_acquisition.jsonl") if a["acquisition_id"] != SCENARIO_ACQ]
    at = next((i for i, a in enumerate(acqs) if a["requested_at"] > acq["requested_at"]), len(acqs))
    write_rows("10_bronze_acquisition.jsonl", acqs[:at] + [ordered("bronze.acquisition", acq)] + acqs[at:])
    write_rows("14_bronze_scenario_run_entry.jsonl", [ordered("bronze.scenario_run_entry", r) for r in rows])
    manifests = fx.manifests()
    template = next(m for m in manifests if m["build_id"] == RCA_ACQ)
    manifests = upsert_manifest(manifests, shaped(built, template))
    if not any(m["build_id"] == SCENARIO_SILVER for m in manifests):
        # replay_silver needs the build's run, id suffix and creation time; the replay rewrites the rest
        silver = next(m for m in manifests if m["layer"] == "silver" and fx.main_dataset(m) == "silver.rca_result")
        manifests = upsert_manifest(manifests, {**silver, "manifest_id": f"mf_{SCENARIO_SILVER}",
                                                "build_id": SCENARIO_SILVER, "created_at": SCENARIO_SILVER_CREATED,
                                                "outputs": [{"dataset": "silver.scenario_run"}]})
    write_rows("50_manifests.jsonl", manifests)


def eval_runs() -> None:
    """E. (#77) The 04:32 re-acquisition runs in `40_lineage_run.jsonl` (same row shape as the 03:40 runs)."""
    runs = fx.jsonl("40_lineage_run.jsonl")
    template = next(r for r in runs if r["run_id"] == fx.REPROCESS_RUN)
    for task, params, started, ended, status in EVAL_RUNS:
        run_id = canonical.run_id("airflow", "dp_reprocess", EVAL_AIRFLOW_RUN, task, 1, None)
        row = {**template, "run_id": run_id, "airflow_run_id": EVAL_AIRFLOW_RUN, "task_id": task,
               "params": canonical.canonical_str(params), "started_at": started, "ended_at": ended, "status": status}
        runs = [r for r in runs if r["run_id"] != run_id] + [row]
    assert [r["run_id"] for r in runs[-3:]] == [fx.EVAL_RUN, fx.EVAL_SILVER_RUN, fx.EVAL_GOLD_RUN]
    write_rows("40_lineage_run.jsonl", runs)


def remediation_acquisitions() -> None:
    """F. (#77) Remediation chunks: all of them in the first run (03:20:09), then in the 04:32 run the ones that were
    still open (closed chunks are reused, 02 §5). The mock answers only what Loki held at each request time."""
    items = [i for i in plan_incident(fx.request(), fx.bindings_raw()) if i["stream_class"] == "remediation_event"]
    sources = FixtureSources(FIXTURE)
    step = canonical.parse_ts("2026-11-10T00:00:00.020000Z") - canonical.parse_ts("2026-11-10T00:00:00.000000Z")
    new = []  # (acquisition row, loki rows, manifest)
    with tempfile.TemporaryDirectory() as tmp:
        store = LocalFsStore(tmp)
        for run_id, base in ((fx.FIRST_RUN, REMEDIATION_FIRST_AT), (fx.EVAL_RUN, REMEDIATION_EVAL_AT)):
            at = canonical.parse_ts(base)
            for item in items:
                if run_id == fx.EVAL_RUN and find_reusable(store, item["acquisition_key"]):
                    continue
                sources.now_ns = canonical.ns_of(at)
                run = fx.run_context(fx.runs()[run_id], clock=fx.Clock(at - step / 2),  # started_at, then `at`
                                     hex8=fx.Hex([canonical.h(["fixture", "#77", item["acquisition_key"], run_id])[:8]]))
                res = acquire(item, store, run, transport=mock_transport(sources), page_delay_s=0)
                built = store.read_manifest("bronze", res["build_id"])
                acq = output_rows(store, built, "bronze.acquisition")[0]
                assert acq["requested_at"] == canonical.fmt_ts(at), (acq["requested_at"], at)
                new.append((acq, output_rows(store, built, "bronze.loki_entry"), built))
                at += step
    ids = {a["acquisition_id"] for a, _, _ in new}
    acqs = [a for a in fx.jsonl("10_bronze_acquisition.jsonl") if a["acquisition_id"] not in ids]
    acqs = sorted(acqs + [ordered("bronze.acquisition", a) for a, _, _ in new], key=lambda a: a["requested_at"])
    write_rows("10_bronze_acquisition.jsonl", acqs)
    requested = {a["acquisition_id"]: a["requested_at"] for a in acqs}
    entries = [r for r in fx.jsonl("11_bronze_loki_entry.jsonl") if r["acquisition_id"] not in ids]
    entries += [ordered("bronze.loki_entry", r) for _, rows, _ in new for r in rows]
    write_rows("11_bronze_loki_entry.jsonl", sorted(entries, key=lambda r: requested[r["acquisition_id"]]))
    manifests = fx.manifests()
    template = next(m for m in manifests if m["build_id"] == RCA_ACQ)
    for _, _, built in new:
        manifests = upsert_manifest(manifests, shaped(built, template))
    write_rows("50_manifests.jsonl", manifests)


def new_build_placeholders() -> None:
    """G. (#77) Manifests of new Silver/Gold builds: `replay_silver`/`replay_gold` need their run, id suffix and
    creation time; the replay rewrites the rest."""
    manifests = fx.manifests()
    for build_name, run_name, created, dataset in NEW_BUILDS:
        build_id = getattr(fx, build_name)
        if any(m["build_id"] == build_id for m in manifests):
            continue
        layer = "gold" if build_id.startswith("gb_") else "silver"
        template = next(m for m in manifests if m["layer"] == layer)
        manifests = upsert_manifest(manifests, {**template, "manifest_id": f"mf_{build_id}", "build_id": build_id,
                                                "run_id": getattr(fx, run_name, run_name), "created_at": created,
                                                "outputs": [{"dataset": dataset}]})
    write_rows("50_manifests.jsonl", manifests)


def replay() -> None:
    """D. Replay the fixture history and write back every Silver/Gold build's rows, edges, manifest and pointer.
    Each row file is its builds' rows in manifest order; replaced builds keep only their manifest."""
    manifests = fx.manifests()
    with tempfile.TemporaryDirectory() as tmp:
        store = LocalFsStore(tmp)
        fx.replay_fixture(store)
        built = {m["build_id"]: store.read_manifest(m["layer"], m["build_id"]) for m in manifests
                 if m["layer"] != "bronze"}
        assert all(built.values()), [b for b, m in built.items() if m is None]
        for dataset, name in fx.DATASET_FILE.items():
            if dataset.startswith("bronze."):
                continue
            key = "child_version" if dataset == "lineage.edge" else "_dataset_version"
            old = defaultdict(list)
            for row in fx.jsonl(name) if (FIXTURE / name).exists() else []:
                old[row[key]].append(row)
            out = []
            for m in manifests:
                build = m["build_id"]
                if build in built and build not in fx.REPLACED:
                    out.extend(ordered(dataset, r) for r in output_rows(store, built[build], dataset))
                elif build not in fx.REPLACED:  # a replaced build keeps only its manifest
                    out.extend(old.get(build, []))
            write_rows(name, out)
        write_rows("50_manifests.jsonl", [shaped(built[m["build_id"]], m) if m["build_id"] in built else m
                                          for m in manifests])
        old = fx.load_json("51_current_pointers.json")
        scope = lambda p: (p["layer"], p.get("dataset"), p.get("coverage_id"), p.get("incident_id"))  # noqa: E731
        pointer_at = {getattr(fx, name): at for name, at in POINTER_AT.items()}
        pointers = []
        for p in store.pointers():
            match = next((o for o in old if scope(o) == scope(p)), None)
            # `updated_at` is the replay clock's value, not derived from the data: keep the fixture's
            if match and {k: v for k, v in p.items() if k != "updated_at"} == \
                    {k: v for k, v in match.items() if k != "updated_at"}:
                pointers.append(match)
                continue
            # a pointer moved by a new run, or a new coverage: that run's commit time (or its siblings')
            assert match is None or match["run_id"] != p["run_id"], (match, p)
            sibling = next((o for o in old if o["run_id"] == p["run_id"]), match or old[0])
            updated = pointer_at.get(p["run_id"]) or sibling["updated_at"]
            pointers.append(shaped({**p, "updated_at": updated}, sibling))
        assert all(any(scope(o) == scope(p) for p in pointers) for o in old)
        write_json("51_current_pointers.json", sorted(pointers, key=lambda p: (LAYERS.index(p["layer"]),
                                                                                  p["dataset"])))


def parity(dump: dict) -> None:
    """D. `60_realtime_parity.json` value of the revalidated LLM dump."""
    path = FIXTURE / "60_realtime_parity.json"
    text = path.read_text("utf-8")
    values = json.loads(text)
    values["llm_result_model_dump"] = dump
    path.write_text(json.dumps(values, ensure_ascii=False, indent=2) + ("\n" if text.endswith("\n") else ""), "utf-8")


def main() -> int:
    check_roundtrip()
    dump = rca_line()
    rca_acquisition()
    scenario_acquisition()
    eval_runs()
    remediation_acquisitions()
    new_build_placeholders()
    replay()
    parity(dump)
    print(f"fixture regenerated: {FIXTURE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
