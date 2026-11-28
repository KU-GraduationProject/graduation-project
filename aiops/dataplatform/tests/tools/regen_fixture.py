"""Recompute the STEP 0 fixture's derived values with the data platform code itself (#70, #71).

The fixture (docs/data-platform/examples/db-connection-limit) has no hand-editable derived
values: a Bronze line change moves its raw page sha, record key, Silver/Gold rows, lineage
edges and manifest sha. Hand-written inputs are `00`~`02` (request, bindings, scenario run log).
This script
  - sets the RCA envelope to the current Pipeline output shape (`LLMAnalysisResult.model_dump()`)
    and re-acquires that query from the mock sources (#70),
  - acquires `02_scenario_runs.jsonl` as the plan's `scenario_run` item (#71),
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
os.environ["DP_FIXTURE_DIR"] = str(FIXTURE)
sys.path[:0] = [str(DATAPLATFORM), str(DATAPLATFORM / "tests")]

import fixture_data as fx  # noqa: E402
from bronze.acquire import acquire  # noqa: E402
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
    """A. The RCA envelope `result` = what the current Pipeline writes. Returns the model dump."""
    entries = fx.jsonl("11_bronze_loki_entry.jsonl")
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
    write_rows("11_bronze_loki_entry.jsonl", entries)
    return dump


def rca_acquisition() -> None:
    """B. Re-acquire the RCA query from the mock sources: raw page bytes/sha, then the Bronze manifest."""
    acqs = fx.jsonl("10_bronze_acquisition.jsonl")
    want = next(a for a in acqs if a["acquisition_id"] == RCA_ACQ)
    item = next(i for i in plan_incident(fx.request(), fx.bindings_raw())
                if i["acquisition_key"] == want["acquisition_key"])
    line = next(r for r in fx.jsonl("11_bronze_loki_entry.jsonl") if r["acquisition_id"] == RCA_ACQ)
    with tempfile.TemporaryDirectory() as tmp:
        store = LocalFsStore(tmp)
        run = fx.run_context(fx.runs()[want["run_id"]], clock=fx.Clock(want["requested_at"]),
                             hex8=fx.Hex([RCA_ACQ[-8:]]))
        res = acquire(item, store, run, transport=mock_transport(FixtureSources(FIXTURE)), page_delay_s=0)
        built = store.read_manifest("bronze", res["build_id"])
        acq = output_rows(store, built, "bronze.acquisition")[0]
        assert output_rows(store, built, "bronze.loki_entry") == [line]
    changed = {k for k in want if want[k] != acq[k]}
    assert changed <= {"response_bytes", "raw_sha256", "requested_at", "completed_at"}, changed
    want.update({k: acq[k] for k in ("response_bytes", "raw_sha256")})  # the times stay the fixture's
    write_rows("10_bronze_acquisition.jsonl", acqs)

    manifests = fx.manifests()
    manifest = next(m for m in manifests if m["build_id"] == RCA_ACQ)
    assert [(o["dataset"], o["rows"]) for o in manifest["outputs"]] == [(o["dataset"], o["rows"])
                                                                        for o in built["outputs"]]
    with tempfile.TemporaryDirectory() as tmp:
        scratch = LocalFsStore(tmp)
        for o in manifest["outputs"]:
            for f in o["files"]:
                f["bytes"], f["sha256"] = scratch.write_rows(f["path"], fx.build_rows(o["dataset"], RCA_ACQ))
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
                else:
                    out.extend(old.get(build, []))
            write_rows(name, out)
        write_rows("50_manifests.jsonl", [shaped(built[m["build_id"]], m) if m["build_id"] in built else m
                                          for m in manifests])
        old = fx.load_json("51_current_pointers.json")
        scope = lambda p: (p["layer"], p.get("dataset"), p.get("coverage_id"), p.get("incident_id"))  # noqa: E731
        pointers = []
        for p in store.pointers():
            match = next((o for o in old if scope(o) == scope(p)), None)
            if match:
                # `updated_at` is the replay clock's value, not derived from the data: keep the fixture's
                assert {k: v for k, v in p.items() if k != "updated_at"} == \
                       {k: v for k, v in match.items() if k != "updated_at"}, (match, p)
                pointers.append(match)
            else:  # a new coverage of an existing run: same pointer commit time as its siblings
                sibling = next(o for o in old if o["run_id"] == p["run_id"])
                pointers.append(shaped({**p, "updated_at": sibling["updated_at"]}, sibling))
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
    replay()
    parity(dump)
    print(f"fixture regenerated: {FIXTURE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
