"""Recompute the STEP 0 fixture's derived values with the data platform code itself (#70).

The fixture (docs/data-platform/examples/db-connection-limit) has no hand-editable derived
values: a Bronze line change moves its raw page sha, record key, Silver/Gold rows, lineage
edges and manifest sha. This script sets the RCA envelope to the current Pipeline output shape
(`LLMAnalysisResult.model_dump()`), re-acquires that query from the mock sources and replays the
fixture history (tests/fixture_data.replay_fixture), then writes back only the rebuilt values.
Rows keep the fixture serialization (schema column order, manifest key order).

Writes only inside the fixture directory (intermediate stores are temporary directories that are
removed on exit, and no bytecode is written). Running it on an up-to-date fixture changes nothing:

    python aiops/dataplatform/tests/tools/regen_fixture.py && git diff --exit-code docs/data-platform/examples
"""
import sys

sys.dont_write_bytecode = True

import json  # noqa: E402
import os  # noqa: E402
import tempfile  # noqa: E402
from pathlib import Path  # noqa: E402

DATAPLATFORM = Path(__file__).resolve().parents[2]
FIXTURE = DATAPLATFORM.parents[1] / "docs/data-platform/examples/db-connection-limit"
RCA_ACQ = "acq_20261110T032007Z_ba6da055"
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


def like(new, old):
    """`new` with the key order of `old` (fixture serialization); keys must match."""
    if isinstance(new, dict):
        assert sorted(new) == sorted(old), (sorted(new), sorted(old))
        return {k: like(new[k], old[k]) for k in old}
    if isinstance(new, list) and isinstance(old, list) and len(new) == len(old):
        return [like(n, o) for n, o in zip(new, old)]
    return new


def check_roundtrip() -> None:
    """The rewrite below reproduces untouched files byte for byte only if this holds."""
    for name in list(fx.DATASET_FILE.values()) + ["50_manifests.jsonl"]:
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
    assert dump == result, (dump, result)
    envelope["result"] = result
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


def replay() -> None:
    """C. Replay the fixture history and write back every Silver/Gold build's rows, edges and manifest."""
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
            cols = [c for c, _, _ in schemas.columns(dataset)]
            out, done = [], set()
            for row in fx.jsonl(name):
                build = row[key]
                if build not in built:
                    out.append(row)
                elif build not in done:
                    done.add(build)
                    for new in output_rows(store, built[build], dataset):
                        assert set(new) == set(cols), (dataset, set(new) ^ set(cols))
                        out.append({c: new[c] for c in cols})
            write_rows(name, out)
        write_rows("50_manifests.jsonl", [like(built[m["build_id"]], m) if m["build_id"] in built else m
                                          for m in manifests])
        for p in fx.load_json("51_current_pointers.json"):
            scope = ({"incident_id": p["incident_id"]} if p["layer"] == "gold"
                     else {"dataset": p["dataset"], "coverage_id": p["coverage_id"]})
            current = store.read_pointer(p["layer"], **scope)
            # `updated_at` is the replay clock's value, not derived from the data
            assert {k: v for k, v in current.items() if k != "updated_at"} == \
                   {k: v for k, v in p.items() if k != "updated_at"}, (p, current)


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
    replay()
    parity(dump)
    print(f"fixture regenerated: {FIXTURE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
