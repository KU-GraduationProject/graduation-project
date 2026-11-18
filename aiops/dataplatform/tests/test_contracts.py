"""STEP 0.5 contract tests: re-verify S-01~S-06 (docs/data-platform/08 §3, §4) in code.

실행 (aiops/dataplatform 디렉터리에서):
    python -m unittest discover -s tests -v
"""
import json
import os
import re
import sys
import tempfile
import unittest
from collections import Counter

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

import fixture_data as fx  # noqa: E402
from contracts import canonical, enums, pipeline_compat, schemas  # noqa: E402
from contracts.canonical import h  # noqa: E402
from storage.store import LocalFsStore  # noqa: E402
from lineage.trace import integrity  # noqa: E402
from silver.build import check_coverage  # noqa: E402

DOCS = os.path.join(HERE, "..", "..", "..", "docs", "data-platform")
TYPES = {"string": "string", "string(JSON)": "json", "timestamp": "timestamp", "int32": "int32", "int64": "int64",
         "bool": "bool", "double": "double", "list<string>": "list<string>"}


def doc_tables() -> dict:
    """Parse the 01/03 dataset tables straight from the markdown."""
    out, current = {}, None
    for name in ("01_DATA_CONTRACT.md", "03_LINEAGE.md"):
        with open(os.path.join(DOCS, name), encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        for line in lines:
            m = re.match(r"^###? [\d.]+ `([a-z_]+\.[a-z_]+)`", line)
            if m:
                current = m.group(1)
                out[current] = []
                continue
            if line.startswith("## ") or line.startswith("### "):
                current = None
                continue
            if current and line.startswith("| `"):
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                names = re.findall(r"`([a-z_0-9]+)`", cells[0])
                if cells[1] == "(원 스키마)":
                    out[current].append(("@network", None, None))
                    continue
                if cells[1] not in TYPES:
                    continue
                nulls = [x.strip() for x in cells[2].split("/")]
                nulls = nulls * len(names) if len(nulls) == 1 else nulls
                out[current].extend((n, TYPES[cells[1]], null == "Y") for n, null in zip(names, nulls))
    return out


def all_rows():
    for dataset, name in fx.DATASET_FILE.items():
        for row in fx.jsonl(name):
            yield dataset, row
    for row in fx.jsonl("40_lineage_run.jsonl"):
        yield "lineage.run", row


class S01Schemas(unittest.TestCase):
    @unittest.skipUnless(os.path.isdir(DOCS), "docs/data-platform not mounted (e.g. inside dp-airflow)")
    def test_code_schemas_equal_document_tables(self):
        self.assertEqual(doc_tables(), schemas.DOC_TABLES)

    def test_every_fixture_row_matches_its_columns_nulls_and_types(self):
        checked = Counter()
        for dataset, row in all_rows():
            self.assertEqual(schemas.check_row(dataset, row), [], dataset)
            checked[dataset] += 1
        self.assertEqual(len(checked), 18)  # 19 datasets; silver.transport_issue has 0 rows (empty build)


class S02Vocabulary(unittest.TestCase):
    def test_enum_values_are_in_the_contract_vocabulary(self):
        for dataset, row in all_rows():
            for column, vocab in (("status", None), ("scope_role", enums.SCOPE_ROLES),
                                  ("stream_class", enums.STREAM_CLASSES), ("relation", enums.RELATIONS),
                                  ("event_time_source", enums.EVENT_TIME_SOURCES), ("severity", None),
                                  ("label_profile", enums.LABEL_PROFILES), ("reason_code", enums.QUARANTINE_REASONS),
                                  ("link_type", enums.LINK_TYPES), ("allowlist_decision", enums.ALLOWLIST_DECISIONS),
                                  ("overall_status", enums.OVERALL_STATUSES), ("series_preflight", enums.SERIES_PREFLIGHT),
                                  ("orchestrator", enums.ORCHESTRATORS)):
                if column not in row:
                    continue
                if column == "status":
                    vocab = {"bronze.acquisition": enums.ACQ_STATUSES, "gold.incident_channel": enums.CHANNEL_STATUSES,
                             "lineage.run": enums.RUN_STATUSES}[dataset]
                if column == "severity":
                    vocab = enums.SEVERITIES if dataset.startswith(("silver.app", "silver.db", "gold.evidence")) \
                        else None
                if vocab is not None and row[column] is not None:
                    self.assertIn(row[column], vocab, f"{dataset}.{column}")
            for flag in row.get("_quality_flags", []):
                self.assertIn(flag, enums.QUALITY_FLAGS)
            for reason in json.loads(row.get("skipped_reasons", "{}")):
                self.assertIn(reason, enums.SKIPPED_REASONS)


class S03Ids(unittest.TestCase):
    def test_incident_and_acquisition_ids(self):
        req = fx.request()
        aid = canonical.alert_event_id(req["alert"]["labels"], fx.ts(req["alert"]["starts_at"]))
        self.assertEqual(canonical.incident_id(aid), req["expected_incident_id"])
        for a in fx.jsonl("10_bronze_acquisition.jsonl"):
            self.assertEqual(canonical.acquisition_key(a["plan_id"], a["binding_sha256"], a["query_name"],
                                                       a["query_text"], a["window_start"], a["window_end"]),
                             a["acquisition_key"])
            self.assertRegex(a["acquisition_id"], r"^acq_\d{8}T\d{6}Z_[0-9a-f]{8}$")

    def test_binding_sha_is_hash_of_the_raw_binding_row(self):
        rows = json.loads(fx.bindings_raw())
        self.assertEqual({h(r) for r in rows},
                         {a["binding_sha256"] for a in fx.jsonl("10_bronze_acquisition.jsonl") if a["binding_sha256"]})

    def test_record_keys(self):
        for r in fx.jsonl("11_bronze_loki_entry.jsonl"):
            labels = json.loads(r["stream_labels"])
            self.assertEqual(canonical.loki_record_key(labels, r["entry_ts_ns"], r["line"]), r["record_key"])
            self.assertEqual(h(labels), r["stream_labels_sha256"])
            self.assertEqual(canonical.sha256_text(r["line"]), r["line_sha256"])
        for r in fx.jsonl("12_bronze_prometheus_sample.jsonl"):
            labels = json.loads(r["series_labels"])
            self.assertEqual(canonical.prom_record_key(r["query_text_sha256"], labels, r["sample_ts_ms"],
                                                       r["value_raw"]), r["record_key"])

    def test_silver_primary_keys(self):
        for r in fx.jsonl("20_silver_db_log.jsonl"):
            self.assertEqual(canonical.db_log_id(r["site"], r["source"], r["target"], r["session_id"], r["line_num"],
                                                 r["pg_timestamp_raw"]), r["db_log_id"])
        for r in fx.jsonl("22_silver_network_event.jsonl"):
            event = {k: r[k] for k in schemas.NETWORK_EVENT_FIELDS}
            self.assertEqual(canonical.network_event_id(event), r["network_event_id"])
        for r in fx.jsonl("23_silver_metric_point.jsonl"):
            self.assertEqual(canonical.metric_point_id(r["query_text_sha256"], json.loads(r["series_labels"]),
                                                       r["sample_ts_ms"]), r["metric_point_id"])
        for r in fx.jsonl("26_silver_quarantine.jsonl"):
            self.assertEqual(canonical.quarantine_id(r["record_key"], r["target_dataset"], r["reason_code"]),
                             r["quarantine_id"])

    def test_evidence_and_edge_ids(self):
        for r in fx.jsonl("32_gold_evidence_log.jsonl"):
            self.assertEqual(canonical.evidence_log_id(r["incident_id"], r["log_dataset"], r["silver_key"]),
                             r["evidence_id"])
        for r in fx.jsonl("33_gold_evidence_metric.jsonl"):
            self.assertEqual(canonical.evidence_metric_id(r["incident_id"], r["query_name"],
                                                          json.loads(r["series_labels"])), r["evidence_id"])
        for r in fx.jsonl("34_gold_evidence_network_flow.jsonl"):
            self.assertEqual(canonical.evidence_flow_id(r["incident_id"], r["scope_role"], json.loads(r["scope_identity"]),
                                                        r["src_service"], r["dst_service"], r["dst_ip"], r["dst_port"],
                                                        r["protocol"]), r["evidence_id"])
        for e in fx.jsonl("41_lineage_edge.jsonl"):
            self.assertEqual(canonical.edge_id(e["child_dataset"], e["child_key"], e["child_version"],
                                               e["parent_dataset"], e["parent_key"], e["parent_version"]), e["edge_id"])

    def test_run_id_and_map_index_rule(self):
        for r in fx.jsonl("40_lineage_run.jsonl"):
            args = (r["orchestrator"], r["dag_id"], r["airflow_run_id"], r["task_id"], r["try_number"])
            self.assertEqual(canonical.run_id(*args, r["map_index"]), r["run_id"])
            self.assertEqual(canonical.run_id(*args, -1), r["run_id"])  # unmapped Airflow task == null
            self.assertNotEqual(canonical.run_id(*args, 0), r["run_id"])
            self.assertNotEqual(canonical.run_id(*args, 0), canonical.run_id(*args, 1))

    def test_coverage_ids(self):
        plan = fx.plan_record()
        for m in fx.manifests():
            if m["layer"] == "bronze":
                continue
            dataset = next(o["dataset"] for o in m["outputs"] if o["dataset"] not in ("lineage.edge", "silver.quarantine"))
            self.assertEqual(canonical.coverage_id(dataset, plan["plan_id"], plan["plan_binding_sha256"],
                                                   plan["window_start"], plan["window_end"]), m["coverage_id"])

    def test_binding_change_gives_another_coverage(self):
        plan = fx.plan_record()
        other = canonical.plan_binding_sha256([plan["binding_set"][0], "f" * 64])
        self.assertNotEqual(canonical.coverage_id("silver.db_log", plan["plan_id"], other, plan["window_start"],
                                                  plan["window_end"]),
                            canonical.coverage_id("silver.db_log", plan["plan_id"], plan["plan_binding_sha256"],
                                                  plan["window_start"], plan["window_end"]))


class S04Manifests(unittest.TestCase):
    def test_current_build_files_hash_to_the_manifest(self):
        replaced = {"sb_20261110T032010Z_62bad93f", "gb_20261110T032015Z_edd1b412"}  # rows not in fixture
        for m in fx.manifests():
            if m["build_id"] in replaced:
                continue
            for output in m["outputs"]:
                rows = fx.build_rows(output["dataset"], m["build_id"])
                data = canonical.rows_bytes(rows)
                self.assertEqual((output["files"][0]["rows"], output["files"][0]["bytes"],
                                  output["files"][0]["sha256"]), (len(rows), len(data), canonical.sha256_bytes(data)))

    def test_raw_page_flattens_to_bronze_rows(self):
        raw = (fx.FIXTURE_DIR / "13_bronze_raw_page_example.json").read_bytes()
        first = fx.jsonl("10_bronze_acquisition.jsonl")[0]
        self.assertEqual(canonical.sha256_bytes(raw), first["raw_sha256"][0])
        page = json.loads(raw)
        flat = [(int(ts), s["stream"], line) for s in page["data"]["result"] for ts, line in s["values"]]
        rows = fx.build_rows("bronze.loki_entry", first["acquisition_id"])
        self.assertEqual([(r["entry_ts_ns"], json.loads(r["stream_labels"]), r["line"]) for r in rows], flat)

    def test_flag_counts_are_output_row_flags(self):
        for m in fx.manifests():
            if m["layer"] == "bronze" or m["build_id"] in ("sb_20261110T032010Z_62bad93f",
                                                            "gb_20261110T032015Z_edd1b412"):
                continue
            rows = [r for o in m["outputs"] if o["dataset"] not in ("lineage.edge", "silver.quarantine")
                    for r in fx.build_rows(o["dataset"], m["build_id"])]
            self.assertEqual(m["quality"]["flag_counts"], dict(Counter(f for r in rows for f in r["_quality_flags"])))


class S05QualityRules(unittest.TestCase):
    """DQ-B02/S01/S02/G01/L01 applied to the fixture loaded as a committed lake."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = LocalFsStore(self.tmp.name)
        for m in fx.manifests():
            if m["build_id"] not in ("sb_20261110T032010Z_62bad93f", "gb_20261110T032015Z_edd1b412"):
                fx.commit_fixture_build(self.store, m["build_id"])
        for pointer in fx.load_json("51_current_pointers.json"):
            self.store.write_pointer(pointer)

    def tearDown(self):
        self.tmp.cleanup()

    def test_fixture_lake_passes_validation(self):
        for m in self.store.manifests():  # DQ-B02: rows/bytes/sha256 of every committed file
            for output in m["outputs"]:
                for f in output["files"]:
                    data = self.store.data_path(f["path"]).read_bytes()
                    self.assertEqual((len(self.store.read_rows(f["path"])), len(data), canonical.sha256_bytes(data)),
                                     (f["rows"], f["bytes"], f["sha256"]))
        current = {p["build_id"] for p in self.store.pointers()}
        for m in self.store.manifests("silver"):  # DQ-S01/S02 on current Silver builds
            if m["build_id"] in current:
                self.assertEqual(check_coverage(self.store, m), [])
        # DQ-G01/L01. Runs are not part of the fixture lake.
        self.assertEqual(integrity(self.store, require_runs=False), [])

    def test_no_forbidden_stream_in_fixture(self):
        for a in fx.jsonl("10_bronze_acquisition.jsonl"):
            for token in enums.FORBIDDEN_SELECTOR_TOKENS:
                self.assertNotIn(token, a["query_text"] or "")

    def test_rendered_lines_are_masked(self):
        mask = pipeline_compat.log_line().mask_secrets
        for name in ("32_gold_evidence_log.jsonl", "33_gold_evidence_metric.jsonl", "34_gold_evidence_network_flow.jsonl"):
            for r in fx.jsonl(name):
                self.assertEqual(mask(r["rendered_line"]), r["rendered_line"])


class S06PipelineParity(unittest.TestCase):
    def test_resolve_identity_is_resolved(self):
        ident = pipeline_compat.identity()
        alert = fx.request()["alert"]
        identity, binding, status = ident.resolve_identity(alert["labels"], alert["annotations"],
                                                           ident.parse_bindings(fx.bindings_raw()))
        parity = fx.load_json("60_realtime_parity.json")["identity_resolution"]
        self.assertEqual((status, identity.to_dict()), (parity["status"], parity["identity"]))

    def test_llm_result_revalidates_to_the_same_dump(self):
        envelope = json.loads(fx.build_rows("bronze.loki_entry", "acq_20261110T032007Z_ba6da055")[0]["line"])
        dump = pipeline_compat.llm_output().LLMAnalysisResult(**envelope["result"]).model_dump()
        self.assertEqual(dump, fx.load_json("60_realtime_parity.json")["llm_result_model_dump"])

    def test_realtime_skipped_equals_gold_skipped_plus_quarantine(self):
        network = pipeline_compat.load("collector.network")
        corr = pipeline_compat.correlation()
        ident = pipeline_compat.identity()
        alert = fx.request()["alert"]
        identity, binding, _ = ident.resolve_identity(alert["labels"], alert["annotations"],
                                                      ident.parse_bindings(fx.bindings_raw()))
        ctx = corr.CorrelationContext.around(identity.service, corr.to_instant(alert["starts_at"]),
                                             __import__("datetime").timedelta(minutes=5), runtime=identity.runtime,
                                             identity=identity, binding=binding)
        lines = [r["line"] for r in fx.build_rows("bronze.loki_entry", "acq_20261110T032001Z_ac094d07")]
        events, skipped = network.NetworkCollector("http://unused")._parse(lines, ctx)
        channel = next(c for c in fx.jsonl("31_gold_incident_channel.jsonl")
                       if c["scope_role"] == "primary" and c["channel"] == "network")
        self.assertEqual((len(events), skipped), (0, channel["skipped"] + channel["quarantined"]))


if __name__ == "__main__":
    unittest.main()
