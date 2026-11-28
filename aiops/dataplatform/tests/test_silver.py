"""Track B — Silver tests (docs/data-platform/05 §5 ①~⑥). Inputs are fixture Bronze builds only."""
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

import fixture_data as fx  # noqa: E402
from contracts import canonical, pipeline_compat  # noqa: E402
from silver.build import build_silver, check_coverage, coverage, coverage_inputs, plan_silver  # noqa: E402
from storage.manifest import commit_build, output_rows  # noqa: E402
from storage.store import LocalFsStore  # noqa: E402

ENVELOPE_IDS = ("_dataset_version", "_run_id")


class SilverTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = LocalFsStore(self.tmp.name)
        self.plan = fx.plan_record()
        self.hex = fx.Hex()

    def tearDown(self):
        self.tmp.cleanup()

    def load_bronze(self, run_id=None):
        for m in fx.manifests():
            if m["layer"] == "bronze" and (run_id is None or m["run_id"] == run_id):
                fx.commit_fixture_build(self.store, m["build_id"])

    def rebuild(self, want):
        return fx.replay_silver(self.store, want["build_id"])

    def assert_build_equals_fixture(self, manifest, want):
        self.assertEqual(manifest, want)
        for output in want["outputs"]:
            self.assertEqual(output_rows(self.store, manifest, output["dataset"]),
                             fx.build_rows(output["dataset"], want["build_id"]), output["dataset"])

    # ① fixture Bronze -> 20~27 (first run), then the db_log rebuild after the forced re-acquisition
    def test_fixture_bronze_reproduces_silver(self):
        self.load_bronze(fx.FIRST_RUN)
        first = [m for m in fx.manifests() if m["layer"] == "silver" and m["run_id"] == "run_4069680f5feed7639ed0"]
        for want in first:
            if want["build_id"] in fx.REPLACED:
                manifest = self.rebuild(want)  # rows are not in the fixture; manifest quality/inputs still match
                self.assertEqual((manifest["inputs"], manifest["quality"], manifest["coverage_id"]),
                                 (want["inputs"], want["quality"], want["coverage_id"]))
                self.assertEqual([(o["dataset"], o["rows"]) for o in manifest["outputs"]],
                                 [(o["dataset"], o["rows"]) for o in want["outputs"]])
                continue
            self.assert_build_equals_fixture(self.rebuild(want), want)
        fx.commit_fixture_build(self.store, "acq_20261110T034000Z_e240baaa")
        self.assertEqual([t["dataset"] for t in plan_silver(self.store, self.plan)], ["silver.db_log"])
        want = fx.manifest("sb_20261110T034042Z_c4d90e9a")
        self.assert_build_equals_fixture(self.rebuild(want), want)

    # ② same Silver PK from two acquisitions -> one row, _dup_count=2, both parents as edges
    def test_duplicate_rows_merge(self):
        self.load_bronze()
        manifest = self.rebuild(fx.manifest("sb_20261110T034042Z_c4d90e9a"))
        rows = output_rows(self.store, manifest, "silver.db_log")
        dup = [r for r in rows if r["_dup_count"] == 2]
        self.assertEqual(len(dup), 3)
        self.assertTrue(all("duplicate" in r["_quality_flags"] for r in dup))
        edges = output_rows(self.store, manifest, "lineage.edge")
        self.assertEqual(len(edges), 9)
        self.assertEqual({e["parent_version"] for e in edges if e["child_key"] == dup[0]["db_log_id"]},
                         {"acq_20261110T032000Z_f6122f9f", "acq_20261110T034000Z_e240baaa"})

    # ③ unsupported zone (JST) -> receiver time + flags
    def test_unknown_zone_falls_back_to_receiver_time(self):
        self.load_bronze(fx.FIRST_RUN)
        manifest = self.rebuild(fx.manifest("sb_20261110T032010Z_62bad93f"))
        jst = next(r for r in output_rows(self.store, manifest, "silver.db_log") if "JST" in r["pg_timestamp_raw"])
        self.assertEqual((jst["event_time_source"], jst["event_time"]), ("receiver_fallback", "2026-11-10T03:01:03.250000Z"))
        self.assertEqual(jst["_quality_flags"], ["event_time_fallback", "log_time_parse_error"])

    # ④ future MAJOR network event -> quarantine, never dropped silently
    def test_future_major_is_quarantined(self):
        self.load_bronze(fx.FIRST_RUN)
        manifest = self.rebuild(fx.manifest("sb_20261110T032010Z_06fac1f8"))
        quarantine = output_rows(self.store, manifest, "silver.quarantine")
        self.assertEqual([(q["reason_code"], q["detail"]) for q in quarantine],
                         [("unsupported_schema_version", "schema_version='2.0'")])
        self.assertEqual((manifest["quality"]["quarantined"], manifest["quality"]["skipped"]), (1, 1))

    # ⑤ legacy label profile: label `source` is the output channel, not the observation source
    def test_legacy_label_profile(self):
        acquisition_id = "acq_20261110T032003Z_00000aaa"
        labels = {"container": "backend", "log_format": "json", "service": "backend", "source": "stdout"}
        line = json.dumps({"level": "ERROR", "message": "boom"})
        rows = [{"bronze_id": canonical.bronze_id(acquisition_id, 0, 0), "acquisition_id": acquisition_id,
                 "stream_class": "app_log", "stream_labels": canonical.canonical_str(labels),
                 "stream_labels_sha256": canonical.h(labels), "entry_ts_ns": 1794279620000000000, "line": line,
                 "line_sha256": canonical.sha256_text(line),
                 "record_key": canonical.loki_record_key(labels, 1794279620000000000, line), "_schema_version": "1.0"}]
        self.commit_synthetic(acquisition_id, "app_log", "loki", rows)
        cov = coverage("silver.app_log", self.plan)
        result = build_silver("silver.app_log", cov, coverage_inputs(self.store, cov), self.store,
                              fx.run_context(hex8=self.hex))
        row = output_rows(self.store, self.store.read_manifest("silver", result["build_id"]), "silver.app_log")[0]
        self.assertEqual((row["label_profile"], row["log_stream"], row["source"], row["site"]),
                         ("legacy", "stdout", "UNKNOWN", "UNKNOWN"))
        self.assertIn("identity_unverified", row["_quality_flags"])

    def test_revised_metric_value_uses_last_closed_acquisition(self):
        base = fx.build_rows("bronze.prometheus_sample", "acq_20261110T032006Z_7fdc2fe0")[:2]
        for i, (acq_id, value) in enumerate((("acq_20261110T032006Z_00000aa1", "0.5"),
                                             ("acq_20261110T032007Z_00000aa2", "0.7"))):
            rows = [{**r, "bronze_id": canonical.bronze_id(acq_id, 0, j), "acquisition_id": acq_id,
                     "value_raw": value if j == 0 else r["value_raw"],
                     "record_key": canonical.prom_record_key(r["query_text_sha256"], json.loads(r["series_labels"]),
                                                             r["sample_ts_ms"], value if j == 0 else r["value_raw"])}
                    for j, r in enumerate(base)]
            self.commit_synthetic(acq_id, "metric", "prometheus", rows, requested=f"2026-11-10T03:2{i}:00.000000Z")
        cov = coverage("silver.metric_point", self.plan)
        result = build_silver("silver.metric_point", cov, coverage_inputs(self.store, cov), self.store,
                              fx.run_context(hex8=self.hex))
        rows = output_rows(self.store, self.store.read_manifest("silver", result["build_id"]), "silver.metric_point")
        self.assertEqual((rows[0]["value"], rows[0]["_quality_flags"]), (0.7, ["duplicate", "value_revised"]))
        self.assertEqual(rows[1]["_quality_flags"], ["duplicate"])

    def commit_synthetic(self, acquisition_id, stream_class, source, rows, requested="2026-11-10T03:20:03.000000Z"):
        template = next(a for a in fx.jsonl("10_bronze_acquisition.jsonl") if a["stream_class"] == stream_class)
        acq = {**template, "acquisition_id": acquisition_id, "requested_at": requested, "completed_at": requested,
               "row_count": len(rows), "raw_pages": [], "raw_sha256": [], "page_count": 0}
        dataset = "bronze.loki_entry" if source == "loki" else "bronze.prometheus_sample"
        run = fx.run_context(hex8=self.hex)
        commit_build(self.store, run, layer="bronze", build_id=acquisition_id, plan_id=acq["plan_id"],
                     incident_id=acq["incident_id"], coverage_id=None, build_status=acq["status"], inputs=[],
                     outputs=[("bronze.acquisition", f"s3://lake-bronze/v1/acquisition/{acquisition_id}.parquet", [acq]),
                              (dataset, f"s3://lake-bronze/v1/x/{acquisition_id}/part-0000.parquet", rows)],
                     quality={"status_counts": {acq["status"]: 1}}, supersedes=None, created_at=fx.ts(requested))

    # ⑥ every Bronze row explains as a Silver or quarantine parent (DQ-S01), PK unique (DQ-S02)
    def test_every_bronze_row_is_explained(self):
        self.load_bronze()
        for todo in plan_silver(self.store, self.plan):
            result = build_silver(todo["dataset"], todo["coverage"], todo["inputs"], self.store,
                                  fx.run_context(hex8=self.hex))
            self.assertEqual(check_coverage(self.store, self.store.read_manifest("silver", result["build_id"])), [])

    def test_rebuild_with_same_inputs_has_same_content(self):
        self.load_bronze(fx.FIRST_RUN)
        cov = coverage("silver.network_event", self.plan)
        builds = [build_silver("silver.network_event", cov, coverage_inputs(self.store, cov), self.store,
                               fx.run_context(hex8=self.hex, task_id=f"t{i}")) for i in range(2)]
        contents = []
        for b in builds:
            m = self.store.read_manifest("silver", b["build_id"])
            contents.append([{k: v for k, v in r.items() if k not in ENVELOPE_IDS}
                             for r in output_rows(self.store, m, "silver.network_event")])
        self.assertNotEqual(builds[0]["build_id"], builds[1]["build_id"])
        self.assertEqual(contents[0], contents[1])


class RcaEnvelopeTest(unittest.TestCase):
    """`silver.rca_result` keeps every LLM output shape the Pipeline has written (#70): never a silent drop."""

    CURRENT = {"root_cause": "connection slots exhausted", "incident_class": "failure", "action_type": "NOTIFY",
               "action_targets": [], "threat_level": "high", "evidence": ["L1"], "confidence": 0.7,
               "analysis_status": "valid", "invalid_reasons": []}

    def normalize(self, result):
        from silver.normalize import rca_result
        envelope = {**json.loads(fx.build_rows("bronze.loki_entry", "acq_20261110T032007Z_ba6da055")[0]["line"]),
                    "result": result}
        line = json.dumps(envelope)
        return rca_result({"line": line, "record_key": canonical.sha256_text(line), "entry_ts_ns": 1}, {})

    def test_current_output_shape(self):
        out = self.normalize(self.CURRENT)
        self.assertEqual((out.values["incident_class"], out.values["analysis_status"],
                          out.values["action_description"]), ("failure", "valid", None))
        self.assertNotIn("llm_output_legacy", out.flags)

    def test_pre_incident_class_output_is_kept_and_flagged(self):
        legacy = {k: v for k, v in self.CURRENT.items() if k not in ("incident_class", "analysis_status",
                                                                     "invalid_reasons")}
        out = self.normalize({**legacy, "action_description": "Notify the DB operator."})
        self.assertEqual((out.values["incident_class"], out.values["analysis_status"],
                          out.values["action_description"], out.values["threat_level"]),
                         (None, None, "Notify the DB operator.", "high"))
        self.assertIn("llm_output_legacy", out.flags)

    def test_pipeline_invalid_analysis_is_kept(self):
        invalid = pipeline_compat.llm_output().LLMAnalysisResult.invalid(["truncated"]).model_dump()
        out = self.normalize(invalid)
        self.assertEqual((out.values["incident_class"], out.values["analysis_status"], out.values["action_type"]),
                         (None, "invalid", "NOTIFY"))
        self.assertNotIn("llm_output_legacy", out.flags)

    def test_null_class_on_a_valid_analysis_is_quarantined(self):
        from silver.normalize import Quarantine
        with self.assertRaises(Quarantine) as ctx:
            self.normalize({**self.CURRENT, "incident_class": None})
        self.assertEqual(ctx.exception.reason, "invalid_value")

    def test_legacy_output_still_validates_other_fields(self):
        from silver.normalize import Quarantine
        legacy = {k: v for k, v in self.CURRENT.items() if k != "incident_class"}
        with self.assertRaises(Quarantine) as ctx:
            self.normalize({**legacy, "threat_level": "extreme"})
        self.assertEqual(ctx.exception.reason, "invalid_value")



class ScenarioRunTest(unittest.TestCase):
    """`silver.scenario_run` (#71): one row per run record of scenarios/v2/run.py; bad lines are quarantined."""

    LINE = {"scenario_id": "f2_c_db_pool_exhaustion", "variant_id": None, "seed": None,
            "started_at": "2026-11-10T02:58:00.000000+00:00", "ended_at": "2026-11-10T03:02:30.000000+00:00",
            "status": "ok"}

    def normalize(self, rec):
        from silver.normalize import scenario_run
        line = rec if isinstance(rec, str) else json.dumps(rec)
        return scenario_run({"line": line, "record_key": canonical.scenario_run_record_key(line), "line_no": 1}, {})

    def test_run_record(self):
        line = json.dumps({**self.LINE, "variant_id": "v2", "seed": 7})
        out = self.normalize(line)
        self.assertEqual(out.pk, canonical.scenario_run_record_key(line))
        self.assertEqual(out.values, {
            "scenario_run_id": out.pk, "scenario_id": "f2_c_db_pool_exhaustion", "variant_id": "v2", "seed": 7,
            "started_at": "2026-11-10T02:58:00.000000Z", "ended_at": "2026-11-10T03:02:30.000000Z",
            "started_at_raw": "2026-11-10T02:58:00.000000+00:00", "ended_at_raw": "2026-11-10T03:02:30.000000+00:00",
            "status": "ok"})
        self.assertEqual(out.flags, set())

    def test_bad_lines_are_quarantined(self):
        from silver.normalize import Quarantine
        cases = [("not json", "invalid_json"), ("[1]", "not_object"),
                 ({k: v for k, v in self.LINE.items() if k != "scenario_id"}, "missing_required_field"),
                 ({**self.LINE, "status": None}, "missing_required_field"),
                 ({**self.LINE, "started_at": "2026-11-10T02:58:00"}, "invalid_timestamp"),  # no offset (C-4)
                 ({**self.LINE, "seed": "7"}, "invalid_value"), ({**self.LINE, "scenario_id": 3}, "invalid_value")]
        for rec, reason in cases:
            with self.subTest(rec=rec), self.assertRaises(Quarantine) as ctx:
                self.normalize(rec)
            self.assertEqual(ctx.exception.reason, reason)


if __name__ == "__main__":
    unittest.main()
