"""Measurement provenance, missing samples and durable Loki publication.

All HTTP in this test module is mocked; no test data is sent to a live Loki.
"""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from evaluation import ConfusionMatrix, RunOutcome
from experiment import ExperimentConfig, build_plan, run_experiment, write_results
from result_telemetry import enrich_result, publish_result_file, result_metadata


def metadata(repetition=1, detected=True):
    verify = SimpleNamespace(
        t0="2026-01-01T00:00:00+00:00",
        firing_active_at="2026-01-01T00:00:03.250000+00:00" if detected else None,
        stages={"loki_ruler_firing": SimpleNamespace(ok=detected)},
    )
    return result_metadata("unit-test", repetition, f"transfer-{repetition}", verify,
                           "http://localhost:3100/prometheus/api/v1/alerts")


class ResultTelemetryTest(unittest.TestCase):
    def test_preserves_measured_seconds_and_utc_endpoints(self):
        outcome = RunOutcome("S2-V1", "S2", "V1", True, True, True, 3.25)
        row = enrich_result(outcome, metadata())
        self.assertEqual(row["mttd_seconds"], outcome.mttd_seconds)
        self.assertEqual(row["started_at"], "2026-01-01T00:00:00+00:00")
        self.assertEqual(row["detected_at"], "2026-01-01T00:00:03.250000+00:00")
        self.assertIn("loki_ruler", row["measurement_basis"])

    def test_summary_samples_match_enriched_rows_and_misses_are_retained(self):
        outcomes = [
            RunOutcome("S2-V1", "S2", "V1", True, True, True, 3.25),
            RunOutcome("S2-V1", "S2", "V1", True, True, True, 7.75),
            RunOutcome("S2-V1", "S2", "V1", True, False, True),
            RunOutcome("C-a-V1", "C-a", "V1", False, True, True, 1.0),
            RunOutcome("S2-V1", "S2", "V1", True, True, False, 0.5),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            measurements = [metadata(i+1, o.detected) for i,o in enumerate(outcomes)]
            paths = write_results(outcomes, ConfusionMatrix.from_outcomes(outcomes), tmp,
                                  "test", measurements=measurements)
            rows = [json.loads(l) for l in Path(paths["runs_jsonl"]).read_text().splitlines()]
            summary = json.loads(Path(paths["summary_json"]).read_text())
        self.assertEqual(len(rows), 5)
        self.assertEqual(len({r["result_id"] for r in rows}), 5)
        self.assertIsNone(rows[2]["mttd_seconds"])
        self.assertIsNone(rows[2]["detected_at"])
        self.assertEqual(rows[2]["detection_status"], "not_detected")
        self.assertEqual(rows[4]["detection_status"], "invalid")
        selected = [r["mttd_seconds"] for r in rows
                    if r["valid"] and r["should_alert"] and r["detected"]]
        self.assertEqual(summary["confusion_matrix"]["mttd"]["count"], len(selected))
        self.assertEqual(summary["confusion_matrix"]["mttd"]["mean"], sum(selected)/len(selected))

    def test_retry_uses_exact_persisted_timestamp_and_no_duplicate_after_ack(self):
        row = enrich_result(RunOutcome("S2", "S2", "V1", True, True, True, 3.25), metadata())
        sent = []

        def push(request, timeout):
            sent.append(json.loads(request.data))
            if len(sent) == 1:
                raise OSError("lost acknowledgement")
            response = SimpleNamespace(status=204)
            from unittest.mock import MagicMock
            context = MagicMock()
            context.__enter__.return_value = response
            return context

        with tempfile.TemporaryDirectory() as tmp, patch("result_telemetry.urllib.request.urlopen", side_effect=push):
            path = Path(tmp)/"runs.jsonl"
            path.write_text(json.dumps(row)+"\n", encoding="utf8")
            with self.assertRaises(OSError):
                publish_result_file(path, "http://unit-test.invalid")
            self.assertFalse(path.with_name(path.name+".loki-receipt.json").exists())
            self.assertEqual(publish_result_file(path, "http://unit-test.invalid"), 1)
            self.assertEqual(publish_result_file(path, "http://unit-test.invalid"), 0)
        self.assertEqual(sent[0], sent[1])
        self.assertEqual(sent[1]["streams"][0]["values"][0][0], row["recorded_at_ns"])
        self.assertEqual(len(sent), 2)

    def test_legacy_timestamps_are_not_invented(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"legacy.jsonl"
            path.write_text('{"mttd_seconds": 5.0}\n')
            with self.assertRaisesRegex(ValueError, "metadata required"):
                publish_result_file(path, "http://unit-test.invalid")

    def test_publication_failure_preserves_evaluation_and_files(self):
        verify = SimpleNamespace(
            t0="2026-01-01T00:00:00+00:00", firing_active_at="2026-01-01T00:00:03+00:00",
            mttd_seconds=3.0, stages={"loki_ruler_firing": SimpleNamespace(ok=True)},
        )
        verifier = SimpleNamespace(wait_ruler_inactive=lambda **kw: True, verify=lambda *a,**kw: verify)
        cfg = ExperimentConfig("unit-test", verifier, inter_run_sleep=0,
                               results_loki_url="http://unit-test.invalid")
        with tempfile.TemporaryDirectory() as tmp, \
             patch("experiment.run_transfer", return_value={"crosscheck": {"ok": True}}), \
             patch("result_telemetry.publish_result_file", side_effect=OSError("offline")):
            with self.assertWarnsRegex(UserWarning, "export-results"):
                result = run_experiment(build_plan("V1", 1, 0), cfg, tmp, "test")
            self.assertEqual(result["confusion_matrix"]["mttd"]["mean"], 3.0)
            self.assertTrue(Path(result["paths"]["runs_jsonl"]).is_file())
            row = json.loads(Path(result["paths"]["runs_jsonl"]).read_text())
            self.assertEqual(row["mttd_seconds"], 3.0)


if __name__ == "__main__":
    unittest.main()
