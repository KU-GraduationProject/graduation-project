"""Track D — phase entry points, dp_validate and E2E tests (docs/data-platform/05 §5 ①~⑤). Airflow 불필요.

실행 (aiops/dataplatform 디렉터리에서):
    python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

import fixture_data as fx  # noqa: E402
from mock_sources.fixture_backend import FixtureSources, mock_transport  # noqa: E402
from mock_sources.server import make_server  # noqa: E402
from orchestration import phases  # noqa: E402
from orchestration import validate as checks  # noqa: E402
from storage.manifest import output_rows  # noqa: E402
from storage.store import LocalFsStore  # noqa: E402


class FakeTI:
    def __init__(self, map_index=-1):
        self.dag_id, self.run_id, self.task_id, self.try_number, self.map_index = (
            "dp_bronze_acquire", "manual__2026-11-18T00:00:00+00:00", "acquire_loki", 1, map_index)


class PhaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.lake = LocalFsStore(self.tmp.name)
        self.sources = FixtureSources()
        self.hex = fx.Hex()
        self.clock = fx.Clock("2026-11-18T01:00:00.000000Z")

    def tearDown(self):
        self.tmp.cleanup()

    def make_run(self, task_id):
        return fx.run_context(clock=self.clock, hex8=self.hex, task_id=task_id)

    def run_all(self, request=None, transport=None):
        return phases.run_all(request or fx.request(), self.lake, self.make_run,
                              transport=transport or mock_transport(self.sources))

    # ⑤ (in-process) fixture HTTP -> A -> B -> C -> validate PASS
    def test_chain_commits_and_validate_passes(self):
        result = self.run_all()
        self.assertEqual(len(result["bronze"]), 15)
        self.assertEqual(len(result["silver"]), 7)
        self.assertEqual([g["build_status"] for g in result["gold"]], ["partial"])
        report = checks.summarize(checks.run_checks(self.lake), checks.find_orphans(self.lake))
        self.assertEqual((report["status"], report["orphans"]), ("passed", []))
        gold = self.lake.manifests("gold")[0]
        channels = {(c["scope_role"], c["channel"]): c["status"] for c in output_rows(self.lake, gold, "gold.incident_channel")}
        self.assertEqual(channels, {("primary", "log"): "complete", ("primary", "metric"): "unavailable",
                                    ("primary", "network"): "unavailable", ("related", "log"): "complete",
                                    ("related", "metric"): "complete", ("related", "network"): "complete"})

    # ② a re-run reuses closed ok acquisitions; rebuilt coverages get new builds and keep the previous ones
    def test_rerun_keeps_previous_builds(self):
        self.run_all()
        before = {m["build_id"] for m in self.lake.manifests()}
        second = self.run_all()
        self.assertTrue(any(r["status"] == "reused" for r in second["bronze"]))
        after = {m["build_id"] for m in self.lake.manifests()}
        self.assertLess(before, after)  # nothing removed, new builds added
        for build in second["silver"]:
            manifest = self.lake.read_manifest("silver", build["build_id"])
            self.assertIsNotNone(manifest["supersedes"])
            self.assertIsNotNone(self.lake.read_manifest("silver", manifest["supersedes"].removeprefix("mf_")))
        self.assertEqual(checks.summarize(checks.run_checks(self.lake), [])["status"], "passed")

    def test_filtered_reprocess_rebuilds_only_its_dataset(self):
        """A db_log-only forced re-acquisition keeps the plan's binding set (fixture 03:40 reprocess)."""
        self.run_all()
        reprocess = {**fx.request(), "force_reacquire": True, "page_limit": 3, "stream_classes": ["db_log"]}
        result = self.run_all(reprocess)
        self.assertEqual([b["dataset"] for b in result["silver"]], ["silver.db_log"])
        gold = self.lake.read_manifest("gold", result["gold"][0]["build_id"])
        roles = {(c["scope_role"], c["channel"]) for c in output_rows(self.lake, gold, "gold.incident_channel")}
        self.assertEqual(len(roles), 6)
        self.assertEqual(self.lake.read_plan(result["incident_id"])["binding_set"], fx.plan_record()["binding_set"])
        self.assertEqual(checks.summarize(checks.run_checks(self.lake), [])["status"], "passed")

    # ③ a failing build writes no manifest and leaves the current pointer alone
    def test_failed_build_commits_nothing(self):
        self.run_all()
        pointers = self.lake.pointers()
        acquisition = phases.plan_incident({**fx.request(), "force_reacquire": True, "stream_classes": ["db_log"]},
                                           phases.bindings_raw())[0]
        phases.acquire(acquisition, self.lake, self.make_run("reacquire"), mock_transport(self.sources))
        todo = next(t for t in phases.silver_todo(self.lake) if t["dataset"] == "silver.db_log")
        manifests = len(self.lake.manifests("silver"))
        with mock.patch.dict("silver.normalize.NORMALIZERS", {"silver.db_log": mock.Mock(side_effect=RuntimeError("boom"))}):
            with self.assertRaises(RuntimeError):
                phases.build_silver(todo, self.lake, self.make_run("build_silver"))
        self.assertEqual(len(self.lake.manifests("silver")), manifests)
        self.assertEqual(self.lake.pointers(), pointers)
        self.assertIn("failed", [r["status"] for r in self.lake.runs()])

    # ④ git_dirty=true is refused in production; unknown git sha is always refused
    def test_run_context_guards(self):
        with mock.patch.dict(os.environ, {"DP_GIT_SHA": "a" * 40, "DP_GIT_DIRTY": "true", "DP_ENV": "production"}):
            with self.assertRaises(RuntimeError):
                phases.airflow_run({"ti": FakeTI()})
        with mock.patch.dict(os.environ, {"DP_GIT_SHA": "", "DP_ENV": "development"}):
            with self.assertRaises(ValueError):
                phases.airflow_run({"ti": FakeTI()})
        with mock.patch.dict(os.environ, {"DP_GIT_SHA": "a" * 40, "DP_GIT_DIRTY": "false"}):
            unmapped, mapped = phases.airflow_run({"ti": FakeTI(-1)}), phases.airflow_run({"ti": FakeTI(3)})
        self.assertIsNone(unmapped.map_index)
        self.assertNotEqual(unmapped.run_id, mapped.run_id)

    def test_validate_detects_tampered_file(self):
        self.run_all()
        manifest = self.lake.manifests("silver")[0]
        path = self.lake.data_path(manifest["outputs"][0]["files"][0]["path"])
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "rows/bytes/sha256"):
            checks.summarize(checks.run_checks(self.lake), [])

    def test_validate_detects_tampered_raw_page(self):
        self.run_all()
        acq = output_rows(self.lake, self.lake.manifests("bronze")[0], "bronze.acquisition")[0]
        self.lake.put_raw(acq["raw_pages"][0], b"{}")
        self.assertTrue(any("raw page sha256" in e for e in checks.check_raw_pages(self.lake)))

    def test_validate_detects_pointer_to_uncommitted_build(self):
        self.run_all()
        pointer = self.lake.pointers()[0]
        self.lake.manifest_path(pointer["layer"], pointer["build_id"]).unlink()
        self.assertTrue(any("not committed" in e for e in checks.check_pointers(self.lake)))

    def test_validate_detects_edge_with_missing_parent(self):
        self.run_all()
        for manifest in self.lake.manifests("bronze"):
            self.lake.manifest_path("bronze", manifest["build_id"]).unlink()
        self.assertTrue(checks.check_lineage(self.lake))

    def test_orphan_file_is_reported_not_failed(self):
        self.run_all()
        orphan = self.lake.root / "lake-silver" / "v1" / "stray.jsonl"
        orphan.write_text("{}", "utf-8")
        report = checks.summarize(checks.run_checks(self.lake), checks.find_orphans(self.lake))
        self.assertEqual(report["orphans"], ["lake-silver/v1/stray.jsonl"])

    def test_pointer_refuses_uncommitted_target(self):
        from storage.manifest import move_pointer
        fake = {"layer": "silver", "build_id": "sb_20261110T000000Z_00000000", "manifest_id": "mf_x",
                "coverage_id": "cov_x", "created_at": "2026-11-10T00:00:00.000000Z"}
        with self.assertRaises(FileNotFoundError):
            move_pointer(self.lake, fake, "silver.db_log", self.make_run("p"))

    # ⑤ (HTTP) the same chain against the mock server over real sockets (loopback, ephemeral port)
    def test_chain_over_http_mock_server(self):
        server = make_server("127.0.0.1", 0, self.sources)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = f"http://127.0.0.1:{server.server_address[1]}"
        with mock.patch.dict(os.environ, {"DP_LOKI_URL": url, "DP_PROMETHEUS_URL": url, "DP_PAGE_DELAY_S": "0"}):
            result = phases.run_all(fx.request(), self.lake, self.make_run, transport=None)
        self.assertEqual(len(result["gold"]), 1)
        self.assertEqual(checks.summarize(checks.run_checks(self.lake), checks.find_orphans(self.lake))["status"],
                         "passed")


class DagStructureTest(unittest.TestCase):
    """Loads the DAG folder only where Airflow is installed (the dp-airflow image)."""

    def setUp(self):
        try:
            from airflow.dag_processing.dagbag import DagBag
        except ImportError:
            try:
                from airflow.models.dagbag import DagBag
            except ImportError:
                self.skipTest("Airflow not installed")
        folder = os.path.join(os.path.dirname(__file__), "..", "airflow", "dags")
        sys.path.insert(0, folder)  # Airflow puts the DAG folder on sys.path the same way
        self.bag = DagBag(dag_folder=folder)

    def test_phase_dags_load_without_errors(self):
        self.assertEqual(self.bag.import_errors, {})
        self.assertEqual(set(self.bag.dag_ids),
                         {"dp_bronze_acquire", "dp_silver_transform", "dp_gold_build", "dp_validate"})

    def test_phase_tasks(self):
        tasks = {d: sorted(self.bag.get_dag(d).task_ids) for d in self.bag.dag_ids}
        self.assertEqual(tasks["dp_bronze_acquire"],
                         ["acquire_loki", "acquire_prometheus", "commit_bronze", "plan_loki", "plan_prometheus"])
        self.assertEqual(tasks["dp_validate"], ["check_lineage", "check_manifests", "check_pointers",
                                                "check_raw_pages", "check_silver", "find_orphans", "report"])
        self.assertEqual(tasks["dp_silver_transform"], ["build_silver", "plan_builds", "update_current"])
        self.assertEqual(tasks["dp_gold_build"], ["build_gold", "plan_builds", "update_current"])


if __name__ == "__main__":
    unittest.main()
