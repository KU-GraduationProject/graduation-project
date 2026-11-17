"""Phase stub + dp_validate tests (Airflow 불필요).

실행 (aiops/dataplatform 디렉터리에서):
    python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from orchestration import fixture_stubs as phase  # noqa: E402
from orchestration import validate as checks  # noqa: E402
from orchestration.lake import LocalLake  # noqa: E402


def run_all_phases(lake: LocalLake) -> dict:
    plan = phase.plan_incident(phase.load_request())
    bronze = [phase.acquire(item, lake) for items in plan.values() for item in items]
    silver = [phase.build_silver(b["build_id"], lake) for b in phase.silver_builds()]
    phase.update_pointers("silver", lake)
    gold = [phase.build_gold(b["build_id"], lake) for b in phase.gold_builds()]
    phase.update_pointers("gold", lake)
    return {"plan": plan, "bronze": bronze, "silver": silver, "gold": gold}


def run_checks(lake: LocalLake) -> dict:
    return {"manifests": checks.check_manifests(lake), "pointers": checks.check_pointers(lake),
            "lineage": checks.check_lineage(lake)}


class PhaseStubTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.lake = LocalLake(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_plan_groups_fixture_acquisitions_by_source(self):
        plan = phase.plan_incident(phase.load_request())
        self.assertEqual((len(plan["loki"]), len(plan["prometheus"])), (9, 2))

    def test_all_phases_commit_and_validate_passes(self):
        result = run_all_phases(self.lake)
        self.assertTrue(all(r["status"] == "committed" for r in result["bronze"]))
        skipped = [r["build_id"] for r in result["silver"] + result["gold"] if r["status"] != "committed"]
        self.assertEqual(skipped, ["sb_20261110T032010Z_62bad93f", "gb_20261110T032015Z_edd1b412"])
        report = checks.summarize(run_checks(self.lake), checks.find_orphans(self.lake))
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["orphans"], [])

    def test_validate_detects_tampered_file(self):
        run_all_phases(self.lake)
        manifest = self.lake.manifests()[0]
        path = self.lake.data_path(manifest["outputs"][0]["files"][0]["path"])
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "rows/bytes/sha256"):
            checks.summarize(run_checks(self.lake), [])

    def test_validate_detects_pointer_to_uncommitted_build(self):
        run_all_phases(self.lake)
        pointer = self.lake.pointers()[0]
        self.lake.manifest_path(pointer["layer"], pointer["build_id"]).unlink()
        errors = checks.check_pointers(self.lake)
        self.assertTrue(any("not committed" in e for e in errors))

    def test_validate_detects_edge_with_missing_parent(self):
        run_all_phases(self.lake)
        bronze = [m for m in self.lake.manifests() if m["layer"] == "bronze"]
        for manifest in bronze:
            self.lake.manifest_path("bronze", manifest["build_id"]).unlink()
        self.assertTrue(any("not committed" in e for e in checks.check_lineage(self.lake)))

    def test_orphan_file_is_reported_not_failed(self):
        run_all_phases(self.lake)
        orphan = self.lake.root / "lake-silver" / "v1" / "stray.jsonl"
        orphan.write_text("{}", "utf-8")
        report = checks.summarize(run_checks(self.lake), checks.find_orphans(self.lake))
        self.assertEqual(report["orphans"], ["lake-silver/v1/stray.jsonl"])

    def test_pointer_update_refuses_uncommitted_target(self):
        with self.assertRaises(FileNotFoundError):
            phase.update_pointers("silver", self.lake)

    def test_rerun_is_idempotent(self):
        run_all_phases(self.lake)
        first = {p.name: p.read_bytes() for p in self.lake.root.rglob("*.jsonl")}
        run_all_phases(self.lake)
        second = {p.name: p.read_bytes() for p in self.lake.root.rglob("*.jsonl")}
        self.assertEqual(first, second)


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
        self.assertEqual(tasks["dp_validate"],
                         ["check_lineage", "check_manifests", "check_pointers", "find_orphans", "report"])
        self.assertEqual(tasks["dp_silver_transform"], ["build_silver", "plan_builds", "update_current"])
        self.assertEqual(tasks["dp_gold_build"], ["build_gold", "plan_builds", "update_current"])
