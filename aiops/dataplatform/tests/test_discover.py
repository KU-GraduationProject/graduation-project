"""Track D follow-up — `dp_incident_discover` over mock Loki `aiops-llm` entries (05 §5·§6). Airflow 불필요.

실행 (aiops/dataplatform 디렉터리에서):
    python -m unittest tests.test_discover -v     # 또는 discover -s tests
"""
import json
import os
import sys
import tempfile
import unittest
from datetime import timedelta

import httpx

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

import fixture_data as fx  # noqa: E402
from bronze.plan import plan_incident  # noqa: E402
from mock_sources.fixture_backend import FixtureSources, mock_transport  # noqa: E402
from orchestration import discover as dsc  # noqa: E402
from orchestration import phases  # noqa: E402
from orchestration import validate as checks  # noqa: E402
from storage.store import LocalFsStore  # noqa: E402

T = dsc.parse_ts
ENDPOINTS = {"loki": "http://mock-loki", "prometheus": "http://mock-prom"}
# fixture alert starts 03:00:20.512 -> acquisition window ends 03:06:20.512 -> due at +10 min
READY = T("2026-11-10T03:16:20.512Z")
FIXTURE_INCIDENT = "inc_3f9a00917bce9babb36e68f4"
RELATED = [{"match": {"site": "fixture-gc", "service": "db"},
            "related_scopes": fx.request()["related_scopes"]}]


def settings(**over):
    base = {"window_s": 900, "max_windows": 8, "lookback_s": 3600, "ingest_delay_s": 60, "page_limit": 500,
            "max_pages": 20, "page_delay_s": 0, "start": None, "related": []}
    return {**base, **over}


def fixture_envelope() -> tuple[dict, dict]:
    sources = FixtureSources()
    rows = sources._loki_rows('{job="aiops-llm"}')
    assert len(rows) == 1
    _, labels, line, _ = rows[0]
    return labels, json.loads(line)


class DiscoverTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.lake = LocalFsStore(self.tmp.name)
        self.sources = FixtureSources()

    def tearDown(self):
        self.tmp.cleanup()

    def run_discover(self, now, transport=None, scan_range=None, **over):
        return dsc.discover(self.lake, now, settings(**over), transport or mock_transport(self.sources), ENDPOINTS,
                            scan_range=scan_range, sleep=lambda s: None)

    def add_alert(self, starts_at: str, entry_at: str, **labels):
        """Push-free injection: one more RCA envelope only the mock Loki answers."""
        stream, env = fixture_envelope()
        env = {**env, "alert_starts_at": starts_at, "alert_labels": {**env["alert_labels"], **labels}}
        self.sources.add_loki_entry(dsc._ns(T(entry_at)), {**stream, **{k: v for k, v in labels.items() if k in stream}},
                                    json.dumps(env, ensure_ascii=False))

    def loki_calls(self):
        return [c for p, c in self.sources.calls if p == "/loki/api/v1/query_range"]

    # ---- discovery and the closed-window delay ----------------------------------------
    def test_fixture_incident_waits_for_window_end_plus_10m(self):
        start = T("2026-11-10T02:50:00Z")
        first = self.run_discover(READY - timedelta(seconds=1), scan_range=(start, start + timedelta(minutes=30)))
        self.assertEqual((first["due"], first["pending"], first["stats"]["new_incidents"]), ([], 1, 1))
        second = self.run_discover(READY, scan_range=(start, start + timedelta(minutes=30)))
        self.assertEqual([d["trigger_run_id"] for d in second["due"]], [f"discover__{FIXTURE_INCIDENT}"])
        self.assertEqual(second["stats"]["new_incidents"], 0)  # already pending, not re-added

    def test_discovered_request_reproduces_fixture_plan(self):
        """With the related-scope rule the request plans the same incident and binding set as the fixture."""
        start = T("2026-11-10T02:50:00Z")
        due = self.run_discover(READY, scan_range=(start, start + timedelta(minutes=30)), related=RELATED)["due"]
        request = due[0]["conf"]
        self.assertEqual((request["trigger"], request["expected_incident_id"]), ("discover", FIXTURE_INCIDENT))
        self.assertEqual(request["alert"], {k: fx.request()["alert"][k] for k in request["alert"]})
        ours, fixture = plan_incident(request, phases.bindings_raw()), plan_incident(fx.request(), phases.bindings_raw())
        self.assertEqual({i["plan_binding_sha256"] for i in ours}, {i["plan_binding_sha256"] for i in fixture})
        self.assertEqual(sorted(i["acquisition_key"] for i in ours), sorted(i["acquisition_key"] for i in fixture))

    def test_without_related_rule_scope_is_alert_identity_only(self):
        start = T("2026-11-10T02:50:00Z")
        request = self.run_discover(READY, scan_range=(start, start + timedelta(minutes=30)))["due"][0]["conf"]
        self.assertEqual(request["scope_policy"], "alert_identity_only")
        self.assertNotIn("related_scopes", request)

    # ---- idempotency --------------------------------------------------------------------
    def test_triggered_once_even_when_rescanned_or_repeated(self):
        start, end = T("2026-11-10T02:50:00Z"), T("2026-11-10T03:20:00Z")
        self.add_alert("2026-11-10T03:00:20.512Z", "2026-11-10T03:05:00Z")  # repeat envelope, same alert
        due = self.run_discover(READY, scan_range=(start, end))["due"]
        self.assertEqual(len(due), 1)
        self.assertEqual(dsc.mark_triggered(self.lake, due, READY, "run-1"), [FIXTURE_INCIDENT])
        again = self.run_discover(READY + timedelta(hours=1), scan_range=(start, end))
        self.assertEqual((again["due"], again["pending"]), ([], 0))
        marker = json.loads(dsc.triggered_path(self.lake, FIXTURE_INCIDENT).read_text("utf-8"))
        self.assertEqual(marker["discover_run_id"], "run-1")
        dsc.mark_triggered(self.lake, due, READY + timedelta(hours=2), "run-2")  # write-once
        self.assertEqual(json.loads(dsc.triggered_path(self.lake, FIXTURE_INCIDENT).read_text("utf-8")), marker)

    def test_incident_with_existing_plan_is_not_triggered(self):
        """A manual dp_bronze_acquire run already planned the incident."""
        self.lake.write_plan({"incident_id": FIXTURE_INCIDENT, "plan_id": f"incident:{FIXTURE_INCIDENT}"})
        start = T("2026-11-10T02:50:00Z")
        result = self.run_discover(READY, scan_range=(start, start + timedelta(minutes=30)))
        self.assertEqual((result["due"], result["stats"]["new_incidents"]), ([], 0))

    # ---- injected aiops-llm entries, cursor and load limits -------------------------------
    def test_injected_alerts_and_non_alert_lines(self):
        self.add_alert("2026-11-12T01:00:00Z", "2026-11-12T01:00:40Z", alertname="HighCPU", severity="warning")
        self.add_alert("2026-11-12T01:20:00Z", "2026-11-12T01:20:30Z", alertname="HighMemory")
        stream, _ = fixture_envelope()
        self.sources.add_loki_entry(dsc._ns(T("2026-11-12T01:10:00Z")), stream, "periodic scan: not an envelope")
        now = T("2026-11-12T01:31:00Z")  # HighCPU due at 01:16, HighMemory at 01:36
        result = self.run_discover(now, start="2026-11-12T00:55:00Z")
        self.assertEqual(result["stats"]["skipped_lines"], 1)
        self.assertEqual([d["conf"]["alert"]["labels"]["alertname"] for d in result["due"]], ["HighCPU"])
        self.assertEqual(result["pending"], 1)
        self.assertEqual(result["scanned_until"], "2026-11-12T01:30:00.000000Z")  # now - ingest delay

    def test_scan_windows_are_bounded_and_read_only(self):
        now = T("2026-11-12T12:00:00Z")
        first = self.run_discover(now, start="2026-11-12T00:00:00Z", window_s=3600, max_windows=3)
        calls = self.loki_calls()
        self.assertEqual(len(calls), 3)
        for c in calls:
            self.assertEqual(c["query"], '{job="aiops-llm"}')
            self.assertLessEqual(int(c["end"]) - int(c["start"]), 15 * 60 * 10**9)  # window_s capped at 15 min
        self.assertEqual(first["scanned_until"], "2026-11-12T00:45:00.000000Z")
        self.assertTrue(all(p.startswith(("/loki/api/v1/", "/api/v1/")) and "push" not in p for p, _ in self.sources.calls))
        second = self.run_discover(now, window_s=900, max_windows=2)  # resumes from the cursor
        self.assertEqual(second["scanned_until"], "2026-11-12T01:15:00.000000Z")

    def test_paging_reads_every_entry(self):
        for minute in (1, 2, 3):
            self.add_alert(f"2026-11-12T02:0{minute}:00Z", f"2026-11-12T02:0{minute}:30Z", alertname=f"A{minute}")
        result = self.run_discover(T("2026-11-12T03:00:00Z"), page_limit=1,
                                   scan_range=(T("2026-11-12T02:00:00Z"), T("2026-11-12T02:15:00Z")))
        self.assertEqual(result["stats"]["new_incidents"], 3)
        self.assertGreaterEqual(len(self.loki_calls()), 3)

    def test_failed_window_keeps_cursor_before_it(self):
        def fault(request, n):
            return httpx.Response(503) if n == 2 else None
        result = self.run_discover(T("2026-11-12T02:00:00Z"), transport=mock_transport(self.sources, fault),
                                   start="2026-11-12T00:00:00Z", max_windows=4)
        self.assertEqual(result["stats"]["windows"], 1)
        self.assertIn("api_error", result["stats"]["error"])
        self.assertEqual(result["scanned_until"], "2026-11-12T00:15:00.000000Z")

    # ---- end to end ---------------------------------------------------------------------
    def test_discovered_incident_runs_the_chain_and_validates(self):
        start = T("2026-11-10T02:50:00Z")
        due = self.run_discover(READY, scan_range=(start, start + timedelta(minutes=30)), related=RELATED)["due"]
        clock, hex8 = fx.Clock("2026-11-18T01:00:00.000000Z"), fx.Hex()
        result = phases.run_all(due[0]["conf"], self.lake,
                                lambda task: fx.run_context(clock=clock, hex8=hex8, task_id=task),
                                transport=mock_transport(self.sources))
        self.assertEqual((result["incident_id"], len(result["bronze"])), (FIXTURE_INCIDENT, 16))
        dsc.mark_triggered(self.lake, due, READY, "run-1")
        report = checks.summarize(checks.run_checks(self.lake), checks.find_orphans(self.lake))
        self.assertEqual((report["status"], report["orphans"]), ("passed", []))  # discover state is not an orphan

    def test_daily_validate_passes_on_an_empty_lake(self):
        """The daily dp_validate run may come before any build."""
        report = checks.summarize(checks.run_checks(self.lake), checks.find_orphans(self.lake))
        self.assertEqual(report["status"], "passed")


if __name__ == "__main__":
    unittest.main()
