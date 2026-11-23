"""Track C — Gold tests (docs/data-platform/05 §5 ①~⑥) and real-time parity (60_realtime_parity.json)."""
import json
import os
import sys
import tempfile
import unittest
from collections import Counter

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

import fixture_data as fx  # noqa: E402
from contracts import pipeline_compat  # noqa: E402
from gold import render  # noqa: E402
from gold.build import build_gold, channel_status, plan_gold  # noqa: E402
from gold.checks import GoldCheckError, check_build  # noqa: E402
from lineage.trace import integrity, trace  # noqa: E402
from storage.manifest import output_rows  # noqa: E402
from storage.store import LocalFsStore  # noqa: E402

GOLD_FILES = ("gold.incident", "gold.incident_channel", "gold.evidence_log", "gold.evidence_metric",
              "gold.evidence_network_flow", "gold.rca_link", "lineage.edge")


class GoldTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.store = LocalFsStore(cls.tmp.name)
        cls.first, cls.current = fx.replay_fixture(cls.store)
        cls.rows = {d: output_rows(cls.store, cls.current, d) for d in GOLD_FILES}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    # ① fixture -> 30~35 + Gold edges, byte for byte (the replay clock returns the fixture instants)
    def test_current_build_equals_fixture(self):
        want = fx.manifest("gb_20261110T034045Z_124c3f4f")
        self.assertEqual(self.current, want)
        for dataset in GOLD_FILES:
            self.assertEqual(self.rows[dataset], fx.build_rows(dataset, want["build_id"]), dataset)

    def test_first_build_matches_fixture_manifest(self):
        want = fx.manifest("gb_20261110T032015Z_edd1b412")
        for key in ("build_id", "inputs", "quality", "build_status", "coverage_id", "supersedes"):
            self.assertEqual(self.first[key], want[key], key)
        self.assertEqual([(o["dataset"], o["rows"]) for o in self.first["outputs"]],
                         [(o["dataset"], o["rows"]) for o in want["outputs"]])

    # ② rendered lines = existing Pipeline functions
    def test_rendered_lines_match_realtime_parity(self):
        parity = fx.load_json("60_realtime_parity.json")
        self.assertEqual({r["evidence_id"]: r["rendered_line"] for r in self.rows["gold.evidence_log"]},
                         parity["rendered_log_lines"])
        self.assertEqual({r["evidence_id"]: r["rendered_line"] for r in self.rows["gold.evidence_metric"]},
                         parity["rendered_metric_lines"])
        self.assertEqual({r["evidence_id"]: r["rendered_line"] for r in self.rows["gold.evidence_network_flow"]},
                         parity["rendered_flow_lines"])

    def test_ports_equal_pipeline_functions(self):
        log_line = pipeline_compat.log_line()
        for name in ("20_silver_db_log.jsonl", "21_silver_app_log.jsonl"):
            for row in fx.jsonl(name):
                entry = {"labels": json.loads(row["stream_labels"]), "line": row["body"]}
                self.assertEqual(render.render_log_line(entry["labels"], entry["line"]), log_line.render_log_line(entry))
        section = pipeline_compat.load("prompt.network_section")
        events = []
        for row in fx.jsonl("22_silver_network_event.jsonl"):
            event = {k: row[k] for k in ("src_service", "dst_service", "dst_ip", "dst_port", "protocol", "event_type",
                                         "connection_state", "app_protocol", "bytes_sent", "bytes_received",
                                         "duration_ms", "timestamp")}
            events.append(event)
        early = {**events[0], "event_type": "connection_threshold", "observer_meta": {"bytes_threshold": 4096}}
        events.append(early)
        policy = pipeline_compat.policy_evaluator()
        ours = render.aggregate_flows(events)
        theirs = section._aggregate(events)
        self.assertEqual([k for k, _ in ours], [k for k, _ in theirs])
        self.assertEqual([render.flow_line(st, policy) for _, st in ours],
                         [section._flow_line(k, st, policy) for k, st in theirs])

    # ③ host db network: target field absent -> unavailable, skipped 2
    def test_host_network_is_unavailable(self):
        primary = next(c for c in self.rows["gold.incident_channel"]
                       if c["scope_role"] == "primary" and c["channel"] == "network")
        self.assertEqual((primary["status"], primary["status_reason"], primary["skipped"],
                          json.loads(primary["skipped_reasons"]), primary["quarantined"]),
                         ("unavailable", "host_target_field_absent", 2, {"target_unresolvable": 2}, 1))

    # ④ many-to-many: the same Silver events count for primary and feed the related flow
    def test_same_silver_event_feeds_related_flow(self):
        flow_parents = {e["parent_key"] for e in self.rows["lineage.edge"]
                        if e["child_dataset"] == "gold.evidence_network_flow"}
        self.assertEqual(flow_parents, {r["network_event_id"] for r in fx.jsonl("22_silver_network_event.jsonl")})
        primary = next(c for c in self.rows["gold.incident_channel"]
                       if c["scope_role"] == "primary" and c["channel"] == "network")
        self.assertEqual(primary["rows_in_window"], 2)

    # ⑤ rebuild -> new gold_build_id, same evidence ids, previous build preserved
    def test_rebuild_keeps_evidence_ids(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = LocalFsStore(tmp.name)
        _, current = fx.replay_fixture(store)
        self.assertIsNone(plan_gold(store, fx.plan_record()))  # same inputs: no-op
        todo = {"incident": fx.plan_record(), "silver_inputs": {}, "acquisitions": current["inputs"][7:]}
        for mid in current["inputs"][:7]:
            built = store.read_manifest("silver", mid.removeprefix("mf_"))
            todo["silver_inputs"][fx.main_dataset(built)] = [mid]
        result = build_gold(todo["incident"], todo["silver_inputs"], todo["acquisitions"], store,
                            fx.run_context(hex8=fx.Hex(["0000abcd"]), clock=fx.Clock("2026-11-11T00:00:00.000000Z")))
        rebuilt = store.read_manifest("gold", result["build_id"])
        self.assertNotEqual(rebuilt["build_id"], current["build_id"])
        ids = lambda m: sorted(r["evidence_id"] for d in ("gold.evidence_log", "gold.evidence_metric",
                                                          "gold.evidence_network_flow") for r in output_rows(store, m, d))
        self.assertEqual(ids(rebuilt), ids(current))
        self.assertIsNotNone(store.read_manifest("gold", current["build_id"]))
        self.assertEqual(rebuilt["supersedes"], current["manifest_id"])

    # ⑥ trace(evidence) reaches Bronze rows, the acquisition query and its run
    def test_trace_reaches_bronze_acquisition_and_run(self):
        flow = self.rows["gold.evidence_network_flow"][0]
        graph = trace(self.store, "gold.evidence_network_flow", flow["evidence_id"], self.current["build_id"])
        self.assertEqual({b["bronze_id"] for b in graph["bronze"]},
                         {"acq_20261110T032001Z_ac094d07:0000:000000", "acq_20261110T032001Z_ac094d07:0000:000001",
                          "acq_20261110T032004Z_61c0d08d:0000:000000", "acq_20261110T032004Z_61c0d08d:0000:000001"})
        queries = {a["query_text"] for a in graph["acquisitions"].values()}
        self.assertIn('{log_type="network", src_service="backend"} | json | observer="network-observer" and '
                      'observer_instance="fixture-gc-backend-netns"', queries)
        self.assertIn(fx.FIRST_RUN, graph["runs"])
        self.assertTrue(all(e["child_version"] in (self.current["build_id"], "sb_20261110T032010Z_06fac1f8")
                            for e in graph["edges"]))

    def test_lineage_integrity(self):
        self.assertEqual(integrity(self.store, require_runs=False), [])

    def test_overall_status_and_counts(self):
        incident = self.rows["gold.incident"][0]
        self.assertEqual((incident["overall_status"], incident["evidence_count"], incident["rca_count"],
                          incident["transport_check_status"], incident["transport_loss_suspected"]),
                         ("partial", 12, 1, "empty_unverified", False))
        self.assertEqual(Counter(e["relation"] for e in self.rows["lineage.edge"]),
                         {"selected_from": 10, "aggregated_from": 43, "linked_from": 1, "anchored_on": 1})


class ChannelRuleTest(unittest.TestCase):
    """04 §4 rules on synthetic inputs (the fixture covers rules 2, 4 and 6)."""

    def status(self, bests, in_window=0, matched=0, skipped=None, identity="resolved", runtime="container"):
        acqs = [{"query_name": q, "status_reason": None} for q in bests]
        return channel_status(identity, bests, acqs, in_window, matched, Counter(skipped or {}), runtime)

    def test_rules(self):
        self.assertEqual(self.status({"logs": "ok"}, identity="ambiguous_source"), ("unavailable", "ambiguous_source"))
        self.assertEqual(self.status({"a": "failed", "b": "source_mismatch"})[0], "failed")
        self.assertEqual(self.status({"a": "ok", "b": "source_mismatch"}, 3, 3), ("partial", "source_mismatch"))
        self.assertEqual(self.status({"a": "ok", "b": "truncated"}, 3, 3), ("partial", "truncated"))
        self.assertEqual(self.status({"a": "ok", "b": "scope_unavailable"}, 3, 3)[0], "partial")
        self.assertEqual(self.status({"a": "ok"}, 3, 3), ("complete", None))
        self.assertEqual(self.status({"a": "ok", "b": "empty_verified"}), ("complete_empty", None))
        self.assertEqual(self.status({"a": "empty_unverified", "b": "empty_verified"}), ("unavailable", "scope_unverified"))
        self.assertEqual(self.status({"a": "empty_unverified", "b": "ok"}, 2, 2), ("complete", None))  # src/dst
        self.assertEqual(self.status({"a": "ok"}, 2, 0, {"runtime_mismatch": 2}), ("unavailable", "runtime_mismatch"))

    def test_unresolved_identity_blocks_evidence(self):
        rows = {"gold.incident": [], "gold.incident_channel": [], "gold.evidence_log": [{"evidence_id": "x",
                "rendered_line": "a", "selected_for_prompt": False, "is_priority": False, "scope_role": "primary"}],
                "gold.evidence_metric": [], "gold.evidence_network_flow": [], "gold.rca_link": []}
        with self.assertRaises(GoldCheckError):
            check_build(rows, [], resolved=False)


if __name__ == "__main__":
    unittest.main()
