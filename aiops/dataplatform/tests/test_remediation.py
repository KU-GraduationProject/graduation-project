"""#77 gold.remediation_link (DEC-19, docs/data-platform/09): Bronze chunks -> Silver events -> Gold link."""
import json
import os
import sys
import tempfile
import unittest
from datetime import timedelta

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

import fixture_data as fx  # noqa: E402
from bronze.acquire import acquire  # noqa: E402
from bronze.plan import (REMEDIATION_CHUNK, ChunkPlanError, check_remediation_chunks, incident_window,  # noqa: E402
                         plan_incident, remediation_chunks, remediation_window)
from contracts import canonical, enums, schemas  # noqa: E402
from contracts.canonical import fmt_ts, ns_of, parse_ts  # noqa: E402
from gold.build import remediation_chunk_reasons, remediation_link  # noqa: E402
from gold.checks import GoldCheckError, check_build  # noqa: E402
from mock_sources.fixture_backend import FixtureSources, mock_transport  # noqa: E402
from orchestration import phases  # noqa: E402
from orchestration import validate as checks  # noqa: E402
from silver.build import coverage, coverage_inputs  # noqa: E402
from silver.normalize import Quarantine, rca_result, remediation_event  # noqa: E402
from storage.manifest import output_rows  # noqa: E402
from storage.store import LocalFsStore  # noqa: E402

ALERT = "DBConnectionLimit"
ANCHOR_RAW = "2026-11-10T03:00:20.512Z"
ANCHOR = parse_ts(ANCHOR_RAW)
WINDOW = (ANCHOR - timedelta(minutes=6), ANCHOR + timedelta(minutes=81))
RID = "3c1e9a7b5d2f4e60a8b1c9d7e5f3a201"
TIMING_KEYS = ("approval_requested_at", "approved_at", "action_started_at", "action_verified_at", "recovery_due_at",
               "recovery_started_at", "recovery_verified_at", "service_recovered_at", "restore_duration_sec",
               "approval_latency_sec", "action_duration_sec", "recovery_duration_sec", "mttr_sec",
               "service_recovery_sec")
DETAIL_NULL = ("link_basis", "action_type", "final_state", "approval_requested_at", "approved_at", "action_started_at",
               "action_verified_at", "recovery_due_at", "recovery_verified_at", "service_recovered_at", "approved_by",
               "mttr_sec", "approval_latency_sec")


def loki_row(job: str, body, ts_ns: int | None = None, labels: dict | None = None) -> dict:
    """A Bronze Loki row as Remediation's `_push_soc_event` would leave it."""
    line = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
    if labels is None:
        labels = {"job": job, "event": str(body.get("event", "unknown")), "status": str(body.get("status", "unknown"))}
        if body.get("alert"):
            labels["alert"] = body["alert"]
    ts_ns = ts_ns if ts_ns is not None else ns_of(parse_ts(body["timestamp"]))
    return {"bronze_id": "acq_x:0000:000000", "acquisition_id": "acq_x", "stream_class": "remediation_event",
            "stream_labels": canonical.canonical_str(labels), "entry_ts_ns": ts_ns, "line": line,
            "line_sha256": canonical.sha256_text(line), "record_key": canonical.loki_record_key(labels, ts_ns, line),
            "_schema_version": "1.0"}


def record_body(ts, event, state, rid=RID, alert=ALERT, active=ANCHOR_RAW, action="KILL_SESSIONS",
                targets=("fixture-pg17",), **timings):
    return {"timestamp": ts, "event": event, "status": state, "remediation_id": rid, "alert": alert,
            "action_type": action, "targets": list(targets), "state": state, "alert_active_at": active,
            **{k: timings.get(k) for k in TIMING_KEYS}}


def approved_body(ts, rid=RID, user="U0TEST", target="fixture-pg17"):
    return {"timestamp": ts, "event": "manual_approval_executed", "alert": ALERT, "target": target,
            "action_type": "KILL_SESSIONS", "approved_by": user, "source": "alert_triggered", "status": "SUCCESS",
            "result": "Success: done", "remediation_id": rid, "verified": True}


def silver(job, body, **kw) -> dict:
    return remediation_event(loki_row(job, body, **kw), {}).values


def rca(remediation_id=RID, handoff="approval_pending", rca_id="rca-1") -> dict:
    return {"rca_id": rca_id, "rca_time": "2026-11-10T03:01:28.604117Z", "handoff_status": handoff,
            "remediation_id": remediation_id}


DONE = dict(approval_requested_at="2026-11-10T03:01:29.204511+00:00", approved_at="2026-11-10T03:02:44.118206+00:00",
            action_started_at="2026-11-10T03:02:44.530912+00:00",
            action_verified_at="2026-11-10T03:02:47.296130+00:00", approval_latency_sec=74.914, mttr_sec=146.784)


def linked_events(final_state="VERIFIED", **timings):
    return [silver("aiops-remediation", record_body("2026-11-10T03:01:29.215804Z", "approval_requested",
                                                     "AWAITING_APPROVAL",
                                                     approval_requested_at=DONE["approval_requested_at"])),
            silver("aiops-remediation", record_body("2026-11-10T03:02:47.318044Z", "remediation_executed",
                                                     final_state, **{**DONE, **timings})),
            silver("aiops-timeline", approved_body("2026-11-10T03:02:47.331920Z"))]


# ---- Bronze ------------------------------------------------------------------------------

class RemediationPlanTest(unittest.TestCase):
    def test_window_is_anchor_minus_5m_pad_to_plus_80m_pad(self):
        start, end = remediation_window(fx.request())
        self.assertEqual((start, end), WINDOW)
        start, end = remediation_window({**fx.request(), "acquisition_padding_s": 0})
        self.assertEqual((start, end), (ANCHOR - timedelta(minutes=5), ANCHOR + timedelta(minutes=80)))

    def test_chunks_tile_the_window_without_gap_or_overlap(self):
        for pad, sizes in ((60, [15, 15, 15, 15, 15, 12]), (0, [15, 15, 15, 15, 15, 10]),
                           (300, [15, 15, 15, 15, 15, 15, 5]), (600, [15] * 7)):
            start, end = remediation_window({**fx.request(), "acquisition_padding_s": pad})
            chunks = remediation_chunks(start, end)
            self.assertEqual([(e - s) / timedelta(minutes=1) for s, e in chunks], sizes, pad)
            self.assertEqual((chunks[0][0], chunks[-1][1]), (start, end))
            for (_, end_i), (start_j, _) in zip(chunks, chunks[1:]):
                self.assertEqual(end_i, start_j)
            self.assertTrue(all(e - s <= REMEDIATION_CHUNK for s, e in chunks))
            check_remediation_chunks(chunks, start, end)

    def test_dq_b07_rejects_long_gapped_or_overlapping_chunks(self):
        start, end = WINDOW
        good = remediation_chunks(start, end)
        minute = timedelta(minutes=1)
        for bad in ([(start, start + 16 * minute)] + [(s, e) for s, e in good if s >= start + 16 * minute],
                    [good[0], (good[1][0] + minute, good[1][1])] + good[2:],
                    [good[0], (good[1][0] - minute, good[1][1])] + good[2:],
                    good[:-1]):
            with self.assertRaises(ChunkPlanError):
                check_remediation_chunks(bad, start, end)

    def test_plan_has_two_selectors_per_chunk(self):
        items = [i for i in plan_incident(fx.request(), fx.bindings_raw()) if i["stream_class"] == "remediation_event"]
        chunks = remediation_chunks(*WINDOW)
        self.assertEqual(len(items), 2 * len(chunks))
        self.assertEqual(sorted({(i["window_start"], i["window_end"]) for i in items}),
                         [(fmt_ts(s), fmt_ts(e)) for s, e in chunks])
        audit = '{alert="DBConnectionLimit",job="aiops-remediation"}'  # Pipeline `identity.selector` form
        timeline = ('{alert="DBConnectionLimit",job="aiops-timeline",event=~"remediation_decision_started|'
                    'manual_approval_executed|auto_remediation_completed|recovery_approval_required"}')
        self.assertEqual({(i["query_name"], i["query_text"]) for i in items},
                         {("remediation_audit", audit), ("remediation_timeline", timeline)})
        for item in items:
            self.assertEqual((item["scope_role"], item["source_system"], item["binding_sha256"],
                              set(item["scope_identity"].values()), item["preflight_selector"]),
                             ("global", "loki", None, {"UNKNOWN"}, item["query_text"]))
            self.assertEqual((item["start_ns"], item["end_ns"]),
                             (ns_of(parse_ts(item["window_start"])), ns_of(parse_ts(item["window_end"]))))
        self.assertEqual(len({i["acquisition_key"] for i in items}), len(items))
        labels = [phases.label(i) for i in plan_incident(fx.request(), fx.bindings_raw())]
        self.assertEqual(len(labels), len(set(labels)))  # one Airflow map name / local run per acquisition
        only = plan_incident({**fx.request(), "stream_classes": ["remediation_event"]}, fx.bindings_raw())
        self.assertEqual([i["acquisition_key"] for i in only], [i["acquisition_key"] for i in items])

    def test_plan_record_keeps_the_incident_window_under_a_stream_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            lake = LocalFsStore(tmp)
            phases.plan({**fx.request(), "stream_classes": ["remediation_event"]}, lake, fx.run_context())
            [plan] = lake.plans()
        _, _, (start, end) = incident_window(fx.request())
        self.assertEqual((plan["window_start"], plan["window_end"]), (fmt_ts(start), fmt_ts(end)))

    def test_only_open_chunks_are_reacquired(self):
        items = [i for i in plan_incident(fx.request(), fx.bindings_raw()) if i["stream_class"] == "remediation_event"]
        sources = FixtureSources()
        with tempfile.TemporaryDirectory() as tmp:
            store = LocalFsStore(tmp)

            def run(at):
                sources.now_ns = ns_of(parse_ts(at))
                context = fx.run_context(clock=fx.Clock(at), hex8=fx.Hex())
                return [acquire(i, store, context, transport=mock_transport(sources), page_delay_s=0) for i in items]

            first = run("2026-11-10T03:20:09.100000Z")
            acqs = {r["build_id"]: output_rows(store, store.read_manifest("bronze", r["build_id"]),
                                               "bronze.acquisition")[0] for r in first}
            closed = [a["window_closed"] for a in acqs.values()]
            self.assertEqual(closed, [True, True] + [False] * 10)  # only chunk 1 ended 600s before 03:20:09
            rows = [r for b in first for r in output_rows(store, store.read_manifest("bronze", b["build_id"]),
                                                          "bronze.loki_entry")]
            self.assertTrue(rows)
            self.assertTrue(all(r["entry_ts_ns"] <= sources.now_ns for r in rows))  # no entry from the future
            again = run("2026-11-10T04:32:00.100000Z")
            self.assertEqual([r["status"] == "reused" for r in again], [True, True] + [False] * 10)


# ---- Silver ------------------------------------------------------------------------------

class RemediationSilverTest(unittest.TestCase):
    def test_record_event(self):
        body = record_body("2026-11-10T03:02:47.318044Z", "remediation_executed", "VERIFIED", **DONE)
        norm = remediation_event(loki_row("aiops-remediation", body), {})
        v = norm.values
        self.assertEqual(norm.pk, loki_row("aiops-remediation", body)["record_key"])
        self.assertEqual((v["event_time"], v["event_time_source"], v["stream_job"], v["event"], v["status"],
                          v["alertname"], v["remediation_id"], v["action_type"], v["targets"], v["record_state"],
                          v["alert_active_at"], v["alert_active_at_raw"], v["approved_by"]),
                         ("2026-11-10T03:02:47.318044Z", "body_timestamp", "aiops-remediation", "remediation_executed",
                          "VERIFIED", ALERT, RID, "KILL_SESSIONS", ["fixture-pg17"], "VERIFIED",
                          "2026-11-10T03:00:20.512000Z", ANCHOR_RAW, None))
        self.assertEqual(json.loads(v["timings"]), {k: body[k] for k in TIMING_KEYS})
        self.assertEqual((json.loads(v["event_body"]), v["policy"], norm.flags), (body, None, set()))
        self.assertEqual(schemas.check_row("silver.remediation_event", schemas.project(
            "silver.remediation_event", {**v, "_schema_version": "1.0", "_dataset_version": "sb", "_run_id": "r",
                                         "_quality_flags": [], "_dup_count": 1, "_first_acquired_at": v["event_time"],
                                         "_last_acquired_at": v["event_time"]})), [])

    def test_manual_approval_executed(self):
        v = silver("aiops-timeline", approved_body("2026-11-10T03:02:47.331920Z"))
        self.assertEqual((v["stream_job"], v["approved_by"], v["result"], v["verified"], v["targets"],
                          v["record_state"], v["timings"], v["alert_active_at"], v["remediation_id"]),
                         ("aiops-timeline", "U0TEST", "Success: done", True, ["fixture-pg17"], None, None, None, RID))

    def test_policy_decision_has_no_key(self):
        body = {"timestamp": "2026-11-10T03:01:28.963540Z", "event": "policy_decision", "alert": ALERT,
                "source": "action", "status": "AWAITING_APPROVAL", "action_type": "KILL_SESSIONS",
                "outcome": "AWAITING_APPROVAL", "targets": ["fixture-pg17"], "ttl_seconds": None}
        v = silver("aiops-remediation", body)
        self.assertEqual((v["remediation_id"], v["record_state"], v["targets"]), (None, None, ["fixture-pg17"]))
        self.assertEqual(json.loads(v["policy"]), {"action_type": "KILL_SESSIONS", "outcome": "AWAITING_APPROVAL",
                                                   "targets": ["fixture-pg17"], "ttl_seconds": None})

    def test_block_event_reason(self):
        v = silver("aiops-remediation", {"timestamp": "2026-11-10T03:02:45.000000Z", "event": "capture_blocked",
                                         "status": "BLOCKED", "remediation_id": RID, "alert": ALERT,
                                         "action_type": "PAUSE", "reason": "capture_executor_unavailable",
                                         "targets": ["fixture-backend"]})
        self.assertEqual((v["reason"], v["record_state"], v["targets"]),
                         ("capture_executor_unavailable", None, ["fixture-backend"]))

    def test_body_timestamp_fallback(self):
        for stamp in (None, "not a time", "2026-11-10T03:02:47"):  # absent, garbage, no offset (C-4 rejects)
            body = approved_body("x")
            body["timestamp"] = stamp
            norm = remediation_event(loki_row("aiops-timeline", body, ts_ns=1794279767331920000), {})
            self.assertEqual((norm.values["event_time"], norm.values["event_time_source"], norm.flags),
                             ("2026-11-10T03:02:47.331920Z", "receiver_fallback", {"event_time_fallback"}), stamp)

    def test_unparsable_alert_active_at_is_null_not_guessed(self):
        v = silver("aiops-remediation", record_body("2026-11-10T03:02:47.318044Z", "approval_requested",
                                                     "AWAITING_APPROVAL", active="2026-11-10T03:00:20"))
        self.assertEqual((v["alert_active_at"], v["alert_active_at_raw"]), (None, "2026-11-10T03:00:20"))

    def test_quarantine(self):
        labels = {"job": "aiops-remediation", "event": "x", "status": "x", "alert": ALERT}
        for line, reason in (("not json", "invalid_json"), ("[1]", "not_object"),
                             ('{"timestamp": "2026-11-10T03:00:00Z"}', "missing_required_field")):
            with self.assertRaises(Quarantine) as ctx:
                remediation_event(loki_row("aiops-remediation", line, ts_ns=1, labels=labels), {})
            self.assertEqual(ctx.exception.reason, reason)

    def test_rca_result_1_1_keeps_remediation_id(self):
        row = next(r for r in fx.jsonl("11_bronze_loki_entry.jsonl") if r["stream_class"] == "rca_result")
        envelope = json.loads(row["line"])
        self.assertEqual(schemas.schema_version("silver.rca_result"), "1.1")
        self.assertEqual(schemas.schema_version("silver.remediation_event"), "1.0")
        for value, want in ((RID, RID), (None, None), (7, None)):
            line = json.dumps({**envelope, "remediation_id": value}, ensure_ascii=False)
            got = rca_result({**row, "line": line}, {}).values["remediation_id"]
            self.assertEqual(got, want, value)
        envelope.pop("remediation_id", None)
        self.assertIsNone(rca_result({**row, "line": json.dumps(envelope)}, {}).values["remediation_id"])

    def test_coverage_is_the_remediation_window_and_gathers_chunks(self):
        plan = fx.plan_record()
        cov = coverage("silver.remediation_event", plan)
        self.assertEqual((cov["window_start"], cov["window_end"]), tuple(fmt_ts(t) for t in WINDOW))
        self.assertEqual(coverage("silver.rca_result", plan)["window_start"], plan["window_start"])
        items = [i for i in plan_incident(fx.request(), fx.bindings_raw()) if i["stream_class"] == "remediation_event"]
        with tempfile.TemporaryDirectory() as tmp:
            store = LocalFsStore(tmp)
            context = fx.run_context(clock=fx.Clock("2026-11-18T00:00:00.000000Z"))
            refs = [acquire(i, store, context, transport=mock_transport(FixtureSources()), page_delay_s=0)
                    for i in items]
            other = dict(items[0], plan_id="incident:other", acquisition_key="k" * 32)
            acquire(other, store, context, transport=mock_transport(FixtureSources()), page_delay_s=0)
            self.assertEqual(coverage_inputs(store, cov), [r["manifest_id"] for r in refs])


# ---- Gold --------------------------------------------------------------------------------

class RemediationGoldTest(unittest.TestCase):
    def link(self, rca_row, events, reasons=()):
        return remediation_link(rca_row, events, list(reasons), ALERT, ANCHOR, WINDOW)

    def assert_no_detail(self, values):
        self.assertEqual({k: values[k] for k in DETAIL_NULL}, dict.fromkeys(DETAIL_NULL))
        self.assertEqual((values["targets"], values["execution_results"], values["block_events"]), ([], "[]", "[]"))
        self.assertEqual(values["policy_decision_link"], "unlinked_no_key")

    def test_linked(self):
        values, used = self.link(rca(), linked_events())
        self.assertEqual((values["link_status"], values["link_basis"], values["remediation_status"],
                          values["partial_reasons"], values["final_state"], values["action_type"], values["targets"],
                          values["approved_by"], values["policy_decision_link"]),
                         ("linked", "rca_remediation_id", "complete", [], "VERIFIED", "KILL_SESSIONS",
                          ["fixture-pg17"], "U0TEST", "unlinked_no_key"))
        self.assertEqual((values["approval_requested_at"], values["approved_at"], values["action_verified_at"],
                          values["recovery_due_at"], values["mttr_sec"], values["approval_latency_sec"]),
                         ("2026-11-10T03:01:29.204511Z", "2026-11-10T03:02:44.118206Z", "2026-11-10T03:02:47.296130Z",
                          None, 146.784, 74.914))
        self.assertEqual(json.loads(values["execution_results"]),
                         [{"target": "fixture-pg17", "status": "SUCCESS", "result": "Success: done", "verified": True}])
        self.assertEqual((values["remediation_window_start"], values["remediation_window_end"]),
                         tuple(fmt_ts(t) for t in WINDOW))
        self.assertEqual(len(used), 3)

    def test_no_remediation_id(self):
        values, used = self.link(rca(None, "notification_sent"), linked_events())
        self.assertEqual((values["link_status"], values["remediation_status"], values["handoff_status"], used),
                         ("no_remediation_id", "unlinked", "notification_sent", []))
        self.assert_no_detail(values)

    def test_events_not_found(self):
        values, used = self.link(rca("ffff"), linked_events())
        self.assertEqual((values["link_status"], values["remediation_status"], used), ("events_not_found", "unlinked", []))
        self.assert_no_detail(values)
        # only a timeline event, no record event -> still not found
        values, _ = self.link(rca(), [silver("aiops-timeline", approved_body("2026-11-10T03:02:47.331920Z"))])
        self.assertEqual(values["link_status"], "events_not_found")
        # a record event outside the remediation window does not count
        late = silver("aiops-remediation", record_body("2026-11-10T04:26:41.739522Z", "recovery_completed", "RECOVERED"))
        self.assertEqual(self.link(rca(), [late])[0]["link_status"], "events_not_found")

    def test_events_not_found_while_window_open_is_partial(self):
        for reasons in (["window_open"], ["acquisition_incomplete"]):
            values, _ = self.link(rca("ffff"), [], reasons)
            self.assertEqual((values["link_status"], values["remediation_status"], values["partial_reasons"]),
                             ("events_not_found", "partial", reasons))

    def test_cross_check_failed_keeps_details_null(self):
        previous = linked_events()
        previous[0] = silver("aiops-remediation", record_body("2026-11-10T02:54:41.602117Z", "approval_requested",
                                                               "AWAITING_APPROVAL", active="2026-11-10T02:54:30.208Z"))
        other_alert = linked_events()
        other_alert[1] = silver("aiops-remediation", record_body("2026-11-10T03:02:47.318044Z", "remediation_executed",
                                                                  "VERIFIED", alert="OtherAlert", **DONE))
        unparsable = linked_events()
        unparsable[1] = silver("aiops-remediation", record_body("2026-11-10T03:02:47.318044Z", "remediation_executed",
                                                                 "VERIFIED", active="garbage", **DONE))
        for events in (previous, other_alert, unparsable):
            values, used = self.link(rca(), events, ["window_open"])
            self.assertEqual((values["link_status"], values["remediation_status"], values["partial_reasons"], used),
                             ("cross_check_failed", "unlinked", [], []))
            self.assert_no_detail(values)

    def test_cross_check_compares_instants_not_strings(self):
        events = linked_events()
        events[1] = silver("aiops-remediation", record_body("2026-11-10T03:02:47.318044Z", "remediation_executed",
                                                             "VERIFIED", active="2026-11-10T12:00:20.512+09:00", **DONE))
        self.assertEqual(self.link(rca(), events)[0]["link_status"], "linked")

    def test_policy_decision_is_never_attached(self):
        policy = silver("aiops-remediation", {"timestamp": "2026-11-10T03:01:28.963540Z", "event": "policy_decision",
                                              "alert": ALERT, "source": "action", "status": "AWAITING_APPROVAL"})
        started = silver("aiops-timeline", {"timestamp": "2026-11-10T03:01:28.951207Z",
                                            "event": "remediation_decision_started", "alert": ALERT})
        keyed = silver("aiops-remediation", {"timestamp": "2026-11-10T03:01:29.230000Z", "event": "policy_decision",
                                             "alert": ALERT, "source": "action", "status": "AWAITING_APPROVAL",
                                             "alert_fingerprint": "8c1f0e7a9b3d2c45", "alert_starts_at": ANCHOR_RAW,
                                             "remediation_id": RID})  # #81 shape: keyed, still not linked in v1
        values, used = self.link(rca(), linked_events() + [policy, started, keyed])
        self.assertEqual((values["link_status"], values["policy_decision_link"]), ("linked", "unlinked_no_key"))
        self.assertEqual(keyed["remediation_id"], RID)  # kept in Silver
        self.assertNotIn(keyed["remediation_event_id"], [u["remediation_event_id"] for u in used])
        self.assertNotIn(policy["remediation_event_id"], [u["remediation_event_id"] for u in used])
        self.assertNotIn(started["remediation_event_id"], [u["remediation_event_id"] for u in used])
        # an RCA without remediation_id never borrows events by alert name or time
        values, used = self.link(rca(None, "approval_proposal_unconfirmed"), linked_events() + [policy])
        self.assertEqual((values["link_status"], used), ("no_remediation_id", []))

    def test_block_events(self):
        blocked = silver("aiops-remediation", {"timestamp": "2026-11-10T03:02:45.000000Z", "event": "capture_blocked",
                                               "status": "BLOCKED", "remediation_id": RID, "alert": ALERT,
                                               "reason": "capture_executor_unavailable"})
        events = linked_events("BLOCKED") + [blocked]
        values, _ = self.link(rca(), events)
        self.assertEqual(json.loads(values["block_events"]), [{"event": "capture_blocked",
                                                               "reason": "capture_executor_unavailable",
                                                               "event_time": "2026-11-10T03:02:45.000000Z"}])
        self.assertEqual((values["final_state"], values["remediation_status"]), ("BLOCKED", "complete"))

    def test_remediation_status(self):
        end = fmt_ts(WINDOW[1] + timedelta(seconds=1)).replace("Z", "+00:00")
        cases = [  # (final state, timings, chunk reasons) -> (status, reasons)
            ("VERIFIED", {}, [], ("complete", [])),
            ("VERIFIED", {}, ["window_open"], ("partial", ["window_open"])),
            ("VERIFIED", {}, ["acquisition_incomplete"], ("partial", ["acquisition_incomplete"])),
            ("RECOVERY_APPROVAL_REQUIRED", {}, [], ("partial", ["beyond_window"])),
            ("RECOVERY_PENDING", {}, ["window_open"], ("partial", ["window_open"])),  # still open: not decided yet
            ("RECOVERY_PENDING", {"recovery_due_at": end}, ["window_open"], ("partial", ["window_open", "beyond_window"])),
            ("RECOVERED", {}, [], ("complete", [])),
        ]
        for state, timings, reasons, want in cases:
            values, _ = self.link(rca(), linked_events(state, **timings), reasons)
            self.assertEqual((values["remediation_status"], values["partial_reasons"]), want, (state, timings, reasons))

    def test_chunk_reasons(self):
        chunks = remediation_chunks(*WINDOW)
        expected = [(q, fmt_ts(s), fmt_ts(e)) for s, e in chunks for q in ("remediation_audit", "remediation_timeline")]

        def acq(q, s, e, status="ok", closed=True):
            return {"query_name": q, "window_start": s, "window_end": e, "status": status, "window_closed": closed}

        full = [acq(*x) for x in expected]
        self.assertEqual(remediation_chunk_reasons(full, expected), [])
        self.assertEqual(remediation_chunk_reasons(full[:-1], expected), ["acquisition_incomplete"])
        self.assertEqual(remediation_chunk_reasons([], expected), ["acquisition_incomplete"])
        self.assertEqual(remediation_chunk_reasons(full[:-1] + [acq(*expected[-1], "failed")], expected),
                         ["acquisition_incomplete"])
        self.assertEqual(remediation_chunk_reasons(full[:-1] + [acq(*expected[-1], "empty_verified", False)], expected),
                         ["window_open"])
        # an open chunk re-acquired after it closed is closed; an older failure is superseded by the best status
        self.assertEqual(remediation_chunk_reasons(full + [acq(*expected[-1], "failed", False)], expected), [])
        self.assertEqual(remediation_chunk_reasons(full[:-1] + [acq(*expected[-1], "empty_unverified", False)],
                                                   expected), ["window_open", "acquisition_incomplete"])


class RemediationChecksTest(unittest.TestCase):
    """DQ-G10~G12 block the commit."""

    def rows(self):
        values, used = remediation_link(rca(), linked_events(), [], ALERT, ANCHOR, WINDOW)
        link = {"incident_id": "inc", "gold_build_id": "gb", "rca_id": "rca-1", "link_type": "post_hoc_same_alert",
                "rca_time": values["rca_time"], "fallback_reason": None}
        rows = {"gold.incident": [], "gold.incident_channel": [{"channel": c, "scope_role": "primary",
                                                                "status": "complete"} for c in enums.CHANNELS],
                "gold.evidence_log": [], "gold.evidence_metric": [], "gold.evidence_network_flow": [],
                "gold.rca_link": [link], "gold.remediation_link": [{"incident_id": "inc", "gold_build_id": "gb",
                                                                    **values}]}
        edges = [{"child_dataset": d, "child_key": "inc:rca-1"} for d in ("gold.rca_link", "gold.remediation_link")]
        context = {"alertname": ALERT, "anchor": ANCHOR, "events": {"rca-1": used}}
        return rows, edges, context

    def test_valid_rows_pass(self):
        rows, edges, context = self.rows()
        self.assertEqual(check_build(rows, edges, True, remediation=context), [])

    def test_g10_row_count_and_rca_set(self):
        rows, edges, context = self.rows()
        rows["gold.remediation_link"] = []
        with self.assertRaisesRegex(GoldCheckError, "DQ-G10"):
            check_build(rows, edges, True, remediation=context)
        rows, edges, context = self.rows()
        rows["gold.remediation_link"][0]["rca_id"] = "rca-2"
        edges.append({"child_dataset": "gold.remediation_link", "child_key": "inc:rca-2"})
        with self.assertRaisesRegex(GoldCheckError, "DQ-G10"):
            check_build(rows, edges, True, remediation=context)

    def test_g11_link_basis_and_details(self):
        for change in ({"link_basis": None}, {"link_basis": "heuristic_alertname_time"},
                       {"link_status": "events_not_found"}, {"policy_decision_link": "linked"}):
            rows, edges, context = self.rows()
            rows["gold.remediation_link"][0].update(change)
            with self.assertRaisesRegex(GoldCheckError, "DQ-G11", msg=str(change)):
                check_build(rows, edges, True, remediation=context)
        rows, edges, context = self.rows()
        rows["gold.remediation_link"][0].update(link_status="cross_check_failed", link_basis=None)
        with self.assertRaisesRegex(GoldCheckError, "DQ-G11"):  # details kept on a non-linked row
            check_build(rows, edges, True, remediation=context)

    def test_g12_every_record_event_matches_the_anchor(self):
        rows, edges, context = self.rows()
        bad = silver("aiops-remediation", record_body("2026-11-10T03:02:48.000000Z", "service_verification_checked",
                                                       "VERIFIED", active="2026-11-10T02:54:30.208Z"))
        context["events"]["rca-1"] = context["events"]["rca-1"] + [bad]
        with self.assertRaisesRegex(GoldCheckError, "DQ-G12"):
            check_build(rows, edges, True, remediation=context)


# ---- fixture and E2E ---------------------------------------------------------------------

class RemediationFixtureTest(unittest.TestCase):
    """The fixture history (09 §8): 03:20/03:40 builds with open chunks, 04:32 re-acquisition (09 §9.1)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.store = LocalFsStore(cls.tmp.name)
        cls.first, cls.current = fx.replay_fixture(cls.store)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def links(self, manifest):
        rows = output_rows(self.store, manifest, "gold.remediation_link")
        return [(r["handoff_status"], r["link_status"], r["remediation_status"], r["partial_reasons"], r["final_state"])
                for r in sorted(rows, key=lambda r: r["rca_time"])]

    def test_window_open_builds_then_reacquired_build(self):
        deferred = "deferred_source_aware_consumer_required"
        self.assertEqual(self.links(self.first), [
            (deferred, "no_remediation_id", "unlinked", [], None),
            ("approval_pending", "linked", "partial", ["window_open"], "VERIFIED"),
            ("approval_pending", "cross_check_failed", "unlinked", [], None),
            ("approval_pending", "linked", "partial", ["window_open"], "RECOVERY_PENDING")])
        self.assertEqual(self.links(self.current), [
            (deferred, "no_remediation_id", "unlinked", [], None),
            ("approval_pending", "linked", "complete", [], "VERIFIED"),
            ("approval_pending", "cross_check_failed", "unlinked", [], None),
            ("approval_pending", "linked", "partial", ["beyond_window"], "RECOVERY_APPROVAL_REQUIRED")])
        self.assertEqual(self.current["build_id"], fx.CURRENT_GOLD)

    def test_rows_match_rca_link_and_events_outside_the_window_are_not_acquired(self):
        rca_ids = [r["rca_id"] for r in output_rows(self.store, self.current, "gold.rca_link")]
        links = output_rows(self.store, self.current, "gold.remediation_link")
        self.assertEqual(sorted(r["rca_id"] for r in links), sorted(rca_ids))
        events = fx.jsonl("29_silver_remediation_event.jsonl")
        self.assertFalse([e for e in events if e["event"] == "recovery_completed"])  # 04:26, after the window
        self.assertFalse([e for e in events if e["event"] == "slack_notification_sent"])  # timeline filter
        edges = [e for e in output_rows(self.store, self.current, "lineage.edge")
                 if e["child_dataset"] == "gold.remediation_link"]
        by_parent = {d: sum(e["parent_dataset"] == d for e in edges) for d in ("silver.rca_result",
                                                                              "silver.remediation_event")}
        linked = {r["remediation_id"] for r in links if r["link_status"] == "linked"}
        self.assertEqual(by_parent, {"silver.rca_result": len(links),
                                     "silver.remediation_event": sum(e["remediation_id"] in linked for e in events)})


class RemediationE2ETest(unittest.TestCase):
    def test_chain_links_remediation_and_validate_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            lake = LocalFsStore(tmp)
            hex8, clock = fx.Hex(), fx.Clock("2026-11-18T01:00:00.000000Z")
            result = phases.run_all(fx.request(), lake, lambda t: fx.run_context(clock=clock, hex8=hex8, task_id=t),
                                    transport=mock_transport(FixtureSources()))
            gold = lake.read_manifest("gold", result["gold"][0]["build_id"])
            rows = sorted(output_rows(lake, gold, "gold.remediation_link"), key=lambda r: r["rca_time"])
            self.assertEqual([(r["link_status"], r["remediation_status"], r["partial_reasons"]) for r in rows],
                             [("no_remediation_id", "unlinked", []), ("linked", "complete", []),
                              ("cross_check_failed", "unlinked", []), ("linked", "partial", ["beyond_window"])])
            report = checks.summarize(checks.run_checks(lake), checks.find_orphans(lake))
            self.assertEqual((report["status"], report["orphans"]), ("passed", []))


if __name__ == "__main__":
    unittest.main()
