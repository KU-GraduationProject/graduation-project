"""실행 기록 ↔ pipeline 컨텍스트 짝짓기 (fixtures.pair_context / build_fixtures_from_contexts)."""
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from v2 import fixtures

T0 = datetime(2026, 11, 1, 5, 0, 0, tzinfo=timezone.utc)


def run(sid, start_min, end_min, status="ok"):
    return {"scenario_id": sid, "variant_id": None, "seed": None, "status": status,
            "started_at": (T0 + timedelta(minutes=start_min)).isoformat(),
            "ended_at": (T0 + timedelta(minutes=end_min)).isoformat()}


def at(minutes):
    return (T0 + timedelta(minutes=minutes)).isoformat()


class TestPairing(unittest.TestCase):
    def test_pair_window_grace_and_ambiguity(self):
        runs = [run("f2_a_minio_outage", 0, 3), run("s1_c_login_bruteforce", 20, 22),
                run("s1_a_input_attack", 21, 23), run("f1_b_memory_leak", 40, 45, status="error")]
        self.assertEqual(fixtures.pair_context(runs, at(1))[0]["scenario_id"], "f2_a_minio_outage")
        self.assertEqual(fixtures.pair_context(runs, at(6), grace_seconds=300)[0]["scenario_id"], "f2_a_minio_outage")
        self.assertEqual(fixtures.pair_context(runs, at(9), grace_seconds=300), (None, "no_run"))
        self.assertEqual(fixtures.pair_context(runs, at(21.5)), (None, "ambiguous_run"))
        self.assertEqual(fixtures.pair_context(runs, at(41)), (None, "no_run"))   # 실패한 실행은 쓰지 않는다

    def test_build_from_contexts_rejects_answer_keys(self):
        ok = {"received_at": at(1), "alert": {"labels": {"alertname": "MinioDown"}, "startsAt": at(0.5)},
              "container": "leafy-minio", "rule": None, "metrics": {}, "logs": [], "log_query": None,
              "network": None, "builder": "v2", "identity_status": "resolved"}
        bad = dict(ok, received_at=at(2), metrics={"threat_level": "high"})
        with tempfile.TemporaryDirectory() as d:
            ctx_dir = os.path.join(d, "ctx")
            os.makedirs(ctx_dir)
            for name, c in (("a.json", ok), ("b.json", bad)):
                with open(os.path.join(ctx_dir, name), "w", encoding="utf-8") as fh:
                    json.dump(c, fh)
            runs = os.path.join(d, "runs.jsonl")
            r = run("f2_a_minio_outage", 0, 3)
            fixtures.append_run_record(r["scenario_id"], "full-stop", 3, T0, T0 + timedelta(minutes=3), "ok", runs)
            rows = fixtures.build_fixtures_from_contexts(ctx_dir, runs, os.path.join(d, "out"))
            self.assertIsNotNone(rows[0]["fixture"])
            self.assertIsNone(rows[1]["fixture"])
            self.assertTrue(rows[1]["reason"].startswith("rejected"))
            with open(rows[0]["fixture"], encoding="utf-8") as fh:
                fx = json.load(fh)
        self.assertEqual((fx["scenario_id"], fx["variant_id"], fx["seed"]), ("f2_a_minio_outage", "full-stop", 3))
        self.assertEqual(set(fx["observations"]), set(fixtures.OBSERVATION_KEYS))   # builder 등 부가 키 제외
        self.assertEqual(fx["captured_at"], at(1))


if __name__ == "__main__":
    unittest.main()
