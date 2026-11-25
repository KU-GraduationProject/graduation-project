"""2차 A군 순수 로직 — 레지스트리 정합성·pair·변형 재현성·가드·heldout 부재. Docker/HTTP 없음."""
import contextlib
import importlib
import io
import os
import sys
import unittest

SCENARIOS_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if SCENARIOS_DIR not in sys.path:
    sys.path.insert(0, SCENARIOS_DIR)

from v2 import registry, timing, variants, netns  # noqa: E402
from v2 import run as v2run  # noqa: E402
from v2 import s1b_recon_scan as s1b, s2b_c2_beacon as s2b, s2d_internal_recon as s2d  # noqa: E402
from v2 import s2e_db_bulk_read as s2e, f1a_cpu_overload as f1a, f1c_oom_restart as f1c  # noqa: E402
from v2 import f3b_bad_env_config as f3b, c_b_short_load_spike as cb, c_d_normal_restart as cd  # noqa: E402
from v2 import c_l_broken_link as cl  # noqa: E402

A_GROUP = {  # id: (incident_class, threat, action, ideal, evidence)
    "s1_b_recon_scan": ("attack", "low", "NOTIFY", "NOTIFY", ["nginx_log"]),
    "s2_b_c2_beacon": ("attack", "high", "ISOLATE", "BLOCK_EGRESS", ["network"]),
    "s2_d_internal_recon": ("attack", "medium", "ISOLATE", "ISOLATE", ["network"]),
    "s2_e_db_bulk_read": ("attack", "high", "ISOLATE", "ISOLATE+KILL_SESSIONS", ["metric", "app_log"]),
    "f1_a_cpu_overload": ("failure", "medium", "THROTTLE", "THROTTLE", ["metric", "nginx_log"]),
    "f1_c_oom_restart": ("failure", "medium", "RESTART", "RESTART", ["metric"]),
    "f3_b_bad_env_config": ("failure", "high", "NOTIFY", "ROLLBACK", ["metric", "app_log"]),
    "c_b_short_load_spike": ("benign", "low", "NONE", "NONE", ["metric"]),
    "c_d_normal_restart": ("benign", "low", "NONE", "NONE", ["metric"]),
    "c_h_admin_backup": ("benign", "low", "NONE", "NONE", ["metric"]),
    "c_j_allowed_external_call": ("benign", "low", "NONE", "NONE", ["network"]),
    "c_l_broken_link": ("benign", "low", "NONE", "NONE", ["nginx_log"]),
}
PAIRS = {"c_b_short_load_spike": {"f1_a_cpu_overload", "s2_a_resource_theft"},
         "c_d_normal_restart": {"f1_c_oom_restart", "f3_a_bad_image_deploy", "f3_b_bad_env_config"},
         "c_h_admin_backup": {"f2_c_db_pool_exhaustion", "s2_e_db_bulk_read"},
         "c_j_allowed_external_call": {"s2_b_c2_beacon"},
         "c_l_broken_link": {"s1_b_recon_scan"}}


def row(sid):
    return next(r for r in registry.SCENARIO_REGISTRY_V2 if r["id"] == sid)


class RegistryBatch2(unittest.TestCase):
    def test_labels_match_spec_table(self):
        for sid, (cls, thr, act, ideal, ev) in A_GROUP.items():
            r = row(sid)
            self.assertEqual((r["incident_class"], r["threat_level"], r["expected_action"],
                              r["expected_action_ideal"], r["evidence"]), (cls, thr, act, ideal, ev), sid)
            self.assertEqual(r["batch"], 4)
            importlib.import_module(r["module"])

    def test_attack_ids(self):
        want = {"s1_b_recon_scan": "T1595.002", "s2_b_c2_beacon": "T1071.001",
                "s2_d_internal_recon": "T1046", "s2_e_db_bulk_read": "T1213.006"}
        for sid in A_GROUP:
            self.assertEqual(row(sid).get("attack_id"), want.get(sid), sid)

    def test_pairs(self):
        for sid, want in PAIRS.items():
            self.assertEqual(set(row(sid)["pair"]), want)
        for r in registry.SCENARIO_REGISTRY_V2:
            if "pair" in r:
                self.assertEqual(r["incident_class"], "benign")

    def test_validate_rejects_bad_pair_and_attack_id(self):
        base = [dict(row("s1_b_recon_scan")), dict(row("c_l_broken_link"))]
        bad = [dict(base[0]), dict(base[1], pair=["nope"])]
        with self.assertRaises(ValueError):
            registry._validate(bad)
        with self.assertRaises(ValueError):
            registry._validate([dict(base[0], attack_id="X1"), base[1]])
        with self.assertRaises(ValueError):
            registry._validate([dict(base[0], pair=["c_l_broken_link"]), base[1]])
        registry._validate(base)

    def test_all_a_group_dispatchable_and_dry_run(self):
        for sid in A_GROUP:
            self.assertIn(sid, v2run._MODULES)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(v2run.run(sid, dry_run=True), 0)


class VariantsBatch2(unittest.TestCase):
    def test_every_a_group_has_tuning_variants_and_reproducible(self):
        for sid in A_GROUP:
            vids = list(variants.VARIANT_SPECS[sid])
            self.assertTrue(vids, sid)
            for v in vids:
                a = variants.generate(sid, v, 3, specs=variants.VARIANT_SPECS)
                b = variants.generate(sid, v, 3, specs=variants.VARIANT_SPECS)
                self.assertEqual(a.params, b.params)

    def test_variant_axes_are_inject_params(self):
        import inspect
        for sid in A_GROUP:
            mod = importlib.import_module(row(sid)["module"])
            accepted = set(inspect.signature(mod.inject).parameters)
            for v, spec in variants.VARIANT_SPECS[sid].items():
                self.assertLessEqual(set(spec), accepted, f"{sid}/{v}")

    def test_variant_dry_run_without_heldout(self):
        saved = sys.modules.get("v2.heldout.variant_specs")
        sys.modules["v2.heldout.variant_specs"] = None   # heldout 폴더 부재 흉내
        try:
            self.assertIsNone(registry.load_heldout_specs())
            for sid in A_GROUP:
                v = list(variants.VARIANT_SPECS[sid])[0]
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(v2run.run(sid, True, v, 11), 0)
        finally:
            if saved is None:
                sys.modules.pop("v2.heldout.variant_specs", None)
            else:
                sys.modules["v2.heldout.variant_specs"] = saved


class TimingAndPlans(unittest.TestCase):
    def test_offsets(self):
        for pat in timing.TIME_PATTERNS:
            o = timing.offsets(50, 100, pat, seed=1)
            self.assertEqual(o, timing.offsets(50, 100, pat, seed=1))
            self.assertEqual(len(o), 50)
            self.assertEqual(o, sorted(o))
            self.assertTrue(all(0 <= x <= 100 for x in o))
        self.assertLessEqual(max(timing.offsets(30, 100, "burst")), 10)
        with self.assertRaises(ValueError):
            timing.offsets(1, 1, "nope")

    def test_s1b_one_source_scan_no_injection_payload(self):
        urls = s1b.build_urls(100, "http://h")
        self.assertEqual(len(set(urls)), 100)
        for u in urls:
            self.assertNotRegex(u, r"(?i)(\.\./|union|select|or%20|'|<script)")
        self.assertGreater(s1b.plan_scan("strong")["requests"], s1b.plan_scan("weak")["requests"])

    def test_cl_lower_volume_than_s1b(self):
        self.assertLess(cl.plan_requests("strong")["requests"], s1b.plan_scan("weak")["requests"])

    def test_beacon_small_periodic_and_owned_dest(self):
        p = s2b.plan_beacon("medium", 600)
        self.assertEqual(p["expected_beacons"], 20)
        self.assertLess(s2b.PAYLOAD_BYTES[1], 1024)
        self.assertIn("sink-b", s2b.DEST)
        from v2 import c_j_allowed_external_call as cj
        self.assertIn("sink-a", cj.DEST)
        script = s2b.beacon_script(p)
        compile(script, "<beacon>", "exec")
        for m in ("attack", "c2", "beacon", "threat"):
            self.assertNotIn(m, script.lower())

    def test_sidecar_argv(self):
        argv = netns.sidecar_argv("print(1)", "v2net-x", "b", "img")
        self.assertIn("container:b", argv)
        self.assertIn("--rm", argv)
        with self.assertRaises(ValueError):
            netns.sidecar_argv(" ", "n")

    def test_s2d_internal_only(self):
        for bad in (["1.2.3.4"], ["example.com"], ["db:5432"], [""]):
            with self.assertRaises(ValueError):
                s2d.plan_scan("weak", hosts=bad)
        p = s2d.plan_scan("weak", hosts=["db", "minio", "x"], ports=[1, 2])
        self.assertEqual(p["hosts"], ["db", "minio"])
        compile(s2d.scan_script(p), "<scan>", "exec")

    def test_s2e_read_only_guard(self):
        for bad in ("DELETE FROM t", "update t set a=1", "DROP TABLE t", "COPY t TO '/x'",
                    "create table x()", "TRUNCATE t", "grant all on t to u"):
            with self.assertRaises(ValueError):
                s2e.assert_read_only(bad)
        sql = s2e.scan_sql("plants")
        self.assertIn("READ ONLY", sql)
        s2e.assert_read_only(s2e.LIST_TABLES_SQL)
        with self.assertRaises(Exception):
            s2e.scan_sql('x"; drop table y; --')

    def test_f1a_cb_distinct(self):
        self.assertGreater(f1a.plan_load("weak")["concurrency"], 0)
        spike = cb.plan_spike("strong")
        self.assertLessEqual(spike["duration_seconds"], 60)
        self.assertLess(spike["concurrency"] * spike["duration_seconds"],
                        f1a.plan_load("medium")["concurrency"] * f1a.DEFAULT_DURATION_SECONDS)

    def test_f1c_limits_and_guards(self):
        mib = f1c.MIB
        self.assertEqual(f1c.plan_limit(400 * mib, "medium"), 300 * mib)
        self.assertEqual(f1c.plan_limit(10 * mib, "strong"), f1c.MIN_LIMIT_MIB * mib)
        with self.assertRaises(ValueError):
            f1c.assert_target_allowed("leafy-db")
        lim = f1c.capture_limits({"HostConfig": {"Memory": 512 * mib, "MemorySwap": 1024 * mib,
                                                 "RestartPolicy": {"Name": "unless-stopped"}}})
        f1c.assert_restartable(lim)
        self.assertIn(str(512 * mib), f1c.restore_sh("leafy-backend", lim))
        with self.assertRaises(ValueError):
            f1c.assert_restartable(dict(lim, restart_policy="no"))
        with self.assertRaises(ValueError):
            f1c.assert_restartable(dict(lim, memory=0))

    def test_f3b_override_only_env_no_image(self):
        y = f3b.bad_override_yaml("backend", "STORAGE_ENDPOINT")
        self.assertNotIn("image", y)
        self.assertNotIn("command", y)
        self.assertIn("STORAGE_ENDPOINT", y)
        for secret in ("JWT_SECRET_KEY_DEV", "DB_PASSWORD_DEV", "STORAGE_SECRET_KEY"):
            with self.assertRaises(ValueError):
                f3b.bad_override_yaml("backend", secret)
        argv = f3b.compose_argv(["a.yml"], ["o.yml"])
        self.assertIn("--no-build", argv)
        self.assertEqual(argv[argv.index("--pull") + 1], "never")
        self.assertNotIn("o.yml", f3b.restore_sh(".", ["a.yml"]))

    def test_cd_verify_same(self):
        before = {"Image": "sha:1", "Config": {"Cmd": ["a"], "Entrypoint": None, "Env": ["A=1"]}}
        after = dict(before, State={"Running": True, "Health": {"Status": "healthy"}})
        self.assertTrue(all(cd.verify_same(before, after).values()))
        self.assertFalse(cd.verify_same(before, dict(after, Image="sha:2"))["image_same"])
        with self.assertRaises(ValueError):
            cd.assert_target_allowed("leafy-minio")


if __name__ == "__main__":
    unittest.main()
