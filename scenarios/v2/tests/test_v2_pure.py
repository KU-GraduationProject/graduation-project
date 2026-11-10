"""
scenarios-v2 배치 ① 순수 로직 단위 테스트 (Docker/HTTP 불필요).
런타임 주입(inject)·cleanup 은 Docker/Loki 가 필요해 여기서 검증하지 않는다(UNVERIFIED).

탐지 룰은 팀원(룰 작성자) 몫이라, 테스트는 룰 이름·임계값에 의존하지 않는다.
강도(strength)·안전 가드(OOM 0.94)만 검증한다.
"""

import ast
import os
import subprocess
import sys
import tempfile
import types
import unittest

SCENARIOS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if SCENARIOS_DIR not in sys.path:
    sys.path.insert(0, SCENARIOS_DIR)

from v2 import registry
from v2 import f2a_minio_outage as f2a
from v2 import f1b_memory_leak as f1b
from v2 import s1a_input_attack as s1a
from v2 import s1c_login_bruteforce as s1c
from v2 import run as v2run
from v2 import s2a_resource_theft as s2a
from v2 import f2c_db_pool_exhaustion as f2c
from v2 import f3a_bad_image_deploy as f3a
from v2 import controls
from v2 import supervisor
from v2 import fixtures
from v2 import variants

_MISSING = object()


class TestRegistry(unittest.TestCase):
    def test_validation_passes(self):
        registry._validate()  # 예외 없어야 함

    def test_expected_action_in_policy(self):
        for row in registry.SCENARIO_REGISTRY_V2:
            self.assertIn(row["expected_action"], registry.POLICY_ACTIONS)

    def test_evidence_channels_valid(self):
        for row in registry.SCENARIO_REGISTRY_V2:
            for ch in row["evidence"]:
                self.assertIn(ch, registry.EVIDENCE_CHANNELS)

    def test_no_rule_names_in_registry(self):
        # 레지스트리는 탐지 룰 이름을 담지 않는다(역할 분리).
        self.assertFalse(any("detection" in row for row in registry.SCENARIO_REGISTRY_V2))

    def test_unique_ids(self):
        ids = [r["id"] for r in registry.SCENARIO_REGISTRY_V2]
        self.assertEqual(len(ids), len(set(ids)))

    def test_batch1_has_four(self):
        b1 = [r for r in registry.SCENARIO_REGISTRY_V2 if r["batch"] == 1]
        self.assertEqual(len(b1), 4)

    def test_rejects_bad_action(self):
        bad = [{"id": "x", "expected_action": "KILL", "module": None, "external_tool": None}]
        with self.assertRaises(ValueError):
            registry._validate(bad)

    def test_rejects_bad_incident_class(self):
        bad = [{"id": "x", "expected_action": "NONE", "incident_class": "maybe",
                "module": None, "external_tool": None}]
        with self.assertRaises(ValueError):
            registry._validate(bad)

    def test_every_row_has_incident_class(self):
        for r in registry.SCENARIO_REGISTRY_V2:
            self.assertIn(r["incident_class"], registry.INCIDENT_CLASSES, r["id"])

    def test_rejects_bad_evidence(self):
        bad = [{"id": "x", "expected_action": "NONE", "evidence": ["bogus"],
                "module": None, "external_tool": None}]
        with self.assertRaises(ValueError):
            registry._validate(bad)


class TestHeldoutOptional(unittest.TestCase):
    def _with_modules(self, mapping):
        saved = {k: sys.modules.get(k, _MISSING) for k in mapping}
        sys.modules.update(mapping)
        return saved

    def _restore(self, saved):
        for k, v in saved.items():
            if v is _MISSING:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v

    def test_absent_is_silent(self):
        # heldout 폴더가 없는 저장소(기본 상태) — 예외 없이 None
        saved = self._with_modules({"v2.heldout": None, "v2.heldout.variant_specs": None})
        try:
            self.assertIsNone(registry.load_heldout_specs())
        finally:
            self._restore(saved)

    def test_present_is_loaded(self):
        pkg = types.ModuleType("v2.heldout")
        mod = types.ModuleType("v2.heldout.variant_specs")
        mod.HELDOUT_VARIANT_SPECS = {"x": {"v": {}}}
        pkg.variant_specs = mod
        saved = self._with_modules({"v2.heldout": pkg, "v2.heldout.variant_specs": mod})
        try:
            self.assertEqual(registry.load_heldout_specs(), {"x": {"v": {}}})
        finally:
            self._restore(saved)


class TestF2a(unittest.TestCase):
    def test_healthy_requires_running(self):
        self.assertFalse(f2a.is_healthy({"Running": False, "Health": {"Status": "healthy"}}))

    def test_healthy_with_healthcheck(self):
        self.assertTrue(f2a.is_healthy({"Running": True, "Health": {"Status": "healthy"}}))
        self.assertFalse(f2a.is_healthy({"Running": True, "Health": {"Status": "starting"}}))

    def test_healthy_without_healthcheck(self):
        self.assertTrue(f2a.is_healthy({"Running": True}))


class TestF1b(unittest.TestCase):
    def test_plan_valid_default_strength(self):
        p = f1b.plan_allocation()
        self.assertEqual(p["strength"], "medium")
        self.assertTrue(p["valid"])
        self.assertGreater(p["extra_bytes"], 0)
        self.assertGreater(p["steps"], 0)
        # 결과는 OOM 안전 가드(0.94) 이하 — 룰 임계가 아니라 안전장치다.
        self.assertLessEqual(p["resulting_fraction"], f1b.OOM_GUARD_FRACTION)
        self.assertGreater(p["hold_seconds"], 0)  # 누수는 지속(자가 치유 안 됨)

    def test_strength_is_rate_and_duration(self):
        # 강도는 누수 속도(MiB/분)와 지속(분)으로만 정의한다(목표 비율 없음).
        self.assertEqual(set(f1b.STRENGTH_PROFILE), {"weak", "medium", "strong"})
        for prof in f1b.STRENGTH_PROFILE.values():
            self.assertEqual(set(prof), {"rate_mib_per_min", "duration_min"})
        for name in ("THRESHOLD_FRACTION", "TARGET_FRACTION", "STRENGTH_TARGET_FRACTION"):
            self.assertFalse(hasattr(f1b, name))

    def test_rate_ordering(self):
        r = {k: v["rate_mib_per_min"] for k, v in f1b.STRENGTH_PROFILE.items()}
        self.assertLess(r["weak"], r["medium"])
        self.assertLess(r["medium"], r["strong"])

    def test_requested_is_rate_times_duration(self):
        for name, prof in f1b.STRENGTH_PROFILE.items():
            p = f1b.plan_allocation(current_ws_bytes=0, strength=name)
            self.assertEqual(p["requested_bytes"],
                             prof["rate_mib_per_min"] * prof["duration_min"] * f1b.MIB)

    def test_ramp_slope_matches_rate(self):
        # step 크기 / step 간격 = 누수 속도 → ramp 기울기가 곧 강도다.
        for name, prof in f1b.STRENGTH_PROFILE.items():
            p = f1b.plan_allocation(strength=name)
            per_min = p["step_bytes"] * 60 / p["step_interval"] / f1b.MIB
            self.assertAlmostEqual(per_min, prof["rate_mib_per_min"], places=3)

    def test_injection_never_zero_while_headroom(self):
        # 여유가 있는 한 어떤 강도·baseline 에서도 주입량은 0 이 아니다.
        limit = f1b.MEM_LIMIT_BYTES
        for frac in (0.60, 0.76, 0.79, 0.82, 0.90, 0.93):
            for name in f1b.STRENGTH_PROFILE:
                p = f1b.plan_allocation(current_ws_bytes=int(frac * limit), strength=name)
                self.assertGreater(p["extra_bytes"], 0, (frac, name))
                self.assertTrue(p["valid"], (frac, name))

    def test_unknown_strength_rejected(self):
        with self.assertRaises(ValueError):
            f1b.plan_allocation(strength="nope")

    def test_oom_guard_caps_amount(self):
        # 여유보다 요청이 크면 OOM 가드까지만 — 상한은 가드가 막는다.
        limit = f1b.MEM_LIMIT_BYTES
        p = f1b.plan_allocation(current_ws_bytes=int(0.92 * limit), strength="strong")
        self.assertTrue(p["capped"])
        self.assertLessEqual(p["resulting_fraction"], f1b.OOM_GUARD_FRACTION)

    def test_no_headroom_is_invalid_and_aborted(self):
        # 이미 가드 이상이면 주입량 0·invalid, 시작 가드가 먼저 막는다(0 주입은 실행되지 않음).
        limit = f1b.MEM_LIMIT_BYTES
        ws = int(0.95 * limit)
        p = f1b.plan_allocation(current_ws_bytes=ws, strength="strong")
        self.assertEqual(p["extra_bytes"], 0)
        self.assertFalse(p["valid"])
        self.assertTrue(f1b.should_abort_start(ws))

    def test_command_embeds_bytes(self):
        p = f1b.plan_allocation()
        cmd = f1b.build_alloc_command(p)
        self.assertIn(str(p["extra_bytes"]), cmd)
        self.assertIn("python3", cmd)

    def test_should_abort_start(self):
        limit = f1b.MEM_LIMIT_BYTES
        self.assertTrue(f1b.should_abort_start(None))                      # 못 읽으면 중단
        self.assertTrue(f1b.should_abort_start(int(0.95 * limit)))         # OOM 가드 이상 중단
        self.assertFalse(f1b.should_abort_start(int(0.90 * limit)))        # 가드 아래 진행
        self.assertFalse(f1b.should_abort_start(int(0.80 * limit)))

    def test_allocator_self_monitors_and_compiles(self):
        p = f1b.plan_allocation()
        src = f1b._allocator_py(p)
        ast.parse(src)                                   # 생성된 할당기 python 이 유효해야 함
        self.assertIn("memory.current", src)             # cgroup v2
        self.assertIn("usage_in_bytes", src)             # cgroup v1 폴백
        self.assertIn("guard", src)                      # 증가 중 가드
        self.assertIn(str(p["oom_guard_fraction"]), src)

    def test_shm_has_room(self):
        self.assertTrue(f1b.shm_has_room(80 * f1b.MIB, 200 * f1b.MIB))
        self.assertFalse(f1b.shm_has_room(200 * f1b.MIB, 64 * f1b.MIB))

    def test_sh_allocator_guards_and_cleanup(self):
        p = f1b.plan_allocation()
        sh = f1b._allocator_sh(p)
        # trap 으로 /dev/shm 파일 정리, dd 로 조각 쓰기, df 시작가드, cgroup 정수 가드
        self.assertIn("trap \"rm -f $F\"", sh)
        self.assertIn("rm -f $F", sh)
        self.assertIn("df -kP /dev/shm", sh)
        self.assertIn("exit 3", sh)                          # /dev/shm 부족 시 주입 안 함
        self.assertIn("dd if=/dev/zero", sh)
        self.assertIn("memory.current", sh)                  # cgroup v2
        self.assertIn("usage_in_bytes", sh)                  # cgroup v1
        self.assertIn("$((CUR*100))", sh)                    # 정수 비교 가드
        self.assertIn("GPCT=94", sh)                         # OOM 안전 가드(=0.94)
        self.assertNotIn("'", sh)                            # _shq 안전(작은따옴표 없음)

    def test_sh_allocator_passes_sh_syntax_check(self):
        p = f1b.plan_allocation()
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
            fh.write(f1b._allocator_sh(p)); path = fh.name
        try:
            r = subprocess.run(["sh", "-n", path], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
        finally:
            os.unlink(path)

    def test_build_command_offers_both_paths(self):
        p = f1b.plan_allocation()
        cmd = f1b.build_alloc_command(p)
        self.assertIn("command -v python3", cmd)
        self.assertIn("else sh -c", cmd)


class TestS1a(unittest.TestCase):
    def test_build_urls_count(self):
        urls = s1a.build_request_urls(count=10)
        self.assertEqual(len(urls), 10)

    def test_build_urls_cycles_payloads(self):
        urls = s1a.build_request_urls(count=len(s1a.PAYLOADS) + 1)
        # 페이로드가 순환돼 요청에 실린다(실제 공격 입력 그 자체)
        self.assertIn(s1a.PARAM + "=", urls[0])

    def test_passed_to_app(self):
        self.assertTrue(s1a.passed_to_app(200))
        self.assertTrue(s1a.passed_to_app(204))
        self.assertFalse(s1a.passed_to_app(403))
        self.assertFalse(s1a.passed_to_app(0))


class TestS1c(unittest.TestCase):
    def test_strength_counts_and_ordering(self):
        self.assertEqual(set(s1c.STRENGTH_ATTEMPTS), {"weak", "medium", "strong"})
        self.assertLess(s1c.STRENGTH_ATTEMPTS["weak"], s1c.STRENGTH_ATTEMPTS["medium"])
        self.assertLess(s1c.STRENGTH_ATTEMPTS["medium"], s1c.STRENGTH_ATTEMPTS["strong"])

    def test_default_strength_count(self):
        att = s1c.build_attempts()  # 기본=medium
        self.assertEqual(len(att), s1c.STRENGTH_ATTEMPTS["medium"])

    def test_explicit_attempts_override(self):
        att = s1c.build_attempts(attempts=4, login_id="acct", passwords=["a", "b"])
        self.assertTrue(all(a["login_id"] == "acct" for a in att))
        self.assertEqual([a["password"] for a in att], ["a", "b", "a", "b"])

    def test_request_body_key_is_login_id(self):
        # API(auth_api.js)와 같은 login_id 필드. 과거 loginId 는 쓰지 않는다.
        body = s1c.build_attempts(attempts=1)[0]
        self.assertIn("login_id", body)
        self.assertNotIn("loginId", body)
        self.assertIn("password", body)

    def test_unknown_strength_rejected(self):
        with self.assertRaises(ValueError):
            s1c.build_attempts(strength="nope")

    def test_is_auth_failure(self):
        self.assertTrue(s1c.is_auth_failure(401))
        self.assertFalse(s1c.is_auth_failure(200))


class TestRun(unittest.TestCase):
    def test_dry_run_each_batch1_id(self):
        for sid in ("s1_a_input_attack", "s1_c_login_bruteforce",
                    "f1_b_memory_leak", "f2_a_minio_outage"):
            self.assertEqual(v2run.run(sid, dry_run=True), 0)

    def test_unknown_id_returns_2(self):
        self.assertEqual(v2run.run("nope", dry_run=True), 2)

    def test_s1c_dry_run_hides_login_id(self):
        # loginId 값이 dry-run 출력 dict 에 들어가지 않는다(평문 ID 보호)
        d = s1c.dry_run()
        self.assertNotIn("loginId", d)
        self.assertNotIn(s1c.TARGET_LOGIN_ID, str(d.get("note", "")))



class TestS2a(unittest.TestCase):
    def test_plan_load(self):
        p = s2a.plan_load("strong")
        self.assertEqual(p["workers"], s2a.STRENGTH_WORKERS["strong"])
        self.assertGreater(p["duration_seconds"], 0)

    def test_unknown_strength(self):
        with self.assertRaises(ValueError):
            s2a.plan_load("nope")

    def test_command_has_marker_timeout_and_workers(self):
        p = s2a.plan_load("medium", duration_seconds=90)
        cmd = s2a.build_load_command(p)
        self.assertIn(s2a.MARKER, cmd)
        self.assertIn("timeout 90", cmd)
        self.assertIn("[ $i -lt 2 ]", cmd)


class TestF2c(unittest.TestCase):
    def test_plan_connections(self):
        p = f2c.plan_connections("weak")
        self.assertEqual(p["connections"], f2c.STRENGTH_CONNECTIONS["weak"])

    def test_hold_sql_is_readonly(self):
        self.assertTrue(f2c.is_readonly_statement(f2c.hold_sql(120)))
        self.assertIn("pg_sleep", f2c.hold_sql(120))
        self.assertFalse(f2c.is_readonly_statement("DELETE FROM t"))
        self.assertFalse(f2c.is_readonly_statement("update t set x=1"))

    def test_hold_uses_local_socket_no_credentials(self):
        # 로컬 소켓·컨테이너 env 참조만 — 비밀번호 값이 명령에 들어가지 않는다.
        inner = f2c.hold_inner_sh(120)
        self.assertIn("pg_sleep", inner)
        self.assertIn("$POSTGRES_USER", inner)       # 컨테이너 env 로만 참조
        self.assertIn(f2c.HOLD_APPNAME, inner)
        self.assertNotIn("PGPASSWORD", inner)         # 자격증명 미사용
        self.assertNotIn("leafy_secret", inner)
        argv = f2c.hold_session_argv()
        self.assertEqual(argv[:3], ["docker", "exec", "-d"])

    def test_terminate_targets_only_marked_sessions(self):
        sql = f2c.terminate_sql()
        self.assertIn("pg_terminate_backend", sql)
        self.assertIn(f2c.HOLD_APPNAME, sql)
        self.assertIn("pg_backend_pid()", sql)        # 자기 자신 제외

    def test_numbackends_recovered(self):
        self.assertTrue(f2c.numbackends_recovered(after=12, baseline=10))   # +2 이내
        self.assertFalse(f2c.numbackends_recovered(after=40, baseline=10))

    def test_watchdog_restore_terminates_sessions(self):
        sh = f2c.watchdog_restore_sh()
        self.assertIn("docker exec", sh)
        self.assertIn("pg_terminate_backend", sh)
        self.assertNotIn("leafy_secret", sh)

    def test_background_default_on(self):
        self.assertTrue(f2c.BACKGROUND_DEFAULT)

    def test_unknown_strength(self):
        with self.assertRaises(ValueError):
            f2c.plan_connections("nope")


class TestF3a(unittest.TestCase):
    def test_failing_command_modes(self):
        self.assertEqual(f3a.failing_command("crashloop")[-1], "exit 1")
        self.assertIn("sleep", f3a.failing_command("healthcheck-fail")[-1])

    def test_unknown_mode(self):
        with self.assertRaises(ValueError):
            f3a.failing_command("nope")

    def test_stateful_targets_forbidden(self):
        for t in f3a.FORBIDDEN_TARGETS:
            with self.assertRaises(ValueError):
                f3a.assert_target_allowed(t)
        f3a.assert_target_allowed("leafy-backend")  # 허용

    def test_capture_original(self):
        attrs = {"Config": {"Image": "img:1", "Entrypoint": ["e"], "Cmd": ["c"]}}
        self.assertEqual(f3a.capture_original(attrs)["image"], "img:1")

    def test_capture_original_includes_image_id(self):
        attrs = {"Image": "sha256:abc", "Config": {"Image": "img:1"}}
        cap = f3a.capture_original(attrs)
        self.assertEqual(cap["image"], "img:1")
        self.assertEqual(cap["image_id"], "sha256:abc")

    def test_assert_recreate_image_same_ok(self):
        orig = {"image": "img:1", "image_id": "sha256:abc"}
        f3a.assert_recreate_image(orig, "img:1", "sha256:abc")  # 예외 없음

    def test_assert_recreate_image_tag_mismatch_aborts(self):
        orig = {"image": "img:1", "image_id": "sha256:abc"}
        with self.assertRaises(ValueError):
            f3a.assert_recreate_image(orig, "img:2", "sha256:abc")

    def test_assert_recreate_image_digest_mismatch_aborts(self):
        orig = {"image": "img:1", "image_id": "sha256:abc"}
        with self.assertRaises(ValueError):
            f3a.assert_recreate_image(orig, "img:1", "sha256:def")

    def test_pg_dump_custom_format_no_cred_value(self):
        argv = f3a.pg_dump_argv()
        joined = " ".join(argv)
        self.assertIn("-Fc", joined)                 # custom 포맷
        self.assertIn("pg_dump", joined)
        self.assertIn(f3a.DB_CONTAINER, argv)
        self.assertNotIn("leafy_secret", joined)     # 비밀번호 값 미노출
        self.assertIn("$POSTGRES_PASSWORD", joined)  # 컨테이너 env 로만 참조

    def test_pg_restore_list_argv(self):
        argv = f3a.pg_restore_list_argv()
        self.assertIn("--list", argv)
        self.assertIn("pg_restore", argv)

    def test_verify_backup_ok(self):
        f3a.verify_backup(0, 0, ";\n; Archive created ...\n")  # 예외 없음

    def test_verify_backup_dump_failure_aborts(self):
        with self.assertRaises(RuntimeError):
            f3a.verify_backup(1, 0, "x")

    def test_verify_backup_list_failure_aborts(self):
        with self.assertRaises(RuntimeError):
            f3a.verify_backup(0, 1, "x")

    def test_verify_backup_empty_list_aborts(self):
        with self.assertRaises(RuntimeError):
            f3a.verify_backup(0, 0, "   ")

    def test_restore_hint_no_cred_value(self):
        hint = f3a.restore_hint("/backup/leafy-x.dump")
        self.assertIn("pg_restore", hint)
        self.assertIn("/backup/leafy-x.dump", hint)
        self.assertNotIn("leafy_secret", hint)

    def test_restored_healthy(self):
        self.assertTrue(f3a.restored_healthy({"State": {"Running": True, "Health": {"Status": "healthy"}}}))
        self.assertFalse(f3a.restored_healthy({"State": {"Running": True, "Health": {"Status": "starting"}}}))
        self.assertFalse(f3a.restored_healthy({"State": {"Running": False}}))
        self.assertTrue(f3a.restored_healthy({"State": {"Running": True}}))  # healthcheck 없으면 Running 이면 OK


class TestControls(unittest.TestCase):
    def test_all_blocked_4xx(self):
        self.assertTrue(controls.all_blocked_4xx([403, 404, 400]))
        self.assertFalse(controls.all_blocked_4xx([403, 200]))  # 2xx 통과 → C-c 아님
        self.assertFalse(controls.all_blocked_4xx([]))

    def test_self_report_markers(self):
        self.assertTrue(controls.has_self_report_markers("x [ATTACK] y"))
        self.assertTrue(controls.has_self_report_markers("expected_action=NOTIFY"))
        self.assertFalse(controls.has_self_report_markers("GET /api/plants 404"))


class TestFixtures(unittest.TestCase):
    def test_build_no_labels(self):
        fx = fixtures.build_fixture("f1_b_memory_leak", {"labels": {"alertname": "A"}},
                                    {"loki": ["l"], "prometheus": [{"v": 1}]},
                                    variant_id="gradual", seed=5)
        self.assertEqual(fx["scenario_id"], "f1_b_memory_leak")
        for k in fixtures.ANSWER_LABEL_KEYS:
            self.assertNotIn(k, fx["alert"])
            self.assertNotIn(k, fx["observations"])

    def test_rejects_answer_label_nested(self):
        with self.assertRaises(ValueError):
            fixtures.build_fixture("x", {"a": {"expected_action": "NOTIFY"}}, {})

    def test_find_nested_labels(self):
        found = fixtures.find_answer_label_keys({"a": [{"threat_level": "high"}]})
        self.assertIn("threat_level", found)

    def test_save_roundtrip(self):
        import json
        import tempfile
        fx = fixtures.build_fixture("s1_c_login_bruteforce", {"labels": {}}, {"loki": []})
        d = tempfile.mkdtemp()
        path = fixtures.save_fixture(fx, d)
        saved = json.load(open(path, encoding="utf-8"))
        self.assertEqual(saved["scenario_id"], "s1_c_login_bruteforce")
        self.assertNotIn("threat_level", json.dumps(saved))


class TestVariants(unittest.TestCase):
    def test_all_tuning_variants_generate(self):
        # 모든 시나리오·튜닝 변형에서 인스턴스 생성(= --dry-run 가능)
        for sid, vmap in variants.VARIANT_SPECS.items():
            for vid in vmap:
                inst = variants.generate(sid, vid, 1, specs=variants.VARIANT_SPECS)
                self.assertEqual(inst.scenario_id, sid)
                self.assertEqual(inst.variant_id, vid)
                self.assertIsInstance(inst.params, dict)

    def test_same_seed_same_instance(self):
        a = variants.generate("f1_b_memory_leak", "gradual", 7, specs=variants.VARIANT_SPECS)
        b = variants.generate("f1_b_memory_leak", "gradual", 7, specs=variants.VARIANT_SPECS)
        self.assertEqual(a, b)

    def test_different_seed_differs(self):
        a = variants.generate("f1_b_memory_leak", "gradual", 7, specs=variants.VARIANT_SPECS)
        b = variants.generate("f1_b_memory_leak", "gradual", 8, specs=variants.VARIANT_SPECS)
        self.assertNotEqual(a.params, b.params)

    def test_unknown_rejected(self):
        with self.assertRaises(KeyError):
            variants.generate("nope", "x", 1, specs=variants.VARIANT_SPECS)
        with self.assertRaises(KeyError):
            variants.generate("f1_b_memory_leak", "nope", 1, specs=variants.VARIANT_SPECS)

    def test_labels_from_registry_not_variant(self):
        lab = variants.labels_for("s2_a_resource_theft")
        self.assertEqual(lab["expected_action"], "THROTTLE")

    def test_works_without_heldout(self):
        # heldout 폴더가 없는 저장소를 흉내 — 튜닝 스펙만으로 전부 동작
        saved = registry.load_heldout_specs
        registry.load_heldout_specs = lambda: None
        try:
            specs = variants.all_specs()
            self.assertEqual(set(specs), set(variants.VARIANT_SPECS))
            for sid, vmap in specs.items():
                for vid in vmap:
                    variants.generate(sid, vid, 3, specs=specs)
        finally:
            registry.load_heldout_specs = saved

    def test_heldout_merged_when_present(self):
        # heldout 이 있으면 튜닝 스펙에 없던 변형이 생긴다 → 그것을 동적으로 찾아 생성.
        # (평가용 변형 이름을 저장소 코드에 적지 않기 위해 이름을 하드코딩하지 않는다.)
        specs = variants.all_specs()
        extra = None
        for sid, vmap in specs.items():
            tuning = set(variants.VARIANT_SPECS.get(sid, {}))
            extras = [v for v in vmap if v not in tuning]
            if extras:
                extra = (sid, extras[0])
                break
        if extra is None:
            self.skipTest("평가용 폴더 없음 — 저장소 기본 상태")
        inst = variants.generate(extra[0], extra[1], 1, specs=specs)
        self.assertEqual(inst.variant_id, extra[1])


class TestRunVariant(unittest.TestCase):
    def test_variant_dry_run(self):
        self.assertEqual(
            v2run.run("f1_b_memory_leak", dry_run=True, variant_id="gradual", seed=1), 0)

class TestSupervisor(unittest.TestCase):
    def test_watchdog_script_has_cancel_restore_and_logging(self):
        script = supervisor.build_watchdog_script(
            "docker start leafy-minio", 120, "/w/c.cancel", "/w/c.log")
        self.assertIn("$CANCEL", script)
        self.assertIn("docker start leafy-minio", script)      # 복구 명령 포함
        self.assertIn("watchdog restored", script)
        self.assertIn("RESTORE FAILED", script)                # 복구 실패 로그
        self.assertIn("exit 1", script)

    def test_watchdog_script_is_valid_sh(self):
        script = supervisor.build_watchdog_script("true", 5, "/w/c", "/w/l")
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
            fh.write(script); path = fh.name
        try:
            r = subprocess.run(["sh", "-n", path], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
        finally:
            os.unlink(path)

    def test_watchdog_rejects_bad_args(self):
        with self.assertRaises(ValueError):
            supervisor.build_watchdog_script("true", 0, "/c", "/l")   # timeout < 1
        with self.assertRaises(ValueError):
            supervisor.build_watchdog_script("   ", 5, "/c", "/l")    # 빈 복구 명령

    def test_watchdog_paths_and_workdir(self):
        paths = supervisor.watchdog_paths("/wd", "f2a")
        self.assertEqual(paths["script"], "/wd/wd_f2a.sh")
        self.assertEqual(paths["cancel"], "/wd/wd_f2a.cancel")
        self.assertTrue(supervisor.resolve_work_dir("/x") == "/x")

    def test_background_enabled_override(self):
        self.assertTrue(supervisor.background_enabled(False, True))
        self.assertFalse(supervisor.background_enabled(True, False))
        self.assertTrue(supervisor.background_enabled(True, None))

    def test_build_traffic_command_normal_mode(self):
        cmd = supervisor.build_traffic_command("/tools/traffic_gen.py", "http://fe:80")
        self.assertIn("--control", cmd)
        self.assertEqual(cmd[cmd.index("--control") + 1], "none")   # 정상 모드
        self.assertIn("http://fe:80", cmd)

    def test_background_skips_when_path_missing(self):
        # PR #22 미머지 — 경로가 없으면 조용히 건너뛴다(None).
        self.assertIsNone(supervisor.spawn_background_traffic(None, "http://fe:80"))
        self.assertIsNone(supervisor.spawn_background_traffic("/no/such/traffic_gen.py", "http://fe:80"))


class TestWatchdogRestore(unittest.TestCase):
    def test_f2a_restore_starts_container(self):
        self.assertEqual(f2a.watchdog_restore_sh("leafy-minio"), "docker start leafy-minio")
        self.assertTrue(f2a.BACKGROUND_DEFAULT)

    def test_s2a_restore_clears_marker(self):
        sh = s2a.watchdog_restore_sh()
        self.assertIn("docker exec", sh)
        self.assertIn(s2a.MARKER, sh)
        self.assertIn("rm -f", sh)
        self.assertFalse(s2a.BACKGROUND_DEFAULT)

    def test_f1b_restore_restarts_container(self):
        self.assertIn("docker restart", f1b.watchdog_restore_sh("leafy-backend"))
        self.assertFalse(f1b.BACKGROUND_DEFAULT)

    def test_f3a_restore_recreates_from_compose(self):
        sh = f3a.watchdog_restore_sh("leafy-backend", "/compose")
        self.assertIn("docker compose up -d --force-recreate", sh)
        self.assertIn("leafy-backend", sh)
        self.assertTrue(f3a.BACKGROUND_DEFAULT)

    def test_all_fault_restore_scripts_valid_sh(self):
        scripts = [
            supervisor.build_watchdog_script(f2a.watchdog_restore_sh(), 10, "/c", "/l"),
            supervisor.build_watchdog_script(s2a.watchdog_restore_sh(), 10, "/c", "/l"),
            supervisor.build_watchdog_script(f2c.watchdog_restore_sh(), 10, "/c", "/l"),
            supervisor.build_watchdog_script(f1b.watchdog_restore_sh(), 10, "/c", "/l"),
            supervisor.build_watchdog_script(f3a.watchdog_restore_sh(), 10, "/c", "/l"),
        ]
        for sc in scripts:
            with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
                fh.write(sc); path = fh.name
            try:
                r = subprocess.run(["sh", "-n", path], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)
            finally:
                os.unlink(path)


if __name__ == "__main__":
    unittest.main()
