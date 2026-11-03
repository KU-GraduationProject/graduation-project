"""
scenarios-v2 배치 ① 순수 로직 단위 테스트 (Docker/HTTP 불필요).
런타임 주입(inject)·cleanup 은 Docker/Loki 가 필요해 여기서 검증하지 않는다(UNVERIFIED).
"""

import ast
import os
import re
import subprocess
import sys
import tempfile
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

# SQLInjectionAttempt (security-rules.yml) 의 정규식 — S1-a 페이로드가 잡히는지 교차검증.
SQLI_RE = re.compile(
    r"(?i)(union.{0,3}select|or.{0,3}1=1|drop.{0,3}table|sleep\(|extractvalue|"
    r"information_schema|admin'--|and.{0,3}1=1)")


class TestRegistry(unittest.TestCase):
    def test_validation_passes(self):
        registry._validate()  # 예외 없어야 함

    def test_expected_action_in_policy(self):
        for row in registry.SCENARIO_REGISTRY_V2:
            self.assertIn(row["expected_action"], registry.POLICY_ACTIONS)

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


class TestF2a(unittest.TestCase):
    def test_healthy_requires_running(self):
        self.assertFalse(f2a.is_healthy({"Running": False, "Health": {"Status": "healthy"}}))

    def test_healthy_with_healthcheck(self):
        self.assertTrue(f2a.is_healthy({"Running": True, "Health": {"Status": "healthy"}}))
        self.assertFalse(f2a.is_healthy({"Running": True, "Health": {"Status": "starting"}}))

    def test_healthy_without_healthcheck(self):
        self.assertTrue(f2a.is_healthy({"Running": True}))


class TestF1b(unittest.TestCase):
    def test_plan_valid_default_baseline(self):
        p = f1b.plan_allocation()
        self.assertTrue(p["valid"])
        # 주입 후 working_set 은 임계(0.85) 위, OOM 가드(0.94) 이하
        self.assertGreater(p["resulting_fraction"], 0.85)
        self.assertLessEqual(p["resulting_fraction"], 0.94)
        self.assertGreater(p["extra_bytes"], 0)
        self.assertGreater(p["steps"], 0)
        self.assertGreaterEqual(p["hold_seconds"], 300)  # for:5m 를 넘겨 유지

    def test_cap_prevents_oom_when_baseline_high(self):
        # 현재가 이미 0.90 이면 OOM 가드(0.94)까지만 올린다
        limit = f1b.MEM_LIMIT_BYTES
        p = f1b.plan_allocation(current_ws_bytes=int(0.90 * limit))
        self.assertLessEqual(p["resulting_fraction"], 0.94)

    def test_no_alloc_when_already_above_target(self):
        limit = f1b.MEM_LIMIT_BYTES
        p = f1b.plan_allocation(current_ws_bytes=int(0.95 * limit))
        self.assertEqual(p["extra_bytes"], 0)
        self.assertFalse(p["valid"])  # 더 올릴 여지 없음 → 안전상 주입 안 함

    def test_command_embeds_bytes(self):
        p = f1b.plan_allocation()
        cmd = f1b.build_alloc_command(p)
        self.assertIn(str(p["extra_bytes"]), cmd)
        self.assertIn("python3", cmd)

    def test_should_abort_start(self):
        limit = f1b.MEM_LIMIT_BYTES
        self.assertTrue(f1b.should_abort_start(None))                      # 못 읽으면 중단
        self.assertTrue(f1b.should_abort_start(int(0.851 * limit)))       # 임계 이상 중단
        self.assertTrue(f1b.should_abort_start(int(0.90 * limit)))
        self.assertFalse(f1b.should_abort_start(int(0.80 * limit)))       # 임계 아래 진행

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
        self.assertIn("GPCT=94", sh)
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

    def test_default_exceeds_sqli_threshold(self):
        # SQLInjectionAttempt 임계 >5 — 기본 요청 수가 여유 있게 넘는다
        self.assertGreater(s1a.DEFAULT_REQUESTS, 5)

    def test_payloads_match_detection_regex(self):
        # 모든 페이로드가 탐지 정규식에 걸려야 "앱 통과"해도 액세스 로그로 잡힌다
        for p in s1a.PAYLOADS:
            self.assertRegex(p, SQLI_RE)

    def test_passed_to_app(self):
        self.assertTrue(s1a.passed_to_app(200))
        self.assertTrue(s1a.passed_to_app(204))
        self.assertFalse(s1a.passed_to_app(403))
        self.assertFalse(s1a.passed_to_app(0))


class TestS1c(unittest.TestCase):
    def test_build_attempts_count_at_least_3x_threshold(self):
        att = s1c.build_attempts()
        self.assertGreaterEqual(len(att), 15)  # 임계(5)의 최소 3배 (사용자 조건)

    def test_same_account_wrong_passwords(self):
        att = s1c.build_attempts(attempts=4, login_id="acct", passwords=["a", "b"])
        self.assertTrue(all(a["loginId"] == "acct" for a in att))
        self.assertEqual([a["password"] for a in att], ["a", "b", "a", "b"])

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


if __name__ == "__main__":
    unittest.main()
