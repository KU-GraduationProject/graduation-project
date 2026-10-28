"""
run.py 네트워크 메뉴 런처 테스트 (scenarios/network_runner.py).

Docker/Loki 없이 검증한다 — subprocess 실행부와 사전 점검 프로브를 Mock 으로 주입해
"선택한 시나리오만 실행되는지"(S2 선택 시 C-a 반복 0, 그 반대도) 를 커맨드 수준에서
확인한다. 실제 전송·탐지·MTTD 는 기존 experiment.py 테스트가 담당한다.

실행: cd scenarios/network && python -m unittest discover -s tests -v
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))        # scenarios/network
sys.path.insert(0, os.path.join(HERE, "..", ".."))  # scenarios

import experiment  # noqa: E402
import network_runner  # noqa: E402
from network_runner import (  # noqa: E402
    NETWORK_SCENARIO_REGISTRY, build_command, child_env, menu_default_reps,
    new_result_files, parse_reps, preflight, run_network_scenario,
)

S2, CA, BOTH = NETWORK_SCENARIO_REGISTRY


def _ok_probe(url, timeout=3):
    return True


def _all_containers():
    return set(network_runner.REQUIRED_CONTAINERS)


class RegistryTest(unittest.TestCase):
    def test_three_network_items(self):
        self.assertEqual([m["id"] for m in NETWORK_SCENARIO_REGISTRY],
                         ["net_s2", "net_ca", "net_s2_ca"])
        for m in NETWORK_SCENARIO_REGISTRY:
            self.assertEqual(m["kind"], "network")

    def test_scenario_flags(self):
        self.assertEqual((S2["run_s2"], S2["run_ca"]), (True, False))
        self.assertEqual((CA["run_s2"], CA["run_ca"]), (False, True))
        self.assertEqual((BOTH["run_s2"], BOTH["run_ca"]), (True, True))

    def test_appended_after_existing_menu(self):
        # 기존 12개 항목의 번호/순서는 바뀌지 않고 네트워크는 13~15번에 붙는다
        import run
        infra = [m for m in run.SCENARIO_REGISTRY if m["category"] == "인프라"]
        sec = [m for m in run.SCENARIO_REGISTRY if m["category"] == "보안"]
        self.assertEqual(len(run.SCENARIO_REGISTRY), len(infra) + len(sec))
        all_sc = infra + sec + NETWORK_SCENARIO_REGISTRY
        self.assertEqual([m["id"] for m in all_sc[:len(infra) + len(sec)]],
                         [m["id"] for m in infra + sec])
        self.assertEqual([m["id"] for m in all_sc[len(infra) + len(sec):]],
                         ["net_s2", "net_ca", "net_s2_ca"])
        # data_exfil 은 S2 와 다른 기존 시나리오로 남아 있어야 한다
        self.assertIn("data_exfil", [m["id"] for m in run.SCENARIO_REGISTRY])


class RepsTest(unittest.TestCase):
    def test_parse_reps(self):
        self.assertEqual(parse_reps("", 1), 1)
        self.assertEqual(parse_reps("  ", 30), 30)
        self.assertEqual(parse_reps("5", 1), 5)
        self.assertEqual(parse_reps("0", 1), 0)
        for bad in ("-1", "abc", "1.5", "하나"):
            with self.assertRaises(ValueError):
                parse_reps(bad, 1)

    def test_v1_menu_defaults_are_one(self):
        self.assertEqual(menu_default_reps(S2, "V1"), (1, 0))
        self.assertEqual(menu_default_reps(CA, "V1"), (0, 1))
        self.assertEqual(menu_default_reps(BOTH, "V1"), (1, 1))

    def test_v2_defaults_follow_experiment_cli(self):
        d = experiment.DEFAULT_V2_REPS
        self.assertEqual(menu_default_reps(S2, "V2"), (d["S2"], 0))
        self.assertEqual(menu_default_reps(CA, "V2"), (0, d["C-a"]))
        self.assertEqual(menu_default_reps(BOTH, "V2"), (d["S2"], d["C-a"]))


class BuildCommandTest(unittest.TestCase):
    def test_s2_only(self):
        cmd = build_command("V1", 1, 0)
        self.assertEqual(cmd[0], sys.executable)
        self.assertTrue(Path(cmd[1]).is_absolute())
        self.assertEqual(Path(cmd[1]).name, "experiment.py")
        self.assertEqual(cmd[2:], ["run", "V1", "--s2-reps", "1", "--ca-reps", "0"])

    def test_ca_only(self):
        self.assertEqual(build_command("V1", 0, 1)[2:],
                         ["run", "V1", "--s2-reps", "0", "--ca-reps", "1"])

    def test_compare(self):
        self.assertEqual(build_command("V1", 1, 1)[2:],
                         ["run", "V1", "--s2-reps", "1", "--ca-reps", "1"])

    def test_repetitions_passed_through(self):
        self.assertEqual(build_command("V1", 30, 5)[2:],
                         ["run", "V1", "--s2-reps", "30", "--ca-reps", "5"])

    def test_rejects_negative_and_empty_run(self):
        with self.assertRaises(ValueError):
            build_command("V1", -1, 1)
        with self.assertRaises(ValueError):
            build_command("V1", 1, -2)
        with self.assertRaises(ValueError):
            build_command("V1", 0, 0)

    def test_rejects_unknown_variant(self):
        with self.assertRaises(ValueError):
            build_command("V3", 1, 1)

    def test_v2_requires_frozen(self):
        with self.assertRaises(ValueError):
            build_command("V2", 1, 1)
        cmd = build_command("V2", 30, 75, frozen="results/frozen.json")
        self.assertEqual(cmd[2:], ["run", "V2", "--s2-reps", "30", "--ca-reps", "75",
                                   "--frozen", "results/frozen.json"])

    def test_cli_accepts_generated_args_and_plans_only_s2(self):
        # 런처가 만든 인자를 experiment.py CLI 에 그대로 넣어 파싱·계획까지 확인한다
        # (전송/검증 루프는 Mock — Docker 불필요)
        with mock.patch.object(experiment, "run_experiment") as run_exp, \
             mock.patch.dict(os.environ, {"DB_PASSWORD": "x"}, clear=False), \
             mock.patch("verifier.NetworkScenarioVerifier"):
            run_exp.return_value = {"confusion_matrix": {}, "paths": {"summary_json": "s"}}
            self.assertEqual(experiment.main(build_command("V1", 1, 0)[2:]), 0)
            self.assertEqual([r.scenario for r in run_exp.call_args[0][0]], ["S2"])

            run_exp.reset_mock()
            self.assertEqual(experiment.main(build_command("V1", 0, 1)[2:]), 0)
            self.assertEqual([r.scenario for r in run_exp.call_args[0][0]], ["C-a"])

            run_exp.reset_mock()
            self.assertEqual(experiment.main(build_command("V1", 1, 1)[2:]), 0)
            self.assertEqual(sorted(r.scenario for r in run_exp.call_args[0][0]),
                             ["C-a", "S2"])


class ChildEnvTest(unittest.TestCase):
    def test_password_passed_by_env_not_argv(self):
        env = child_env({"DB_PASSWORD": "s3cret"})
        self.assertEqual(env["DB_PASSWORD"], "s3cret")
        self.assertNotIn("s3cret", " ".join(build_command("V1", 1, 1)))

    def test_urls_defaulted(self):
        env = child_env({})
        self.assertIn("LOKI_URL", env)
        self.assertIn("ALERTMANAGER_URL", env)

    def test_existing_urls_preserved(self):
        env = child_env({"LOKI_URL": "http://loki:3100"})
        self.assertEqual(env["LOKI_URL"], "http://loki:3100")


class PreflightTest(unittest.TestCase):
    def test_all_ok(self):
        with mock.patch.dict(os.environ, {"DB_PASSWORD": "x"}, clear=False):
            checks = preflight("V1", containers=_all_containers(), http_probe=_ok_probe)
        self.assertTrue(all(c.ok for c in checks), [c.name for c in checks if not c.ok])

    def test_missing_db_password(self):
        env = {k: v for k, v in os.environ.items() if k != "DB_PASSWORD"}
        with mock.patch.dict(os.environ, env, clear=True):
            checks = preflight("V1", containers=_all_containers(), http_probe=_ok_probe)
        failed = [c for c in checks if not c.ok]
        self.assertEqual([c.name for c in failed], ["DB_PASSWORD 환경변수"])

    def test_missing_container_is_reported_by_name(self):
        with mock.patch.dict(os.environ, {"DB_PASSWORD": "x"}, clear=False):
            checks = preflight("V1", containers={"leafy-backend"}, http_probe=_ok_probe)
        failed = [c for c in checks if not c.ok]
        self.assertEqual(len(failed), 1)
        self.assertIn("s2-sink-a", failed[0].hint)
        self.assertIn("s2-sink-b", failed[0].hint)

    def test_docker_unreachable(self):
        with mock.patch.dict(os.environ, {"DB_PASSWORD": "x"}, clear=False):
            checks = preflight("V1", containers=None, http_probe=_ok_probe)
        self.assertIn("Docker 접근", [c.name for c in checks if not c.ok])

    def test_endpoint_down(self):
        with mock.patch.dict(os.environ, {"DB_PASSWORD": "x"}, clear=False):
            checks = preflight("V1", containers=_all_containers(),
                               http_probe=lambda url, timeout=3: "8092" not in url)
        failed = [c.name for c in checks if not c.ok]
        self.assertEqual(len(failed), 1)
        self.assertIn("sink-b", failed[0])

    def test_v2_requires_existing_frozen_file(self):
        with mock.patch.dict(os.environ, {"DB_PASSWORD": "x"}, clear=False):
            checks = preflight("V2", frozen=None, containers=_all_containers(),
                               http_probe=_ok_probe)
            self.assertIn("V2 동결 스냅샷", [c.name for c in checks if not c.ok])

            with tempfile.TemporaryDirectory() as tmp:
                fp = Path(tmp) / "frozen.json"
                fp.write_text("{}", encoding="utf-8")
                checks = preflight("V2", frozen=str(fp), containers=_all_containers(),
                                   http_probe=_ok_probe)
        self.assertTrue(all(c.ok for c in checks))

    def test_v1_does_not_require_frozen(self):
        with mock.patch.dict(os.environ, {"DB_PASSWORD": "x"}, clear=False):
            checks = preflight("V1", containers=_all_containers(), http_probe=_ok_probe)
        self.assertNotIn("V2 동결 스냅샷", [c.name for c in checks])


class ResultLookupTest(unittest.TestCase):
    def test_new_summary_files_only(self):
        import time
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "S2CA-V1_20200101_000000_summary.json"
            old.write_text("{}", encoding="utf-8")
            os.utime(old, (0, 0))
            started = time.time()
            new = Path(tmp) / "S2CA-V1_20991231_235959_summary.json"
            new.write_text('{"confusion_matrix": {"tp": 1}}', encoding="utf-8")
            found = new_result_files(started, out_dir=tmp)
        self.assertEqual([p.name for p in found], [new.name])


class RunNetworkScenarioTest(unittest.TestCase):
    """subprocess 를 Mock 으로 두고 '선택한 시나리오만' 실행되는지 확인."""

    def _run(self, meta, variant="V1", reps=None, rc=0, preflight_ok=True, frozen=None):
        default = menu_default_reps(meta, variant)
        with mock.patch.object(network_runner, "prompt_variant", return_value=variant), \
             mock.patch.object(network_runner, "prompt_reps", return_value=reps or default), \
             mock.patch.object(network_runner, "prompt_frozen", return_value=frozen), \
             mock.patch.object(network_runner, "preflight", return_value=[
                 network_runner.Check("mock", preflight_ok, "mock hint")]), \
             mock.patch.object(network_runner, "new_result_files", return_value=[]), \
             mock.patch.object(network_runner.os, "system"), \
             mock.patch.object(network_runner.console, "print"), \
             mock.patch.object(network_runner.console, "input", return_value=""), \
             mock.patch.object(network_runner.subprocess, "run") as sp:
            sp.return_value = mock.Mock(returncode=rc)
            result = run_network_scenario(meta)
        return result, sp

    def test_s2_only_does_not_run_ca(self):
        rc, sp = self._run(S2)
        self.assertEqual(rc, 0)
        cmd = sp.call_args[0][0]
        self.assertEqual(cmd[2:], ["run", "V1", "--s2-reps", "1", "--ca-reps", "0"])

    def test_ca_only_does_not_run_s2(self):
        rc, sp = self._run(CA)
        cmd = sp.call_args[0][0]
        self.assertEqual(cmd[2:], ["run", "V1", "--s2-reps", "0", "--ca-reps", "1"])

    def test_compare_runs_both(self):
        rc, sp = self._run(BOTH)
        cmd = sp.call_args[0][0]
        self.assertEqual(cmd[2:], ["run", "V1", "--s2-reps", "1", "--ca-reps", "1"])

    def test_custom_reps_passed(self):
        rc, sp = self._run(BOTH, reps=(5, 30))
        cmd = sp.call_args[0][0]
        self.assertEqual(cmd[2:], ["run", "V1", "--s2-reps", "5", "--ca-reps", "30"])

    def test_no_shell_and_inherited_env(self):
        rc, sp = self._run(S2)
        self.assertNotIn("shell", sp.call_args[1])
        self.assertEqual(sp.call_args[1]["cwd"], str(network_runner.NETWORK_DIR))
        self.assertIn("env", sp.call_args[1])

    def test_v2_with_frozen(self):
        rc, sp = self._run(S2, variant="V2", frozen="results/frozen.json")
        cmd = sp.call_args[0][0]
        self.assertEqual(cmd[2:4], ["run", "V2"])
        self.assertEqual(cmd[-2:], ["--frozen", "results/frozen.json"])
        self.assertIn("--ca-reps", cmd)
        self.assertEqual(cmd[cmd.index("--ca-reps") + 1], "0")

    def test_v2_without_frozen_aborts_before_running(self):
        rc, sp = self._run(S2, variant="V2", frozen=None)
        sp.assert_not_called()
        self.assertEqual(rc, -1)

    def test_preflight_failure_aborts_before_running(self):
        rc, sp = self._run(BOTH, preflight_ok=False)
        sp.assert_not_called()
        self.assertEqual(rc, -1)

    def test_failed_run_returns_exit_code(self):
        rc, sp = self._run(BOTH, rc=2)
        sp.assert_called_once()
        self.assertEqual(rc, 2)

    def test_cancel_at_variant_prompt(self):
        with mock.patch.object(network_runner, "prompt_variant", return_value=None), \
             mock.patch.object(network_runner.os, "system"), \
             mock.patch.object(network_runner.console, "print"), \
             mock.patch.object(network_runner.subprocess, "run") as sp:
            self.assertEqual(run_network_scenario(S2), -1)
            sp.assert_not_called()


if __name__ == "__main__":
    unittest.main()
