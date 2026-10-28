"""
실행기 테스트 (Phase 2) — 조치 실패를 성공으로 기록하지 않는다.

Docker 데몬은 쓰지 않는다. docker SDK 를 흉내내는 FakeDocker 로 inspect 결과를
직접 만들어, "호출했다" 와 "실제로 적용됐다" 가 구분되는지 검증한다.

실행 (remediation 디렉터리에서):
    python -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from executor.base import (  # noqa: E402
    BLOCKED,
    FAILED,
    ISOLATE,
    PAUSE,
    RECONNECT,
    RESTART,
    SKIPPED,
    SUCCESS,
    THROTTLE,
    UNPAUSE,
    UNTHROTTLE,
    DisabledExecutor,
)
from executor.local_docker import (  # noqa: E402
    LocalDockerExecutor,
    matches,
    parse_networks,
    parse_resources,
    parse_state,
    restorable,
    select_isolation_networks,
    verify_isolated,
    verify_reconnected,
)

BUSINESS = "graduation-project_leafy-net"
MGMT = "graduation-project_mgmt-net"
ISOLATE_PATTERNS = ("leafy-net",)
PRESERVE_PATTERNS = ("mgmt-net", "aiops-net")


def inspect_doc(networks=None, state=None, resources=None, cid="abc123"):
    nets = {}
    for name, cfg in (networks or {}).items():
        nets[name] = {
            "NetworkID": cfg.get("id", "net-" + name),
            "IPAddress": cfg.get("ip"),
            "IPAMConfig": {"IPv4Address": cfg.get("ip")} if cfg.get("ip") else {},
            "Aliases": cfg.get("aliases", []),
            "MacAddress": "02:42:ac:11:00:02",
        }
    base_state = {"Status": "running", "Running": True, "Paused": False,
                  "StartedAt": "2026-10-29T00:00:00Z", "Pid": 1234}
    base_state.update(state or {})
    base_res = {"CpuQuota": 0, "CpuPeriod": 100000, "Memory": 0, "CpuShares": 0,
                "NanoCpus": 0}
    base_res.update(resources or {})
    return {"Id": cid, "Name": "/leafy-backend", "Config": {"Image": "leafy:latest"},
            "State": base_state, "HostConfig": base_res,
            "NetworkSettings": {"Networks": nets}}


class FakeContainer:
    def __init__(self, fake, name):
        self.fake = fake
        self.name = name

    @property
    def attrs(self):
        return self.fake.doc

    def reload(self):
        self.fake.reloads += 1

    def restart(self):
        self.fake.calls.append("restart")
        if self.fake.restart_effect is not None:
            self.fake.restart_effect()

    def pause(self):
        self.fake.calls.append("pause")
        if self.fake.pause_applies:
            self.fake.doc["State"].update(Status="paused", Paused=True, Running=True)

    def unpause(self):
        self.fake.calls.append("unpause")
        if self.fake.pause_applies:
            self.fake.doc["State"].update(Status="running", Paused=False, Running=True)

    def update(self, **kw):
        self.fake.calls.append(("update", kw))
        if self.fake.update_applies:
            if "cpu_quota" in kw:
                self.fake.doc["HostConfig"]["CpuQuota"] = kw["cpu_quota"]
            if "cpu_period" in kw:
                self.fake.doc["HostConfig"]["CpuPeriod"] = kw["cpu_period"]


class FakeNetwork:
    def __init__(self, fake, name):
        self.fake = fake
        self.name = name
        self.id = "net-" + name

    def disconnect(self, target):
        self.fake.calls.append(("disconnect", self.name))
        if self.fake.disconnect_applies:
            self.fake.doc["NetworkSettings"]["Networks"].pop(self.name, None)

    def connect(self, target, ipv4_address=None, aliases=None):
        self.fake.calls.append(("connect", self.name, ipv4_address, tuple(aliases or ())))
        if self.fake.connect_applies:
            self.fake.doc["NetworkSettings"]["Networks"][self.name] = {
                "NetworkID": "net-" + self.name,
                "IPAddress": self.fake.connect_ip or ipv4_address,
                "IPAMConfig": {"IPv4Address": ipv4_address},
                "Aliases": list(aliases or ()),
            }


class FakeDocker:
    """docker SDK 의 containers/networks 만 흉내낸다."""

    def __init__(self, doc, **flags):
        self.doc = doc
        self.calls = []
        self.reloads = 0
        self.missing_container = flags.get("missing_container", False)
        self.missing_network = flags.get("missing_network", False)
        self.disconnect_applies = flags.get("disconnect_applies", True)
        self.connect_applies = flags.get("connect_applies", True)
        self.connect_ip = flags.get("connect_ip")
        self.pause_applies = flags.get("pause_applies", True)
        self.update_applies = flags.get("update_applies", True)
        self.restart_effect = flags.get("restart_effect")

    class _Containers:
        def __init__(self, fake):
            self.fake = fake

        def get(self, name):
            if self.fake.missing_container:
                raise RuntimeError("No such container")
            return FakeContainer(self.fake, name)

    class _Networks:
        def __init__(self, fake):
            self.fake = fake

        def get(self, name):
            if self.fake.missing_network:
                raise RuntimeError("network not found")
            return FakeNetwork(self.fake, name)

    @property
    def containers(self):
        return self._Containers(self)

    @property
    def networks(self):
        return self._Networks(self)


def make_executor(doc, **flags):
    fake = FakeDocker(doc, **flags)
    ex = LocalDockerExecutor(client=fake, isolate_networks=ISOLATE_PATTERNS,
                             preserve_networks=PRESERVE_PATTERNS)
    return ex, fake


# ── 순수 로직 ─────────────────────────────────────────────────────────────────
class PureLogicTest(unittest.TestCase):
    def test_matches_suffix_for_compose_project_prefix(self):
        self.assertTrue(matches(BUSINESS, ("leafy-net",)))
        self.assertTrue(matches("leafy-net", ("leafy-net",)))
        self.assertTrue(matches("deploy_leafy-net", ("leafy-net",)))
        self.assertFalse(matches("leafy-net-staging", ("leafy-net",)))
        self.assertFalse(matches(MGMT, ("leafy-net",)))

    def test_parse_networks_keeps_restore_fields(self):
        doc = inspect_doc({BUSINESS: {"ip": "10.210.0.7", "aliases": ["backend"]}})
        nets = parse_networks(doc)
        self.assertEqual(nets[BUSINESS]["ip_address"], "10.210.0.7")
        self.assertEqual(nets[BUSINESS]["aliases"], ["backend"])
        self.assertEqual(nets[BUSINESS]["network_id"], "net-" + BUSINESS)

    def test_parse_state_and_resources(self):
        doc = inspect_doc(state={"Paused": True}, resources={"CpuQuota": 50000})
        self.assertTrue(parse_state(doc)["paused"])
        self.assertEqual(parse_resources(doc)["cpu_quota"], 50000)

    def test_select_isolates_business_and_preserves_mgmt(self):
        nets = {BUSINESS: {}, MGMT: {}}
        targets, preserved, reason = select_isolation_networks(
            nets, ISOLATE_PATTERNS, PRESERVE_PATTERNS)
        self.assertEqual(targets, [BUSINESS])
        self.assertEqual(preserved, [MGMT])
        self.assertIsNone(reason)

    def test_select_refuses_when_nothing_isolatable(self):
        targets, _, reason = select_isolation_networks(
            {MGMT: {}}, ISOLATE_PATTERNS, PRESERVE_PATTERNS)
        self.assertEqual(targets, [])
        self.assertTrue(reason.startswith("no_isolatable_network"))

    def test_select_refuses_when_ambiguous(self):
        targets, _, reason = select_isolation_networks(
            {BUSINESS: {}}, ("leafy-net",), ("leafy-net",))
        self.assertEqual(targets, [])
        self.assertTrue(reason.startswith("ambiguous_network_classification"))

    def test_verify_isolated_detects_still_attached(self):
        ok, detail = verify_isolated({BUSINESS: {}}, [BUSINESS], [MGMT])
        self.assertFalse(ok)
        self.assertIn("still_attached", detail)

    def test_verify_isolated_detects_lost_management_network(self):
        ok, detail = verify_isolated({}, [BUSINESS], [MGMT])
        self.assertFalse(ok)
        self.assertIn("preserved_network_lost", detail)

    def test_verify_reconnected_requires_same_ip_and_aliases(self):
        expected = {BUSINESS: {"ipam_ipv4": "10.210.0.7", "aliases": ["backend"]}}
        ok, _ = verify_reconnected(
            {BUSINESS: {"ip_address": "10.210.0.7", "aliases": ["backend"]}}, expected)
        self.assertTrue(ok)
        ok, detail = verify_reconnected(
            {BUSINESS: {"ip_address": "10.210.0.99", "aliases": ["backend"]}}, expected)
        self.assertFalse(ok)
        self.assertIn("ip", detail)
        ok, detail = verify_reconnected(
            {BUSINESS: {"ip_address": "10.210.0.7", "aliases": []}}, expected)
        self.assertFalse(ok)
        self.assertIn("aliases_missing", detail)

    def test_restorable_requires_ip(self):
        self.assertTrue(restorable({"networks": {BUSINESS: {"ip_address": "10.210.0.7"}}})[0])
        self.assertFalse(restorable({"networks": {BUSINESS: {}}})[0])
        self.assertFalse(restorable({"networks": {}})[0])


# ── 조치 실행·검증 ────────────────────────────────────────────────────────────
class SnapshotTest(unittest.TestCase):
    def test_snapshot_collects_required_evidence(self):
        doc = inspect_doc({BUSINESS: {"ip": "10.210.0.7", "aliases": ["backend"]}},
                          resources={"CpuQuota": 0})
        ex, _ = make_executor(doc)
        snap = ex.snapshot("leafy-backend")
        self.assertEqual(snap["container_id"], "abc123")
        self.assertEqual(snap["container_name"], "leafy-backend")
        self.assertIn(BUSINESS, snap["networks"])
        self.assertIn("cpu_quota", snap["resources"])
        self.assertTrue(snap["available"])

    def test_snapshot_failure_is_an_error(self):
        from executor.base import ExecutorError
        ex, _ = make_executor(inspect_doc(), missing_container=True)
        with self.assertRaises(ExecutorError):
            ex.snapshot("leafy-backend")


class IsolateTest(unittest.TestCase):
    def test_isolate_disconnects_and_verifies(self):
        doc = inspect_doc({BUSINESS: {"ip": "10.210.0.7", "aliases": ["backend"]},
                           MGMT: {"ip": "10.211.0.7"}})
        ex, fake = make_executor(doc)
        evidence = ex.snapshot("leafy-backend")
        res = ex.execute(ISOLATE, "leafy-backend", evidence)
        self.assertEqual(res.status, SUCCESS)
        self.assertTrue(res.verified)
        self.assertIn(("disconnect", BUSINESS), fake.calls)
        # 관리 네트워크는 끊지 않았다
        self.assertNotIn(("disconnect", MGMT), fake.calls)
        self.assertIn(MGMT, res.after["networks"])

    def test_isolate_not_applied_is_reported_as_failure(self):
        """
        이전 구현의 핵심 결함: disconnect 가 아무 효과가 없어도 'Success' 였다.
        재조회에서 여전히 붙어 있으면 실패다.
        """
        doc = inspect_doc({BUSINESS: {"ip": "10.210.0.7"}, MGMT: {"ip": "10.211.0.7"}})
        ex, _ = make_executor(doc, disconnect_applies=False)
        res = ex.execute(ISOLATE, "leafy-backend", ex.snapshot("leafy-backend"))
        self.assertEqual(res.status, FAILED)
        self.assertFalse(res.verified)
        self.assertIn("still_attached", res.detail)

    def test_isolate_blocked_when_network_missing(self):
        doc = inspect_doc({MGMT: {"ip": "10.211.0.7"}})
        ex, fake = make_executor(doc)
        res = ex.execute(ISOLATE, "leafy-backend", ex.snapshot("leafy-backend"))
        self.assertEqual(res.status, BLOCKED)
        self.assertIn("no_isolatable_network", res.detail)
        self.assertEqual([c for c in fake.calls if isinstance(c, tuple)], [])

    def test_isolate_blocked_without_restorable_evidence(self):
        """IP 를 모르면 재연결 시 주소가 바뀐다 — 그런 격리는 하지 않는다."""
        doc = inspect_doc({BUSINESS: {}})
        ex, fake = make_executor(doc)
        res = ex.execute(ISOLATE, "leafy-backend", {"networks": {BUSINESS: {}}})
        self.assertEqual(res.status, BLOCKED)
        self.assertIn("evidence_missing_ip", res.detail)
        self.assertEqual(fake.calls, [])

    def test_docker_api_error_is_failure_not_success(self):
        doc = inspect_doc({BUSINESS: {"ip": "10.210.0.7"}, MGMT: {"ip": "10.211.0.7"}})
        ex, _ = make_executor(doc, missing_network=True)
        res = ex.execute(ISOLATE, "leafy-backend", ex.snapshot("leafy-backend"))
        self.assertEqual(res.status, FAILED)
        self.assertFalse(res.verified)


class ReconnectTest(unittest.TestCase):
    def test_reconnect_restores_ip_and_aliases(self):
        doc = inspect_doc({BUSINESS: {"ip": "10.210.0.7", "aliases": ["backend"]},
                           MGMT: {"ip": "10.211.0.7"}})
        ex, fake = make_executor(doc)
        evidence = ex.snapshot("leafy-backend")
        ex.execute(ISOLATE, "leafy-backend", evidence)
        res = ex.execute(RECONNECT, "leafy-backend", evidence)
        self.assertEqual(res.status, SUCCESS)
        self.assertTrue(res.verified)
        connect = [c for c in fake.calls if c[0] == "connect"][0]
        self.assertEqual(connect[1], BUSINESS)
        self.assertEqual(connect[2], "10.210.0.7")
        self.assertEqual(connect[3], ("backend",))

    def test_reconnect_with_different_ip_fails(self):
        doc = inspect_doc({BUSINESS: {"ip": "10.210.0.7", "aliases": ["backend"]},
                           MGMT: {"ip": "10.211.0.7"}})
        ex, fake = make_executor(doc, connect_ip="10.210.0.99")
        evidence = ex.snapshot("leafy-backend")
        ex.execute(ISOLATE, "leafy-backend", evidence)
        res = ex.execute(RECONNECT, "leafy-backend", evidence)
        self.assertEqual(res.status, FAILED)
        self.assertIn("ip", res.detail)

    def test_reconnect_blocked_without_evidence(self):
        ex, _ = make_executor(inspect_doc({MGMT: {"ip": "10.211.0.7"}}))
        res = ex.execute(RECONNECT, "leafy-backend", {})
        self.assertEqual(res.status, BLOCKED)
        self.assertIn("evidence_missing_networks", res.detail)


class PauseTest(unittest.TestCase):
    def test_pause_and_unpause_verified(self):
        ex, _ = make_executor(inspect_doc())
        res = ex.execute(PAUSE, "leafy-backend", {})
        self.assertEqual(res.status, SUCCESS)
        self.assertTrue(res.after["paused"])
        res = ex.execute(UNPAUSE, "leafy-backend", {})
        self.assertEqual(res.status, SUCCESS)
        self.assertFalse(res.after["paused"])

    def test_pause_without_effect_is_failure(self):
        ex, _ = make_executor(inspect_doc(), pause_applies=False)
        res = ex.execute(PAUSE, "leafy-backend", {})
        self.assertEqual(res.status, FAILED)
        self.assertIn("not_paused_after_call", res.detail)

    def test_pause_blocked_when_not_running(self):
        ex, _ = make_executor(inspect_doc(state={"Running": False, "Status": "exited"}))
        res = ex.execute(PAUSE, "leafy-backend", {})
        self.assertEqual(res.status, BLOCKED)
        self.assertIn("not_running", res.detail)


class ThrottleTest(unittest.TestCase):
    def test_throttle_applies_and_verifies(self):
        ex, fake = make_executor(inspect_doc(resources={"CpuQuota": 0}))
        res = ex.execute(THROTTLE, "leafy-backend", ex.snapshot("leafy-backend"))
        self.assertEqual(res.status, SUCCESS)
        self.assertEqual(res.after["cpu_quota"], 50000)

    def test_throttle_not_applied_is_failure(self):
        ex, _ = make_executor(inspect_doc(resources={"CpuQuota": 0}), update_applies=False)
        res = ex.execute(THROTTLE, "leafy-backend", {})
        self.assertEqual(res.status, FAILED)
        self.assertIn("cpu_quota_not_applied", res.detail)

    def test_unthrottle_restores_original_quota(self):
        """원래 쿼터가 제한 없음(0)이었다면 0으로 되돌려야 한다."""
        ex, fake = make_executor(inspect_doc(resources={"CpuQuota": 0}))
        evidence = ex.snapshot("leafy-backend")
        ex.execute(THROTTLE, "leafy-backend", evidence)
        self.assertEqual(ex.snapshot("leafy-backend")["resources"]["cpu_quota"], 50000)
        res = ex.execute(UNTHROTTLE, "leafy-backend", evidence)
        self.assertEqual(res.status, SUCCESS)
        self.assertEqual(res.after["cpu_quota"], 0)

    def test_unthrottle_restores_preexisting_limit(self):
        ex, _ = make_executor(inspect_doc(resources={"CpuQuota": 80000}))
        evidence = ex.snapshot("leafy-backend")
        ex.execute(THROTTLE, "leafy-backend", evidence)
        res = ex.execute(UNTHROTTLE, "leafy-backend", evidence)
        self.assertEqual(res.after["cpu_quota"], 80000)

    def test_unthrottle_blocked_without_evidence(self):
        ex, _ = make_executor(inspect_doc())
        res = ex.execute(UNTHROTTLE, "leafy-backend", {})
        self.assertEqual(res.status, BLOCKED)
        self.assertIn("evidence_missing_resources", res.detail)


class RestartTest(unittest.TestCase):
    def test_restart_verifies_new_start_time(self):
        doc = inspect_doc()

        def effect():
            doc["State"]["StartedAt"] = "2026-10-29T01:00:00Z"
            doc["State"]["Pid"] = 4321

        ex, _ = make_executor(doc, restart_effect=effect)
        res = ex.execute(RESTART, "leafy-backend", ex.snapshot("leafy-backend"))
        self.assertEqual(res.status, SUCCESS)
        self.assertEqual(res.after["started_at"], "2026-10-29T01:00:00Z")

    def test_restart_without_restart_is_failure(self):
        """기동 시각이 그대로면 실제로 재시작되지 않았다."""
        ex, _ = make_executor(inspect_doc())
        res = ex.execute(RESTART, "leafy-backend", ex.snapshot("leafy-backend"))
        self.assertEqual(res.status, FAILED)
        self.assertIn("started_at_unchanged", res.detail)

    def test_restart_not_running_after_is_failure(self):
        doc = inspect_doc()

        def effect():
            doc["State"].update(StartedAt="2026-10-29T01:00:00Z", Running=False,
                                Status="exited")

        ex, _ = make_executor(doc, restart_effect=effect)
        res = ex.execute(RESTART, "leafy-backend", ex.snapshot("leafy-backend"))
        self.assertEqual(res.status, FAILED)
        self.assertIn("not_running_after_restart", res.detail)


class DisabledExecutorTest(unittest.TestCase):
    def test_nothing_runs_and_result_is_skipped(self):
        ex = DisabledExecutor()
        for action in (RESTART, PAUSE, ISOLATE, THROTTLE):
            res = ex.execute(action, "leafy-backend", {})
            self.assertEqual(res.status, SKIPPED)
            self.assertFalse(res.verified)
            self.assertFalse(res.ok)

    def test_snapshot_reports_unavailable(self):
        self.assertFalse(DisabledExecutor().snapshot("leafy-backend")["available"])


class UnknownActionTest(unittest.TestCase):
    def test_unknown_action_is_blocked(self):
        ex, fake = make_executor(inspect_doc())
        res = ex.execute("WIPE_DISK", "leafy-backend", {})
        self.assertEqual(res.status, BLOCKED)
        self.assertEqual(fake.calls, [])


if __name__ == "__main__":
    unittest.main()
