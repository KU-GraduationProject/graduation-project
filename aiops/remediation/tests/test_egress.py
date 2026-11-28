"""Fake Docker netns/helper regressions; never call Docker or iptables."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

import yaml

from executor.egress import EgressExecutor, validate_observation, validate_parameters
from executor.managed import ExecutionJournal, check_record
import store

IDENTITY = {"site": "fixture-site", "source": "fixture-docker", "service": "backend",
            "runtime": "container", "target": "fixture-backend"}
CID, IMAGE, HELPER = "a"*64, "sha256:"+"b"*64, "sha256:"+"e"*64
BUSINESS, MGMT, DBID = "c"*64, "d"*64, "f"*64
LABELS = {"io.leafy.remediation": "workload", "com.docker.compose.project": "fixture-project", "com.docker.compose.service": "backend"}


def flow(ip="198.51.100.17", port=443, flow_id="fixture-fingerprint"):
    return {"destination_ip": ip, "destination_port": port, "protocol": "tcp", "flow_id": flow_id}


class FakeHelper:
    def __init__(self, docker, args, kwargs):
        self.docker, self.args, self.kwargs = docker, args, kwargs
        self.operation = args[4]
        start = args.index("OUTPUT") + 1
        if self.operation == "-I": start += 1
        self.key = tuple(args[start:])
    def start(self):
        self.docker.starts.append(self.operation)
        if self.operation == "-I": self.docker.rules.add(self.key)
        elif self.operation == "-D": self.docker.rules.discard(self.key)
    def wait(self, timeout):
        if self.docker.fail_insert_wait and self.operation == "-I": raise TimeoutError("synthetic response loss")
        code = (0 if self.key in self.docker.rules else 1) if self.operation == "-C" else 0
        return {"StatusCode": code}
    def remove(self, force): self.docker.removals += 1


class FakeDocker:
    def __init__(self):
        self.rules, self.starts, self.created = set(), [], []
        self.removals = 0
        self.on_create = None
        self.fail_insert_wait = False
        doc = {"Id": CID, "Image": IMAGE, "Name": "/fixture-backend", "Config": {"Labels": LABELS},
            "HostConfig": {}, "State": {"Running": True, "Paused": False, "StartedAt": "2026-11-28T00:00:00Z"}, "Mounts": [],
            "NetworkSettings": {"Networks": {
                "fixture_leafy-net": {"NetworkID": BUSINESS, "IPAddress": "10.203.1.7", "Gateway": "10.203.1.1"},
                "fixture_mgmt-net": {"NetworkID": MGMT, "IPAddress": "10.77.0.7", "Gateway": "10.77.0.1"}}}}
        self.target = SimpleNamespace(attrs=doc, reload=lambda: None)
        self.peer = SimpleNamespace(attrs={"Config": {"Labels": {"com.docker.compose.service": "db"}}}, reload=lambda: None)
        self.network_docs = {
            BUSINESS: {"IPAM": {"Config": [{"Subnet": "10.203.1.0/24"}]}, "Containers": {DBID: {"IPv4Address": "10.203.1.20/24"}}},
            MGMT: {"IPAM": {"Config": [{"Subnet": "10.77.0.0/24"}]}, "Containers": {}}}
        self.containers = SimpleNamespace(get=self.get, create=self.create)
        self.images = SimpleNamespace(get=lambda image: SimpleNamespace(attrs={"Id": HELPER}))
        self.networks = SimpleNamespace(get=lambda nid: SimpleNamespace(attrs=self.network_docs[nid]))
    def get(self, cid):
        if cid == CID: return self.target
        if cid == DBID: return self.peer
        raise ValueError("unknown synthetic container")
    def create(self, image, **kwargs):
        self.created.append((image, deepcopy(kwargs)))
        helper = FakeHelper(self, kwargs["command"], kwargs)
        if self.on_create: self.on_create(helper)
        return helper


class EgressTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").is_dir() else None)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.policy_path = self.root / "allowlist.yml"
        self.policy = {"version": 1, "allow": [{"match": "endpoint", "ip": "192.0.2.30", "port": 8080}, {"match": "service", "service": "db"}]}
        self.policy_path.write_text(yaml.safe_dump(self.policy))
        self.config_path = self.root / "egress.yml"
        self.config = {"version": 1, "enabled": True, "helper_image_id": HELPER, "policy_file": str(self.policy_path),
            "journal_path": str(self.root / "journal.sqlite3"), "preserve_networks": ["mgmt-net"],
            "targets": {IDENTITY["target"]: {"identity": IDENTITY, "container_id": CID, "image_id": IMAGE, "labels": LABELS}}}
        self.config_path.write_text(yaml.safe_dump(self.config))
        self.docker = FakeDocker()
        self.ex = EgressExecutor(self.config_path, self.docker)

    def record(self, action="BLOCK_EGRESS", params=None, rid="fixture-block"):
        params = params or flow()
        plans = self.ex.plan_record(IDENTITY, [IDENTITY["target"]], action, params)
        now = datetime.now(timezone.utc)
        return SimpleNamespace(remediation_id=rid, action_type=action, identity=IDENTITY, targets=[IDENTITY["target"]],
            action_parameters=params, target_bindings=plans, evidence={"targets": deepcopy(plans)},
            state="EXECUTING", executor_name="egress", requires_approval=True, approved_by="fixture-operator", incident_key="1"*64,
            ttl_seconds=None, recovery_mode="none", approval_requested_at=(now-timedelta(seconds=1)).isoformat(),
            approved_at=(now-timedelta(milliseconds=800)).isoformat(), action_started_at=(now-timedelta(milliseconds=500)).isoformat(),
            approval_expires_at=(now+timedelta(minutes=5)).isoformat(), action_hash=store.action_hash(action, [IDENTITY["target"]], None, "none", params))

    def execute(self, record):
        return self.ex.execute_record(record, IDENTITY["target"], record.approved_by)

    def test_block_exact_tuple_and_separate_verified_parent_unblock(self):
        r = self.record()
        self.assertTrue(self.execute(r).ok)
        self.assertEqual(len(self.docker.rules), 1)
        self.assertEqual(self.execute(r).status, "SUCCESS")  # cached, not replayed
        self.assertEqual(self.docker.starts.count("-I"), 1)
        undo = self.record("UNBLOCK_EGRESS", {"parent_id": r.remediation_id}, "fixture-unblock")
        self.assertTrue(self.execute(undo).ok)
        self.assertEqual(self.docker.rules, set())
        self.assertEqual(self.docker.starts.count("-D"), 1)
        for image, opts in self.docker.created:
            self.assertEqual(image, HELPER)
            self.assertEqual(opts["network_mode"], "container:"+CID)
            self.assertEqual(opts["cap_add"], ["NET_ADMIN"])
            self.assertFalse(opts["privileged"])
            self.assertTrue(opts["read_only"])
            self.assertEqual(opts["entrypoint"], ["/sbin/iptables"])

    def test_rotated_observed_addresses_do_not_encode_scenario_ground_truth(self):
        for i, address in enumerate(("198.51.100.17", "203.0.113.49", "192.0.2.81")):
            params = flow(address, 443+i, "fixture-flow-"+str(i))
            r = self.record(params=params, rid="fixture-"+str(i))
            self.assertTrue(self.execute(r).ok)
            self.assertIn(address+"/32", next(opts["command"] for _, opts in reversed(self.docker.created) if opts["command"][4] == "-I"))
        self.assertEqual(len(self.docker.rules), 3)

    def test_current_authorized_endpoint_service_and_management_are_protected(self):
        for params in (flow("192.0.2.30", 8080), flow("10.203.1.20", 5432), flow("10.77.0.45", 443), flow("10.203.1.1", 443), flow("10.203.1.7", 443)):
            with self.subTest(params=params), self.assertRaises(ValueError): self.record(params=params)
        self.assertEqual(self.docker.created, [])

    def test_replaced_container_or_changed_policy_does_not_mutate(self):
        r = self.record()
        self.docker.target.attrs["Image"] = "sha256:"+"a"*64
        self.assertEqual(self.execute(r).status, "BLOCKED")
        self.assertNotIn("-I", self.docker.starts)
        self.docker.target.attrs["Image"] = IMAGE
        r = self.record(rid="fixture-policy-change")
        self.policy["allow"].append({"match": "endpoint", "ip": "198.51.100.17", "port": 443})
        self.policy_path.write_text(yaml.safe_dump(self.policy))
        self.assertEqual(self.execute(r).status, "BLOCKED")
        self.assertNotIn("-I", self.docker.starts)

    def test_expired_approval_prevents_helper_start(self):
        r = self.record()
        r.approval_expires_at = (datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
        self.assertEqual(self.execute(r).status, "BLOCKED")
        self.assertEqual(self.docker.created, [])

    def test_helper_creation_delay_cannot_extend_approval_or_target_identity(self):
        r = self.record()
        def expire(helper):
            if helper.operation == "-I":
                r.approval_expires_at = (datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
        self.docker.on_create = expire
        self.assertEqual(self.execute(r).status, "UNKNOWN")
        self.assertNotIn("-I", self.docker.starts)
        self.assertFalse(self.docker.rules)

    def test_unconfirmed_mutation_never_retries_and_retains_owned_rule(self):
        r = self.record()
        self.docker.fail_insert_wait = True
        self.assertEqual(self.execute(r).status, "UNKNOWN")
        self.assertEqual(len(self.docker.rules), 1)
        self.docker.fail_insert_wait = False
        self.assertEqual(self.execute(r).status, "UNKNOWN")
        self.assertEqual(self.docker.starts.count("-I"), 1)
        with self.assertRaises(ValueError): self.record("UNBLOCK_EGRESS", {"parent_id": r.remediation_id}, "fixture-unknown-undo")

    def test_changed_same_id_claim_does_not_overwrite_original_verified_result(self):
        r = self.record()
        self.assertTrue(self.execute(r).ok)
        other = self.record(params=flow("203.0.113.42"))
        self.assertEqual(self.execute(other).status, "BLOCKED")
        self.assertEqual(self.execute(r).status, "SUCCESS")
        self.assertEqual(self.docker.starts.count("-I"), 1)

    def test_first_restore_without_parent_or_manually_present_rule_is_rejected(self):
        with self.assertRaises(ValueError): self.record("UNBLOCK_EGRESS", {"parent_id": "missing"})
        r = self.record()
        plan = r.target_bindings[IDENTITY["target"]]
        # Simulate a preexisting rule with this tag; the adapter cannot adopt it.
        self.ex._run(plan, "-S")
        last = self.docker.created[-1][1]
        spec = ["-d", "198.51.100.17/32", "-p", "tcp", "--dport", "443", "-m", "comment", "--comment", plan["operator_config"]["tag"], "-j", "REJECT"]
        self.docker.rules.add(tuple(spec))
        self.assertEqual(self.execute(r).status, "BLOCKED")
        with self.assertRaises(ValueError): self.record("UNBLOCK_EGRESS", {"parent_id": r.remediation_id}, "fixture-unowned")

    def test_alert_evidence_must_match_tuple_and_incident(self):
        p = flow()
        alert = {"fingerprint": p["flow_id"], "labels": {"v2_dst_ip": p["destination_ip"], "v2_dst_port": "443", "v2_protocol": "tcp"}}
        validate_observation(alert, p)
        for change in ({"destination_ip": "203.0.113.54"}, {"destination_port": 8443}, {"protocol": "udp"}, {"flow_id": "another-incident"}):
            with self.subTest(change=change), self.assertRaises(ValueError): validate_observation(alert, {**p, **change})
        for bad in ({**p, "protocol": []}, {**p, "destination_port": True}):
            with self.assertRaises(ValueError): validate_parameters("BLOCK_EGRESS", bad)
        with self.assertRaises(ValueError): validate_parameters("UNBLOCK_EGRESS", {"parent_id": None})
        for address in ("127.0.0.1", "169.254.1.1", "0.0.0.0", "255.255.255.255", "::1", "198.51.100.17/24"):
            with self.subTest(address=address), self.assertRaises(ValueError): validate_parameters("BLOCK_EGRESS", flow(address))


if __name__ == "__main__": unittest.main()
