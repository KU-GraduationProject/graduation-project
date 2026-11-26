"""split_setup.py: 가짜 docker inspect로 두 역할을 돌리고, 실제 로더(Agent·Remediation·Pipeline)로 검증한다."""
import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools/split_setup"))
sys.path.insert(0, str(ROOT / "aiops/remediation"))
sys.path.insert(0, str(ROOT / "aiops/pipeline"))
import split_setup as setup  # noqa: E402
from agent.contract import AgentConfig  # noqa: E402
from executor.identity import configured_bindings  # noqa: E402
from identity import parse_bindings  # noqa: E402

SITE = "gc-mac"
URL = "https://gc-mac.tail0000.ts.net"


def inspect_row(service, n, nano=0, networks=("leafy-probe_leafy-net", "leafy-probe_mgmt-net"), **labels):
    name = f"leafy-{service}"
    return {"Id": f"{n:x}" * 64, "Name": "/" + name, "Image": "sha256:" + "e" * 64,
            "State": {"Running": True}, "HostConfig": {"NanoCpus": nano},
            "NetworkSettings": {"Networks": {k: {} for k in networks}},
            "Config": {"Labels": {"io.leafy.remediation": "workload", "aiops.site": SITE,
                                  "com.docker.compose.project": "leafy-probe",
                                  "com.docker.compose.service": service, **labels}}}


class SplitSetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.rows = {f"leafy-{s}": inspect_row(s, n) for n, s in enumerate(setup.SERVICES, start=1)}

    def tearDown(self):
        self.tmp.cleanup()

    def leafy(self, *extra):
        args = setup.parser().parse_args(
            ["leafy", "--site", SITE, "--aiops-ip", "100.64.0.1", "--leafy-ip", "100.64.0.2",
             "--agent-url", URL, "--agent-dir", str(self.dir / "agent"), "--out", str(self.dir / "leafy"), *extra])
        return setup.run_leafy(args, inspect=lambda name: copy.deepcopy(self.rows[name]))

    def aiops(self):
        args = setup.parser().parse_args(
            ["aiops", "--bundle", str(self.dir / "leafy/aiops-bundle.json"), "--aiops-ip", "100.64.0.1",
             "--hmac-key-file", str(self.dir / "agent/secrets/agent_hmac_key.txt"), "--out", str(self.dir / "aiops")])
        return setup.run_aiops(args)

    def env(self, path):
        return dict(line.split("=", 1) for line in Path(path).read_text().splitlines() if not line.startswith("#"))

    def test_both_roles_produce_files_the_real_loaders_accept_with_same_ids(self):
        self.leafy("--isolate-network", "leafy-net", "--preserve-network", "mgmt-net")
        self.aiops()
        agent = AgentConfig.model_validate(yaml.safe_load((self.dir / "agent/allowlist.yml").read_text()))
        with patch.dict(os.environ, {"REMEDIATION_TARGET_BINDINGS_PATH": str(self.dir / "aiops/remediation_targets.yml")}):
            targets = configured_bindings()
        env = self.env(self.dir / "aiops/aiops.env")
        observations = parse_bindings(env["OBSERVATION_BINDINGS"].strip("'"))
        ids = {t.container_id for t in agent.targets.values()}
        self.assertEqual(len(ids), 3)
        self.assertEqual(ids, {b.container.container_id for b in targets})
        self.assertEqual({"/docker/" + i for i in ids}, {b.metrics["id"] for b in observations})
        self.assertEqual({b.agent_url for b in targets}, {URL})
        self.assertEqual({b.identity.source for b in observations}, {agent.source})
        self.assertEqual(env["REMEDIATION_AGENT_URL"], URL)
        self.assertIn("ISOLATE", agent.targets["leafy-backend"].actions)
        self.assertEqual(yaml.safe_load((self.dir / "aiops/leafy-telemetry.yml").read_text()),
                         [{"targets": ["100.64.0.2:9108"], "labels": {"site": SITE}}])
        telemetry = json.loads((self.dir / "leafy/telemetry-config.json").read_text())
        self.assertEqual(telemetry["targets"], {"backend": "leafy-backend", "frontend": "leafy-frontend",
                                                "minio": "leafy-minio"})
        self.assertEqual(self.env(self.dir / "leafy/leafy.env")["LEAFY_SITE"], SITE)

    def test_hmac_key_created_once_and_never_printed_or_overwritten(self):
        self.leafy()
        key = self.dir / "agent/secrets/agent_hmac_key.txt"
        first = key.read_text()
        self.assertEqual(len(first), 64)
        _, _, created, _ = self.leafy("--force")
        self.assertFalse(created)
        self.assertEqual(key.read_text(), first)
        if os.name != "nt":
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)

    def test_existing_allowlist_needs_force(self):
        self.leafy()
        with self.assertRaises(setup.SetupError):
            self.leafy()

    def test_isolate_and_throttle_only_when_agent_would_accept(self):
        self.rows["leafy-minio"] = inspect_row("minio", 3, nano=500_000_000, networks=("leafy-probe_leafy-net",))
        _, _, _, bundle = self.leafy("--isolate-network", "leafy-net", "--preserve-network", "mgmt-net")
        minio = next(t for t in bundle["targets"] if t["service"] == "minio")
        self.assertEqual(minio["actions"], ["RESTART", "PAUSE", "UNPAUSE"])
        self.assertEqual(minio["isolate_networks"], [])
        _, _, _, plain = self.leafy("--force")
        self.assertTrue(all("ISOLATE" not in t["actions"] for t in plain["targets"]))

    def test_rejects_unlabelled_or_wrong_site_containers_and_bad_inputs(self):
        cases = [
            ("leafy-backend", inspect_row("backend", 1, **{"io.leafy.remediation": "management"}), ()),
            ("leafy-backend", inspect_row("backend", 1, **{"aiops.site": "other"}), ()),
            ("leafy-backend", inspect_row("backend", 1, **{"com.docker.compose.project": "other"}), ()),
            (None, None, ("--agent-url", "http://gc-mac.example.com")),
        ]
        for name, row, extra in cases:
            with self.subTest(name=name, extra=extra):
                saved = copy.deepcopy(self.rows)
                if name:
                    self.rows[name] = row
                with self.assertRaises(setup.SetupError):
                    self.leafy("--force", *extra)
                self.rows = saved


if __name__ == "__main__":
    unittest.main()
