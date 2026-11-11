"""Offline memory/network checks; M2_PROMTOOL enables native synthetic evaluations."""

from contextlib import redirect_stderr
from copy import deepcopy
import importlib.util
import io
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

MODULE = Path(__file__).resolve().parents[1] / "generate_m2_3.py"
spec = importlib.util.spec_from_file_location("m2_3_generator", MODULE)
m2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m2)


def defaults():
    return yaml.safe_load(m2.CONFIG.read_text(encoding="utf-8"))


class ContractTest(unittest.TestCase):
    def test_original_conditions_timing_and_annotations_are_preserved(self):
        original = m2.source_rules()
        normalize = lambda expr: re.sub(r"\s+", "", re.sub(r"\{[^{}]*\}", "", expr))
        rules = m2.build_rules(defaults())["groups"][0]["rules"]
        self.assertEqual(len(rules), 2)
        for rule in rules:
            baseline = original[rule["alert"]]
            self.assertEqual(normalize(rule["expr"]), normalize(baseline["expr"]))
            self.assertEqual(rule["for"], baseline["for"])
            self.assertEqual(rule["annotations"], baseline["annotations"])
            self.assertEqual({k: v for k, v in rule["labels"].items() if k != "rulepack_source"}, baseline["labels"])
        self.assertEqual(original["HighMemoryUsage"]["for"], "5m")
        self.assertEqual(original["HighNetworkReceive"]["for"], "30s")

    def test_memory_keeps_all_names_and_network_fallback_is_not_duplicated(self):
        rules = m2.build_rules(defaults())["groups"][0]["rules"]
        memory, network = rules
        self.assertNotIn("leafy", memory["expr"])
        self.assertNotIn("name=", memory["expr"])
        self.assertEqual(network["expr"].count("unless on ()"), 1)
        self.assertEqual(network["expr"].count('id="/"'), 1)
        for rule in rules:
            self.assertNotIn("or vector(0)", rule["expr"])
            self.assertNotRegex(rule["expr"], r"\b(?:role|site|service)=")

    def test_invalid_and_overlapping_sources_are_rejected(self):
        mutations = [
            lambda c: c.update(version=True),
            lambda c: c["sources"]["integrated"]["cadvisor"].pop("instance"),
            lambda c: c["sources"]["integrated"]["cadvisor"].update(role="invented"),
            lambda c: c["sources"]["integrated"]["cadvisor"].update(instance="bad\nvalue"),
            lambda c: c["sources"]["integrated"].update(network_names=[]),
            lambda c: c["sources"]["integrated"].update(network_names=["a", "a"]),
            lambda c: c["sources"]["integrated"].update(network_names=["a|b"]),
            lambda c: c["sources"]["integrated"].update(rules=["memory", "memory"]),
            lambda c: c["sources"]["integrated"].update(rules=["cpu"]),
            lambda c: c["sources"]["integrated"].update(host_fallback=False),
            lambda c: c["sources"].update(duplicate=deepcopy(c["sources"]["integrated"])),
        ]
        for index, mutation in enumerate(mutations):
            config = defaults()
            mutation(config)
            with self.subTest(index=index), self.assertRaises(ValueError):
                m2.render(config)

    def test_network_only_needs_no_pipeline_metadata(self):
        config = defaults()
        source = config["sources"]["integrated"]
        source["rules"] = ["network"]
        source.pop("pipeline")
        rules = m2.build_rules(config)["groups"][0]["rules"]
        self.assertEqual(len(rules), 1)
        self.assertNotIn("container_name_info", rules[0]["expr"])

    def test_reproducibility_input_preservation_and_generated_drift(self):
        config = defaults()
        snapshot, source = deepcopy(config), m2.SOURCE.read_bytes()
        self.assertEqual(m2.render(config), m2.render(config))
        self.assertEqual(config, snapshot)
        self.assertEqual(m2.SOURCE.read_bytes(), source)
        self.assertEqual(m2.OUTPUT.read_text(encoding="utf-8"), m2.render(config))

    def test_check_mode_leaves_drifted_file_unchanged(self):
        with tempfile.TemporaryDirectory(prefix="leafy-m2-3-check-") as directory:
            path = Path(directory) / "draft.yml"
            path.write_text("sentinel\n")
            with patch.object(m2, "OUTPUT", path), patch("sys.argv", [str(MODULE), "--check"]), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as result:
                    m2.main()
            self.assertEqual(result.exception.code, 2)
            self.assertEqual(path.read_text(), "sentinel\n")

    def test_changed_source_shapes_require_review(self):
        source = defaults()["sources"]["integrated"]
        for transform in (m2.memory_expression, m2.network_expression):
            with self.assertRaises(ValueError):
                transform("vector(0)", source)


POINTS = 101


def series(metric, labels, values):
    return {"series": metric + m2.selector(labels), "values": " ".join(str(v) for v in values)}


def memory_input(name="leafy-backend", working=90, limit=100, *, ws=True, spec=True, metadata=True,
                 lhs=None, rhs=None, metadata_id=None, cid=None, source=None):
    source = source or defaults()["sources"]["integrated"]
    cid = cid or "/docker/" + name
    common = {**source["cadvisor"], "id": cid}
    result = []
    if ws:
        result.append(series("container_memory_working_set_bytes", {**common, **(lhs or {})}, [working] * POINTS))
    if spec:
        result.append(series("container_spec_memory_limit_bytes", {**common, **(rhs or {})}, [limit] * POINTS))
    if metadata:
        result.append(series("container_name_info", {**source["pipeline"], "id": metadata_id or cid, "name": name}, [1] * POINTS))
    return result


def network_input(name="leafy-backend", bps=20_000_000, *, cid=None, interface="eth0", source=None, reset=False):
    source = source or defaults()["sources"]["integrated"]
    cid = cid or ("/" if name is None else "/docker/" + name)
    labels = {**source["cadvisor"], "id": cid, "interface": interface}
    if name is not None:
        labels["name"] = name
    values = [((i - 12) if reset and i >= 12 else i) * bps * 5 for i in range(POINTS)]
    return [series("container_network_receive_bytes_total", labels, values)]


def alert(kind, labels, source_id="integrated", baseline=False):
    original = m2.source_rules()[m2.ALERTS[kind]]
    container = labels.get("name") or "unknown (host-level)"
    return {"exp_labels": {**labels, **original["labels"], **({} if baseline else {"rulepack_source": source_id})},
            "exp_annotations": {**original["annotations"], "container": container}}


def checks(kind, when, new, old=None, source_id="integrated"):
    result = [{"eval_time": when, "alertname": m2.ALERTS[kind],
               "exp_alerts": [alert(kind, label, source_id) for label in new]}]
    if old is not None:
        result.append({"eval_time": when, "alertname": "Baseline" + m2.ALERTS[kind],
                       "exp_alerts": [alert(kind, label, baseline=True) for label in old]})
    return result


@unittest.skipUnless(os.getenv("M2_PROMTOOL"), "M2_PROMTOOL not configured: native tests SKIP")
class NativePrometheusTest(unittest.TestCase):
    def run_matrix(self, cases, config=None, baseline=True, expected_error=False):
        config = config or defaults()
        document = m2.build_rules(config)
        if baseline:
            originals = deepcopy(list(m2.source_rules().values()))
            for rule in originals:
                rule["alert"] = "Baseline" + rule["alert"]
            document["groups"].append({"name": "m2-3-original-baseline", "rules": originals})
        with tempfile.TemporaryDirectory(prefix="leafy-m2-3-promtool-") as directory:
            root = Path(directory)
            (root / "rules.yml").write_text(yaml.safe_dump(document, allow_unicode=True), encoding="utf-8")
            (root / "test.yml").write_text(yaml.safe_dump({"rule_files": ["rules.yml"], "evaluation_interval": "5s", "tests": cases},
                                                          allow_unicode=True), encoding="utf-8")
            result = subprocess.run([os.environ["M2_PROMTOOL"], "test", "rules", "test.yml"], cwd=root,
                                    capture_output=True, text=True, timeout=60)
            if expected_error:
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("many-to-many matching not allowed", result.stdout + result.stderr)
            else:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_memory_ratio_label_matching_limits_maximum_and_all_names(self):
        config = defaults()
        expression = m2.build_rules(config)["groups"][0]["rules"][0]["expr"].split("> 0.85", 1)[0].strip()
        variants = memory_input(lhs={"restartcount": "1"}, rhs={"restartcount": "1"})
        variants += memory_input(working=20, lhs={"restartcount": "2"}, rhs={"restartcount": "2"}, metadata=False)
        cases = []
        for name, data, fired, values in [
            ("high", memory_input(), ["leafy-backend"], {"leafy-backend": 0.9}),
            ("normal", memory_input(working=20), [], {"leafy-backend": 0.2}),
            ("boundary", memory_input(working=85), [], {"leafy-backend": 0.85}),
            ("zero-limit", memory_input(limit=0), [], {}),
            ("missing-limit", memory_input(spec=False), [], {}),
            ("missing-working-set", memory_input(ws=False), [], {}),
            ("missing-metadata", memory_input(metadata=False), [], {}),
            ("mismatched-id", memory_input(metadata_id="/docker/another"), [], {}),
            ("mismatched-full-labels", memory_input(lhs={"restartcount": "1"}, rhs={"restartcount": "2"}), [], {}),
            ("matching-variants-use-max", variants, ["leafy-backend"], {"leafy-backend": 0.9}),
            ("all-docker-names-preserved", memory_input("aiops-ollama"), ["aiops-ollama"], {"aiops-ollama": 0.9}),
            ("concurrent", memory_input() + memory_input("leafy-frontend"), ["leafy-backend", "leafy-frontend"],
             {"leafy-backend": 0.9, "leafy-frontend": 0.9}),
            ("no-data", [], [], {}),
        ]:
            expected = [{"name": n} for n in fired]
            cases.append({"name": name, "interval": "5s", "input_series": data,
                          "alert_rule_test": checks("memory", "6m", expected, expected),
                          "promql_expr_test": [{"expr": expression, "eval_time": "6m",
                                                "exp_samples": [{"labels": '{name="' + n + '"}', "value": v} for n, v in values.items()]}]})
        cases[0]["alert_rule_test"] += checks("memory", "4m55s", [], [])
        cases[0]["alert_rule_test"] += checks("memory", "5m", [{"name": "leafy-backend"}], [{"name": "leafy-backend"}])
        self.run_matrix(cases)

    def test_network_targets_fallback_presence_and_rate(self):
        host = {"id": "/", "job": "cadvisor", "instance": "cadvisor:8080"}
        backend = {"name": "leafy-backend"}
        expression = next(r["expr"] for r in m2.build_rules(defaults())["groups"][0]["rules"]
                          if r["alert"] == "HighNetworkReceive")
        raw_rate = expression.split("> 1e7", 1)[0].strip() + ")"
        cases = []
        for name, data, expected in [
            ("container-high", network_input(), [backend]),
            ("container-normal", network_input(bps=1_000_000), []),
            ("exact-boundary", network_input(bps=10_000_000), []),
            ("multiple-interfaces", network_input(bps=6_000_000) + network_input(bps=6_000_000, interface="eth1"), [backend]),
            ("loopback-excluded", network_input(interface="lo"), []),
            ("root-fallback", network_input(None), [host]),
            ("root-name-annotation-preserved", network_input("root-cgroup", cid="/"), [{**host, "name": "root-cgroup"}]),
            ("root-interface-sum", network_input(None, bps=6_000_000) + network_input(None, bps=6_000_000, interface="eth1"), [host]),
            ("root-loopback-excluded", network_input(None, interface="lo"), []),
            ("container-presence-disables-root", network_input(bps=1_000_000) + network_input(None), []),
            ("root-not-duplicated-with-container", network_input() + network_input(None), [backend]),
            ("unselected-name-disables-root", network_input("aiops-ollama") + network_input(None), []),
            ("unnamed-container-disables-root", network_input(None, cid="/docker/unnamed") + network_input(None), []),
            ("loopback-container-disables-root", network_input(interface="lo") + network_input(None), []),
            ("counter-reset", network_input(reset=True), [backend]),
            ("concurrent", network_input() + network_input("leafy-frontend"), [backend, {"name": "leafy-frontend"}]),
            ("no-data", [], []),
        ]:
            cases.append({"name": name, "interval": "5s", "input_series": data,
                          "alert_rule_test": checks("network", "2m", expected, expected)})
            if name in {"container-normal", "no-data"}:
                cases[-1]["promql_expr_test"] = [{"expr": raw_rate, "eval_time": "2m", "exp_samples":
                                                  [{"labels": '{name="leafy-backend"}', "value": 1_000_000}]
                                                  if name == "container-normal" else []}]
        cases[0]["alert_rule_test"] += checks("network", "1m", [], [])
        cases[0]["alert_rule_test"] += checks("network", "1m5s", [backend], [backend])
        self.run_matrix(cases)

    def test_renamed_literal_targets_and_other_job_exclusion(self):
        config = defaults()
        config["sources"]["integrated"]["network_names"] = ["api.v2"]
        other = deepcopy(config["sources"]["integrated"])
        other["cadvisor"]["job"] = "other-cadvisor"
        self.run_matrix([
            {"name": "literal-dot-target", "interval": "5s", "input_series": network_input("api.v2"),
             "alert_rule_test": checks("network", "2m", [{"name": "api.v2"}], [])},
            {"name": "dot-is-not-wildcard", "interval": "5s", "input_series": network_input("apiXv2"),
             "alert_rule_test": checks("network", "2m", [], [])},
            {"name": "different-job", "interval": "5s", "input_series": network_input("leafy-backend", source=other),
             "alert_rule_test": checks("network", "2m", [], [{"name": "leafy-backend"}])},
            {"name": "other-job-does-not-disable-local-root", "interval": "5s",
             "input_series": network_input(None) + network_input("leafy-backend", bps=1_000_000, source=other),
             "alert_rule_test": checks("network", "2m", [{"id": "/", "job": "cadvisor", "instance": "cadvisor:8080"}], [])},
        ], config)

    def test_two_source_host_fallback_is_local_and_memory_is_isolated(self):
        config = defaults()
        first = config["sources"]["integrated"]
        second = deepcopy(first)
        second["cadvisor"]["instance"] = "synthetic-second:8080"
        second["pipeline"]["instance"] = "synthetic-second:8000"
        config["sources"]["second"] = second
        data = network_input(bps=1_000_000, source=first) + network_input(None, source=second)
        data += memory_input(working=20, source=first) + memory_input(source=second)
        host = {"id": "/", "job": "cadvisor", "instance": "synthetic-second:8080"}
        self.run_matrix([{"name": "source-local-presence", "interval": "5s", "input_series": data,
                          "alert_rule_test": checks("network", "2m", [host], source_id="second")
                          + checks("memory", "6m", [{"name": "leafy-backend"}], source_id="second")}],
                        config, baseline=False)

    def test_duplicate_metadata_remains_an_evaluation_error(self):
        config = defaults()
        data = memory_input()
        data.append(series("container_name_info", {**config["sources"]["integrated"]["pipeline"],
                                                   "id": "/docker/leafy-backend", "name": "other-name"}, [1] * POINTS))
        self.run_matrix([{"name": "duplicate-metadata-id", "interval": "5s", "input_series": data,
                          "alert_rule_test": checks("memory", "6m", [])}], baseline=False, expected_error=True)


if __name__ == "__main__":
    unittest.main()
