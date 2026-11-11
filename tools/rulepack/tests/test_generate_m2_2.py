"""M2-2 offline contract checks and synthetic Prometheus evaluations.

Set M2_PROMTOOL to a verified local promtool binary to enable native tests.
No application/scenario traffic, Docker, network calls or production files are used.
"""

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

MODULE = Path(__file__).resolve().parents[1] / "generate_m2_2.py"
spec = importlib.util.spec_from_file_location("m2_2_generator", MODULE)
m2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m2)


def defaults():
    return yaml.safe_load(m2.CONFIG.read_text(encoding="utf-8"))


def extended():
    config = defaults()
    config["targets"].append({"id": "orders-api", "source": "integrated", "name": "orders-api",
                              "alert_target": "orders-api-alias", "rules": ["cpu", "restart"]})
    return config


def generated(config):
    return m2.build_rules(config)["groups"][0]["rules"]


class ContractTest(unittest.TestCase):
    def test_original_predicates_and_rule_properties_are_preserved(self):
        originals = m2.source_rules()
        normalize = lambda expression: re.sub(r"\s+", "", re.sub(r"\{[^{}]*\}", "", expression))
        for rule in generated(defaults()):
            original = originals[rule["alert"]]
            self.assertEqual(normalize(rule["expr"]), normalize(original["expr"]))
            for field in ("for", "keep_firing_for"):
                self.assertEqual(rule.get(field), original.get(field))
            self.assertEqual({k: v for k, v in rule["labels"].items() if k != "rulepack_target"}, original["labels"])
            self.assertEqual(rule["annotations"]["summary"], original["annotations"]["summary"])
        self.assertEqual(originals["HighCpuUsage"]["for"], "30s")
        self.assertEqual(originals["ContainerRestarted"]["keep_firing_for"], "2m")

    def test_defaults_retain_four_cpu_targets_and_one_restart_target(self):
        rules = generated(defaults())
        self.assertEqual(sum(r["alert"] == "HighCpuUsage" for r in rules), 4)
        restarts = [r for r in rules if r["alert"] == "ContainerRestarted"]
        self.assertEqual(len(restarts), 1)
        self.assertEqual(restarts[0]["annotations"]["container"], "leafy-backend")

    def test_target_and_source_names_are_configuration_values(self):
        config = {"version": 1, "sources": {"local": {
            "cadvisor": {"job": "docker-cpu", "instance": "observer:8080"},
            "pipeline": {"job": "docker-status", "instance": "metadata:8000"}}},
            "targets": [{"id": "store-api", "source": "local", "name": "store-api-v2",
                         "alert_target": "store-api-alias", "rules": ["cpu", "restart"]}]}
        text = m2.render(config)
        self.assertNotIn("leafy", text)
        for rule in generated(config):
            self.assertEqual(rule["annotations"]["container"], "store-api-alias")
            self.assertNotRegex(rule["expr"], r"\b(?:service|role|site)=")
            self.assertNotIn("or vector(0)", rule["expr"])

    def test_invalid_or_ambiguous_mappings_are_rejected(self):
        mutations = [
            lambda c: c.update(version=True),
            lambda c: c["sources"]["integrated"]["pipeline"].pop("instance"),
            lambda c: c["sources"]["integrated"]["cadvisor"].update(site="unobserved"),
            lambda c: c["sources"]["integrated"]["cadvisor"].update(role="unobserved"),
            lambda c: c["sources"]["integrated"]["pipeline"].update(instance="bad\nlabel"),
            lambda c: c["targets"][0].update(source="missing"),
            lambda c: c["targets"][0].update(runtime="host"),
            lambda c: c["targets"][0].update(rules=["memory"]),
            lambda c: c["targets"][0].update(rules=["cpu", "cpu"]),
            lambda c: c["targets"][1].update(id=c["targets"][0]["id"]),
            lambda c: c["targets"][1].update(alert_target=c["targets"][0]["alert_target"]),
            lambda c: c["targets"][1].update(name=c["targets"][0]["name"]),
            lambda c: c["sources"].update(copy=deepcopy(c["sources"]["integrated"])),
            lambda c: c["sources"]["integrated"].pop("cadvisor"),
        ]
        for index, mutation in enumerate(mutations):
            config = defaults()
            mutation(config)
            with self.subTest(case=index), self.assertRaises(ValueError):
                m2.render(config)

    def test_restart_only_scope_does_not_require_cadvisor(self):
        config = defaults()
        config["sources"]["integrated"].pop("cadvisor")
        config["targets"] = [config["targets"][1]]
        config["targets"][0]["rules"] = ["restart"]
        self.assertEqual(len(generated(config)), 1)

    def test_generation_is_reproducible_and_inputs_are_unchanged(self):
        config = defaults()
        snapshot = deepcopy(config)
        source = m2.SOURCE.read_bytes()
        self.assertEqual(m2.render(config), m2.render(config))
        self.assertEqual(config, snapshot)
        self.assertEqual(m2.SOURCE.read_bytes(), source)
        self.assertEqual(m2.OUTPUT.read_text(encoding="utf-8"), m2.render(config))

    def test_source_shape_drift_requires_review(self):
        config = defaults()
        target = config["targets"][1]
        source = config["sources"]["integrated"]
        with self.assertRaises(ValueError):
            m2._cpu_expression('rate(container_cpu_usage_seconds_total[1m]) > 0.5', target, source)
        with self.assertRaises(ValueError):
            m2._restart_expression('increase(aiops_docker_container_restarts_total[10m]) >= 2', target, source)

    def test_check_mode_never_rewrites_a_drifted_draft(self):
        with tempfile.TemporaryDirectory(prefix="leafy-m2-2-check-") as directory:
            output = Path(directory) / "draft.yml"
            output.write_text("unchanged sentinel\n")
            with patch.object(m2, "OUTPUT", output), patch("sys.argv", [str(MODULE), "--check"]), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as exit_info:
                    m2.main()
            self.assertEqual(exit_info.exception.code, 2)
            self.assertEqual(output.read_text(), "unchanged sentinel\n")


def samples(values):
    return " ".join("_" if value is None else str(value) for value in values)


def steps(changes, points=181):
    result, current = [], None
    for index in range(points):
        if index in changes:
            current = changes[index]
        result.append(current)
    return result


def series(metric, labels, values):
    return {"series": metric + m2.selector(labels), "values": samples(values)}


def cpu_input(name="leafy-backend", usage=0.8, *, cpu=True, metadata=True,
              cpu_id=None, metadata_id=None, cpu_label="total", source=None):
    source = source or defaults()["sources"]["integrated"]
    cid = "/docker/" + name
    result = []
    if cpu:
        result.append(series("container_cpu_usage_seconds_total",
                             {**source["cadvisor"], "id": cpu_id or cid, "cpu": cpu_label},
                             [round(index * usage * 5, 6) for index in range(181)]))
    if metadata:
        result.append(series("container_name_info", {**source["pipeline"], "id": metadata_id or cid, "name": name}, [1] * 181))
    return result


def restart_input(name="leafy-backend", counters=None, started=None, source=None):
    source = source or defaults()["sources"]["integrated"]
    labels = {**source["pipeline"], "name": name}
    return [series("aiops_docker_container_restarts_total", labels, counters if counters is not None else [0] * 181),
            series("aiops_docker_container_started_at_seconds", labels, started if started is not None else [1000] * 181)]


def expected_alert(kind, name, config, baseline=False):
    rule = m2.source_rules()[m2.ALERTS[kind]]
    target = next(t for t in config["targets"] if t["name"] == name)
    return {"exp_labels": {"name": name, **rule["labels"], **({} if baseline else {"rulepack_target": target["id"]})},
            "exp_annotations": {**rule["annotations"], "container": name if baseline else target["alert_target"]}}


def alert_check(kind, time, names, config, baseline_names=None):
    result = [{"eval_time": time, "alertname": m2.ALERTS[kind],
               "exp_alerts": [expected_alert(kind, name, config) for name in names]}]
    if baseline_names is not None:
        result.append({"eval_time": time, "alertname": "Baseline" + m2.ALERTS[kind],
                       "exp_alerts": [expected_alert(kind, name, config, True) for name in baseline_names]})
    return result


@unittest.skipUnless(os.getenv("M2_PROMTOOL"), "M2_PROMTOOL not configured: native validation SKIP")
class NativePrometheusTest(unittest.TestCase):
    def run_matrix(self, cases, config=None, *, baseline=True, expect_error=False):
        config = config or extended()
        document = m2.build_rules(config)
        if baseline:
            originals = deepcopy(list(m2.source_rules().values()))
            for rule in originals:
                rule["alert"] = "Baseline" + rule["alert"]
            document["groups"].append({"name": "m2-2-original-baseline", "rules": originals})
        with tempfile.TemporaryDirectory(prefix="leafy-m2-2-promtool-") as directory:
            root = Path(directory)
            (root / "rules.yml").write_text(yaml.safe_dump(document, allow_unicode=True), encoding="utf-8")
            test = {"rule_files": ["rules.yml"], "evaluation_interval": "5s", "tests": cases}
            (root / "test.yml").write_text(yaml.safe_dump(test, allow_unicode=True), encoding="utf-8")
            result = subprocess.run([os.environ["M2_PROMTOOL"], "test", "rules", "test.yml"], cwd=root,
                                    capture_output=True, text=True, timeout=60)
            if expect_error:
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("many-to-many matching not allowed", result.stdout + result.stderr)
            else:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_cpu_existing_added_normal_missing_id_and_concurrent_cases(self):
        config = extended()
        definition = next(r for r in generated(config) if r["alert"] == "HighCpuUsage"
                          and r["labels"]["rulepack_target"] == "leafy-backend")
        cpu_base = definition["expr"].split("> 0.5", 1)[0].strip()
        cases = []
        for name, data, targets, old_targets, base_value in [
            ("existing-high", cpu_input(), ["leafy-backend"], ["leafy-backend"], 0.8),
            ("added-high", cpu_input("orders-api"), ["orders-api"], [], {"orders-api": 0.8}),
            ("normal", cpu_input(usage=0.2), [], [], 0.2),
            ("boundary-0.5", cpu_input(usage=0.5), [], [], 0.5),
            ("cpu-missing", cpu_input(cpu=False), [], [], None),
            ("metadata-missing", cpu_input(metadata=False), [], [], None),
            ("id-mismatch", cpu_input(metadata_id="/docker/other-id"), [], [], None),
            ("cpu-label-mismatch", cpu_input(cpu_label="cpu0"), [], [], None),
            ("unsupported-cgroup-id", cpu_input(cpu_id="/system.slice/docker-example.scope"), [], [], None),
            ("concurrent", cpu_input() + cpu_input("orders-api"), ["leafy-backend", "orders-api"], ["leafy-backend"],
             {"leafy-backend": 0.8, "orders-api": 0.8}),
        ]:
            base_samples = base_value if isinstance(base_value, dict) else (
                {} if base_value is None else {"leafy-backend": base_value})
            case = {"name": name, "interval": "5s", "input_series": data,
                    "alert_rule_test": alert_check("cpu", "1m", targets, config, old_targets),
                    "promql_expr_test": [{"expr": cpu_base, "eval_time": "1m", "exp_samples":
                                           [{"labels": '{name="' + target_name + '"}', "value": value}
                                            for target_name, value in base_samples.items()]}]}
            cases.append(case)
        cases[0]["alert_rule_test"] += alert_check("cpu", "30s", [], config, [])
        cases[0]["alert_rule_test"] += alert_check("cpu", "35s", ["leafy-backend"], config, ["leafy-backend"])
        self.run_matrix(cases, config)

    def test_restart_branches_resets_gaps_missing_and_keep_firing(self):
        config = extended()
        twice = steps({0: 0, 12: 1, 24: 2})
        two_starts = steps({0: 1000, 12: 2000, 24: 3000})
        normal_selector = m2.selector({**config["sources"]["integrated"]["pipeline"], "name": "leafy-backend"})
        raw_count = f"sum(last_over_time(aiops_docker_container_restarts_total{normal_selector}[10m]))"
        cases = []
        definitions = [
            ("automatic-existing", restart_input(counters=twice), "2m", ["leafy-backend"], ["leafy-backend"]),
            ("manual-started-at", restart_input(started=two_starts), "2m", ["leafy-backend"], ["leafy-backend"]),
            ("automatic-added", restart_input("orders-api", counters=twice), "2m", ["orders-api"], []),
            ("normal-zero", restart_input(), "2m", [], []),
            ("missing-despite-scrape-success", [series("aiops_docker_status_scrape_success",
                                                      config["sources"]["integrated"]["pipeline"], [1] * 181)], "2m", [], []),
            ("initial-count-not-an-event", restart_input(counters=[5] * 181), "2m", [], []),
            ("reset-to-zero-and-one-start", restart_input(counters=steps({0: 1, 12: 0}), started=steps({0: 1000, 12: 2000})),
             "2m", [], []),
            ("reset-to-nonzero", restart_input(counters=steps({0: 5, 12: 1, 24: 2})), "2m", ["leafy-backend"], ["leafy-backend"]),
            ("increments-across-reset", restart_input(counters=steps({0: 0, 12: 1, 24: 0, 36: 1})),
             "3m", ["leafy-backend"], ["leafy-backend"]),
            ("gap-is-not-zero", restart_input(counters=steps({0: 0, 12: 1, 18: None, 36: 2}),
                                              started=steps({0: 1000, 18: None, 36: 1000})),
             "3m", ["leafy-backend"], ["leafy-backend"]),
            ("one-event-not-counted-twice", restart_input(counters=steps({0: 0, 12: 1}), started=steps({0: 1000, 12: 2000})),
             "2m", [], []),
            ("new-name-starts-a-new-series", restart_input(counters=steps({0: 0, 12: "stale"}), started=steps({0: 1000, 12: "stale"}))
             + restart_input("orders-api", counters=steps({0: None, 12: 5}), started=steps({0: None, 12: 2000})), "2m", [], []),
            ("concurrent-restarts", restart_input(counters=twice) + restart_input("orders-api", counters=twice),
             "2m", ["leafy-backend", "orders-api"], ["leafy-backend"]),
        ]
        for name, data, when, targets, old_targets in definitions:
            case = {"name": name, "interval": "5s", "input_series": data,
                    "alert_rule_test": alert_check("restart", when, targets, config, old_targets)}
            if name in {"normal-zero", "missing-despite-scrape-success"}:
                case["promql_expr_test"] = [{"expr": raw_count, "eval_time": when,
                                            "exp_samples": [{"labels": "{}", "value": 0}] if name == "normal-zero" else []}]
            if name == "manual-started-at":
                case["alert_rule_test"] += alert_check("restart", "12m", ["leafy-backend"], config, ["leafy-backend"])
                case["alert_rule_test"] += alert_check("restart", "13m5s", [], config, [])
            cases.append(case)
        self.run_matrix(cases, config)

    def test_source_scope_excludes_another_job(self):
        config = extended()
        other = deepcopy(config["sources"]["integrated"])
        other["cadvisor"]["job"] = "unrelated-cadvisor"
        self.run_matrix([{"name": "other-cadvisor-job", "interval": "5s", "input_series": cpu_input(source=other),
                          "alert_rule_test": alert_check("cpu", "1m", [], config, ["leafy-backend"])}], config)

    def test_duplicate_metadata_id_remains_a_join_error(self):
        config = defaults()
        data = cpu_input()
        scope = config["sources"]["integrated"]["pipeline"]
        data.append(series("container_name_info", {**scope, "id": "/docker/leafy-backend", "name": "leafy-frontend"}, [1] * 181))
        self.run_matrix([{"name": "duplicate-rhs-id", "interval": "5s", "input_series": data,
                          "alert_rule_test": alert_check("cpu", "1m", [], config)}], config, baseline=False, expect_error=True)

    def test_same_name_and_id_in_two_explicit_synthetic_scopes(self):
        config = defaults()
        config["sources"]["second"] = {"cadvisor": {"job": "cadvisor", "instance": "second:8080"},
                                          "pipeline": {"job": "pipeline-metadata", "instance": "second:8000"}}
        config["targets"] = [config["targets"][1], {"id": "second-backend", "source": "second", "name": "leafy-backend",
                                                    "alert_target": "second-backend-alias", "rules": ["cpu", "restart"]}]
        first, second = config["sources"]["integrated"], config["sources"]["second"]
        data = cpu_input(source=first) + cpu_input(usage=0.2, source=second) + restart_input(source=first)
        data += restart_input(counters=steps({0: 0, 12: 1, 24: 2}), source=second)
        second_rule = next(r for r in generated(config) if r["alert"] == "ContainerRestarted"
                           and r["labels"]["rulepack_target"] == "second-backend")
        expected = {"exp_labels": {"name": "leafy-backend", **second_rule["labels"]},
                    "exp_annotations": second_rule["annotations"]}
        self.run_matrix([{"name": "two-scopes-synthetic-only", "interval": "5s", "input_series": data,
                          "alert_rule_test": alert_check("cpu", "2m", ["leafy-backend"], config)
                          + [{"eval_time": "2m", "alertname": "ContainerRestarted", "exp_alerts": [expected]}]}],
                        config, baseline=False)


if __name__ == "__main__":
    unittest.main()
