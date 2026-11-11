"""Run offline regression suites with outbound sockets denied.

The sole permitted connection is the producer test's /private/tmp/oi23-*/d.sock
fixture. This script never reads heldout data, starts Docker, or probes a PC.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SUITES = {
    "pipeline": ("aiops/pipeline", "tests"),
    "producer": ("deploy/leafy-pc/telemetry", "tests"),
    "rulepack": (".", "tools/rulepack/tests"),
    "remediation": ("aiops/remediation", "tests"),
    "network-observer": ("aiops/network-observer", "tests"),
}


def worker(suite):
    original = socket.socket.connect
    def guarded(sock, address):
        if (sock.family != socket.AF_UNIX or not isinstance(address, str) or
                not address.startswith("/private/tmp/oi23-") or not address.endswith("/d.sock")):
            raise AssertionError("offline regression denied an external/daemon connection")
        return original(sock, address)
    socket.socket.connect = guarded
    def guarded_ex(sock, address):
        guarded(sock, address)
        return 0
    socket.socket.connect_ex = guarded_ex
    cwd, start = SUITES[suite]
    os.chdir(ROOT / cwd)
    sys.path.insert(0, str(ROOT / cwd))
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.discover(start))
    counts = {"tests": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
              "skipped": len(result.skipped), "expected_failures": len(result.expectedFailures),
              "unexpected_successes": len(result.unexpectedSuccesses)}
    counts["passed"] = counts["tests"] - sum(counts[k] for k in counts if k != "tests")
    # An expected failure or unexpected success never counts as an accepted pass.
    counts["status"] = "PASS" if result.wasSuccessful() and counts["passed"] == counts["tests"] else "FAIL_OR_SKIP"
    print("INTEGRATION_RESULT=" + json.dumps(counts))
    return 0 if counts["status"] == "PASS" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", choices=SUITES)
    parser.add_argument("--promtool", type=Path)
    parser.add_argument("--logcli", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--suites", nargs="+", choices=SUITES, default=list(SUITES))
    args = parser.parse_args()
    if args.worker:
        return worker(args.worker)
    if not args.promtool or not args.logcli or not args.output:
        parser.error("--promtool, --logcli and new --output directory required")
    output = args.output.resolve()
    if output.exists() or ROOT.is_relative_to(output) or (output.is_relative_to(ROOT) and
            not output.is_relative_to(ROOT / "docs/rulepack/integration")):
        parser.error("output must be a new evidence directory outside operating paths")
    for binary in (args.promtool, args.logcli):
        if not binary.is_file(): parser.error("native validator missing")
    output.mkdir(parents=True)
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "SLACK_WEBHOOK_URL": "", "REMEDIATION_MODE": "disabled"}
    for prefix in ("M2", "M3", "M4", "M5", "OI"):
        env[prefix + "_PROMTOOL"] = str(args.promtool.resolve())
        env[prefix + "_LOGCLI"] = str(args.logcli.resolve())
    report = {"runtime_accepted": False, "deployment_performed": False, "suites": {}}
    for suite in args.suites:
        with (output / (suite + ".log")).open("w") as log:
            result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", suite],
                                    cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        lines = (output / (suite + ".log")).read_text().splitlines()
        marker = next((line for line in reversed(lines) if line.startswith("INTEGRATION_RESULT=")), None)
        counts = json.loads(marker.split("=", 1)[1]) if marker else {"status": "RUNNER_ERROR"}
        report["suites"][suite] = {**counts, "exit_code": result.returncode}
        print(suite, json.dumps(report["suites"][suite]), flush=True)
    report["offline_status"] = "PASS" if all(r["status"] == "PASS" and r["exit_code"] == 0 for r in report["suites"].values()) else "FAIL_OR_SKIP"
    (output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["offline_status"] == "PASS" else 1


if __name__ == "__main__": raise SystemExit(main())
