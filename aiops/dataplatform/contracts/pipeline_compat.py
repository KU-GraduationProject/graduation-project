"""Read-only access to `aiops/pipeline` modules (05 §3.2).

The Pipeline uses working-directory imports (`from identity import …`), so its directory is put
on `sys.path` and modules are imported without writing bytecode. Nothing here modifies the
Pipeline. Private Pipeline functions are not imported by production code; their meaning is
ported and fixed by parity tests.
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
PIPELINE_DIR = Path(os.environ.get("DP_PIPELINE_DIR", REPO_ROOT / "aiops" / "pipeline"))
ALLOWLIST_PATH = Path(os.environ.get("DP_ALLOWLIST_PATH", REPO_ROOT / "aiops" / "policy" / "allowlist.yml"))


def load(module: str):
    if not (PIPELINE_DIR / "identity.py").exists():
        raise ImportError(f"aiops/pipeline not found at {PIPELINE_DIR} (set DP_PIPELINE_DIR)")
    if str(PIPELINE_DIR) not in sys.path:
        sys.path.insert(0, str(PIPELINE_DIR))
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        return importlib.import_module(module)
    finally:
        sys.dont_write_bytecode = previous


def identity():
    return load("identity")


def correlation():
    return load("correlation")


def log_line():
    return load("prompt.log_line")


def llm_output():
    return load("schemas.llm_output")


def metrics_collector():
    return load("collector.metrics")


def policy_evaluator():
    """`PolicyEvaluator` over the shared allowlist, or None when the policy file is absent."""
    if not ALLOWLIST_PATH.exists():
        return None
    return load("policy.allowlist").PolicyEvaluator.from_file(str(ALLOWLIST_PATH))
