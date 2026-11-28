"""Portable immutable plans and durable at-most-once side-effect journal.

No client-supplied shell, credentials or connection configuration belongs here.
The existing Controller/Agent authenticates requests; adapters recheck the stored
approval and their operator-owned configuration before every first mutation.
"""
from __future__ import annotations

from copy import deepcopy
from contextlib import contextmanager
import os
import hashlib
import json
from pathlib import Path
import sqlite3
import re
import time

from executor.base import ExecutionResult
import store

PLAN_KEYS = {"executor", "identity", "target", "action_type", "parameters", "operator_config", "pre_snapshot", "plan_digest"}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def seal_plan(plan):
    result = deepcopy(plan)
    result.pop("plan_digest", None)
    if set(result) != PLAN_KEYS - {"plan_digest"}:
        raise ValueError("invalid_managed_plan_keys")
    result["plan_digest"] = digest(result)
    return result


def valid_plan_digest(plan):
    try:
        return (isinstance(plan, dict) and set(plan) == PLAN_KEYS
                and plan["plan_digest"] == digest({k: v for k, v in plan.items() if k != "plan_digest"}))
    except (TypeError, ValueError):
        return False


def check_record(record, executor_name):
    try:
        from executor.deployment import deadline
        now = time.time()
        if (record.state != "EXECUTING" or record.executor_name != executor_name
                or record.requires_approval is not True
                or not isinstance(record.approved_by, str) or not record.approved_by.strip()
                or record.approved_by != record.approved_by.strip() or len(record.approved_by) > 128
                or any(ord(c) < 32 or ord(c) == 127 for c in record.approved_by)
                or not store.approval_valid(record) or record.ttl_seconds is not None
                or record.recovery_mode not in (None, "none")
                or record.targets != [record.identity["target"]]
                or not re.fullmatch(r"[a-f0-9]{64}", record.incident_key or "")
                or not (deadline(record.approval_requested_at) <= deadline(record.approved_at)
                        <= deadline(record.action_started_at) <= now < deadline(record.approval_expires_at))
                or record.action_hash != store.action_hash(record.action_type, record.targets, None, "none", record.action_parameters)):
            raise ValueError()
        for target in record.targets:
            plan = record.target_bindings[target]
            native = {k: v for k, v in plan.items() if k != "transport"}
            if (not valid_plan_digest(native) or native["executor"] != executor_name
                    or native["identity"] != record.identity or native["target"] != target
                    or native["action_type"] != record.action_type or native["parameters"] != record.action_parameters
                    or ((record.evidence or {}).get("targets") or {}).get(target) != plan):
                raise ValueError()
    except (AttributeError, KeyError, TypeError, ValueError):
        raise ValueError("stored_managed_approval_or_plan_invalid") from None


class ExecutionJournal:
    """Persist claim before mutation; crashed/unknown operations are never retried."""
    def __init__(self, path):
        self.path = str(path)

    @contextmanager
    def connection(self):
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=5)
        db.execute("PRAGMA synchronous=FULL")
        db.execute("CREATE TABLE IF NOT EXISTS executions (rid TEXT, target TEXT, hash TEXT, result TEXT, PRIMARY KEY(rid,target))")
        os.chmod(self.path, 0o600)
        try:
            with db:
                yield db
        finally:
            db.close()

    def claim(self, record, target):
        key = digest({"action_hash": record.action_hash, "plan": record.target_bindings[target]})
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT hash,result FROM executions WHERE rid=? AND target=?", (record.remediation_id, target)).fetchone()
            if row:
                if row[0] != key:
                    raise ValueError("managed_execution_payload_conflict")
                if row[1]:
                    return ExecutionResult(**json.loads(row[1]))
                return ExecutionResult(record.action_type, target, "UNKNOWN", detail="prior_managed_claim_requires_reconciliation_no_retry")
            db.execute("INSERT INTO executions VALUES (?,?,?,NULL)", (record.remediation_id, target, key))
        return None

    def save(self, record, target, result):
        key = digest({"action_hash": record.action_hash, "plan": record.target_bindings[target]})
        with self.connection() as db:
            changed = db.execute("UPDATE executions SET result=? WHERE rid=? AND target=? AND hash=?", (json.dumps(result.as_dict(), allow_nan=False), record.remediation_id, target, key)).rowcount
            if changed != 1:
                raise ValueError("managed_claim_missing")
        return result
