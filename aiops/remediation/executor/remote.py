"""Controller transport; timeout is UNKNOWN, never proof of success or failure."""
from datetime import datetime, timezone
import json
import hashlib
import os
from pathlib import Path
import re
import time
from urllib.parse import urlsplit

import httpx

from agent.contract import Authorization, Command
from executor.base import Executor, ExecutionResult, blocked
from security.agent_auth import headers


class RemoteExecutor(Executor):
    name = "remote"
    # Evidence is collected and persisted by Agent, atomically before its mutation.
    evidence_at_agent = True

    def __init__(self, base_url, secret, controller_id="pc1", client=None):
        url = urlsplit(base_url)
        if (url.scheme != "https" or not url.hostname or not url.hostname.endswith(".ts.net")
                or url.username or url.password or url.query or url.fragment or url.path not in ("", "/")):
            raise ValueError("Remote URL must be an HTTPS Tailscale Serve origin (*.ts.net)")
        if not secret or len(secret) < 32:
            raise ValueError("Separate AGENT_HMAC_KEY (>=32 characters) required")
        if secret in (os.getenv("REMEDIATION_API_KEY"), os.getenv("SLACK_SIGNING_SECRET")):
            raise ValueError("Agent key must differ from pipeline and Slack keys")
        self.base_url, self.secret, self.controller_id = base_url.rstrip("/"), secret, controller_id
        self.client = client or httpx.Client(timeout=20, follow_redirects=False, trust_env=False)

    @classmethod
    def from_env(cls):
        path = os.getenv("AGENT_HMAC_KEY_FILE")
        key = Path(path).read_text(encoding="utf-8").strip() if path else os.getenv("AGENT_HMAC_KEY", "")
        return cls(os.environ["REMEDIATION_AGENT_URL"], key, os.getenv("AGENT_CONTROLLER_ID", "pc1"))

    def snapshot(self, target):
        return {"target": target, "available": False, "executor": self.name}

    def request(self, method, path, payload=None):
        body = b"" if payload is None else json.dumps(payload, separators=(",", ":"), allow_nan=False).encode()
        return self.client.request(method, self.base_url + path, content=body,
                                   headers=headers(self.secret, method, path, body, self.controller_id))

    def status(self, rid, target):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", rid) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", target):
            raise ValueError("invalid remote identity")
        response = self.request("GET", f"/v1/executions/{rid}/{target}")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()

    @staticmethod
    def authorization(record, approved_by=None, recovery=False):
        manual = approved_by or record.approved_by
        return Authorization(decision_id=record.remediation_id,
                             approval_id=hashlib.sha256((("recovery:" if recovery else "execute:") + record.remediation_id).encode()).hexdigest(),
                             kind="manual" if manual else "policy",
                             approved_by=manual or "policy-engine")

    def execute_record(self, record, target, approved_by=None, recovery_action=None):
        action = recovery_action or record.action_type
        command = Command(remediation_id=record.remediation_id, action_type=action, target=target,
                          authorization=self.authorization(record, approved_by, bool(recovery_action)),
                          expires_at=int(time.time()) + 120,
                          ttl_seconds=None if recovery_action else record.ttl_seconds,
                          recovery_mode="none" if recovery_action else (record.recovery_mode or "none"))
        return self.execute(action, target, {"command": command.model_dump(),
                                            "recovery": bool(recovery_action)})

    def result_from_status(self, document, action, target, rid, recovery=False):
        if (not isinstance(document, dict) or document.get("remediation_id") != rid
                or document.get("target") != target):
            raise ValueError("remote_response_identity_mismatch")
        result = document.get("recovery" if recovery else "execution")
        state = document.get("recovery_state" if recovery else "state")
        if not result or state in ("EXECUTING", "UNKNOWN", None):
            return ExecutionResult(action, target, "UNKNOWN", detail="remote_state_unresolved")
        if result.get("action") != action or result.get("target") != target:
            raise ValueError("remote_result_action_mismatch")
        if result.get("status") != state or state not in ("SUCCESS", "FAILED", "BLOCKED", "SKIPPED"):
            raise ValueError("invalid_remote_state")
        if state == "SUCCESS" and result.get("verified") is not True:
            return ExecutionResult(action, target, "UNKNOWN", detail="unverified_remote_success_rejected")
        # Keep durable remote evidence/timings in the PC 1 record for recovery/audit.
        return ExecutionResult(action, target, state, result.get("verified") is True,
                               result.get("detail", ""), document.get("evidence", {}),
                               {**result.get("after", {}), "remote": document})

    def execute(self, action, target, evidence):
        payload = evidence.get("command")
        if not payload:
            return blocked(action, target, "approved_record_context_required")
        command = Command.model_validate(payload)
        if command.action_type != action or command.target != target:
            return blocked(action, target, "command_context_mismatch")
        is_recovery = evidence.get("recovery", False)
        path = "/v1/recoveries" if is_recovery else "/v1/executions"
        try:
            response = self.request("POST", path, command.model_dump())
            if response.status_code == 200:
                return self.result_from_status(response.json(), action, target, command.remediation_id, is_recovery)
            if response.status_code == 409:
                # A cached result must not disguise an altered same-ID payload as success.
                return blocked(action, target, "agent_request_conflict_manual_reconciliation_required")
            # Even a 409/5xx might follow an earlier accepted request; query the ledger first.
            document = self.status(command.remediation_id, target)
            if document:
                return self.result_from_status(document, action, target, command.remediation_id, is_recovery)
            if response.status_code in (400, 401, 403, 413, 422):
                return blocked(action, target, f"agent_rejected_http_{response.status_code}")
        except (httpx.HTTPError, ValueError, TypeError, KeyError):
            try:
                document = self.status(command.remediation_id, target)
                if document:
                    return self.result_from_status(document, action, target, command.remediation_id, is_recovery)
            except (httpx.HTTPError, ValueError, TypeError, KeyError):
                pass
        return ExecutionResult(action, target, "UNKNOWN", detail="query_agent_before_retry_same_remediation_id")

    @staticmethod
    def iso(timestamp):
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat() if timestamp else None
