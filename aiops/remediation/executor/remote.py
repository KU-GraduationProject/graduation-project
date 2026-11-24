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

try:
    # starlette TestClient 는 httpx2 가 설치돼 있으면 httpx2 응답을 돌려준다 (google-genai 가 httpx2 를 끌어온다).
    # 같은 Agent 응답 오류를 두 라이브러리 어느 쪽에서 와도 같은 실패로 처리한다.
    import httpx2
    HTTP_ERRORS = (httpx.HTTPError, httpx2.HTTPError)
except ImportError:
    HTTP_ERRORS = (httpx.HTTPError,)

from agent.contract import Authorization, Command, DeploymentCommand
from executor.base import Executor, ExecutorError, ExecutionResult, blocked
from security.agent_auth import headers
import store as store_mod

DEPLOYMENT_ACTIONS = frozenset({"RECREATE", "ROLLBACK"})


class RemoteExecutor(Executor):
    name = "remote"
    # Evidence is collected and persisted by Agent, atomically before its mutation.
    evidence_at_agent = True

    def __init__(self, base_url, secret, controller_id="pc1", client=None, deployment_enabled=False):
        url = urlsplit(base_url)
        if (url.scheme != "https" or not url.hostname or not url.hostname.endswith(".ts.net")
                or url.username or url.password or url.query or url.fragment or url.path not in ("", "/")):
            raise ValueError("Remote URL must be an HTTPS Tailscale Serve origin (*.ts.net)")
        if not secret or len(secret) < 32:
            raise ValueError("Separate AGENT_HMAC_KEY (>=32 characters) required")
        if secret in (os.getenv("REMEDIATION_API_KEY"), os.getenv("SLACK_SIGNING_SECRET")):
            raise ValueError("Agent key must differ from pipeline and Slack keys")
        self.base_url, self.secret, self.controller_id = base_url.rstrip("/"), secret, controller_id
        if type(deployment_enabled) is not bool:
            raise ValueError("deployment_enabled must be boolean")
        self.supports_deployment = deployment_enabled
        self.client = client or httpx.Client(timeout=20, follow_redirects=False, trust_env=False)

    @classmethod
    def from_env(cls):
        path = os.getenv("AGENT_HMAC_KEY_FILE")
        key = Path(path).read_text(encoding="utf-8").strip() if path else os.getenv("AGENT_HMAC_KEY", "")
        enabled = os.getenv("REMEDIATION_REMOTE_DEPLOYMENT_ENABLED", "false").strip().lower()
        if enabled not in ("true", "false"):
            raise ValueError("REMEDIATION_REMOTE_DEPLOYMENT_ENABLED must be true or false")
        return cls(os.environ["REMEDIATION_AGENT_URL"], key, os.getenv("AGENT_CONTROLLER_ID", "pc1"),
                   deployment_enabled=enabled == "true")

    def _deployment_mapping(self, identity, targets, action_type):
        from executor.identity import configured_target_binding
        if not self.supports_deployment or action_type not in DEPLOYMENT_ACTIONS:
            raise ExecutorError("remote_deployment_disabled")
        configured = configured_target_binding(identity, targets, self)
        if action_type not in configured["container"]["actions"]:
            raise ExecutorError("remote_deployment_not_allowlisted")
        return configured

    def _transport(self, configured):
        return {"kind": "remote", "agent_id": configured["agent_id"], "agent_url": self.base_url,
                "controller_id": self.controller_id,
                "expected_target": {k: configured["container"][k] for k in ("container_id", "image_id", "labels")}}

    def plan_record(self, identity, targets, action_type, parameters):
        from executor.deployment import valid_plan_digest
        configured = self._deployment_mapping(identity, targets, action_type)
        target = identity["target"]
        transport = self._transport(configured)
        payload = {"action_type": action_type, "target": target, "identity": identity,
                   "agent_id": configured["agent_id"], "expected_target": transport["expected_target"],
                   "parameters": parameters}
        try:
            response = self.request("POST", "/v1/deployment/plans", payload)
            response.raise_for_status()
            document = response.json()
            plan = document["plan"]
            if (document["agent_id"] != configured["agent_id"] or document["identity"] != identity
                    or document["target"] != target or not valid_plan_digest(plan)
                    or plan["identity"] != identity or plan["target"] != target
                    or plan["action_type"] != action_type or plan["parameters"] != parameters
                    or plan["pre_snapshot"]["container_id"] != configured["container"]["container_id"]
                    or plan["pre_snapshot"]["image_id"] != configured["container"]["image_id"]
                    or plan["operator_config"]["labels"] != configured["container"]["labels"]):
                raise ValueError()
        except (*HTTP_ERRORS, ValueError, TypeError, KeyError):
            raise ExecutorError("remote_deployment_plan_unavailable_or_mismatched") from None
        return {target: {**plan, "transport": transport}}

    def validate_record(self, record):
        try:
            fresh = self.plan_record(record.identity, record.targets, record.action_type, record.action_parameters)
            from executor.deployment import valid_plan_digest
            for target in record.targets:
                original = record.target_bindings[target]
                native = {k: v for k, v in original.items() if k != "transport"}
                if (not valid_plan_digest(native) or original["transport"] != fresh[target]["transport"]
                        or original["plan_digest"] != fresh[target]["plan_digest"]):
                    return "remote_deployment_changed_reapproval_required"
            return None
        except (ExecutorError, ValueError, KeyError, TypeError, AttributeError):
            return "remote_deployment_plan_validation_failed"

    def verify_deployment_status(self, document, record, target):
        binding = record.target_bindings[target]
        request = document.get("request") or {}
        transport = binding["transport"]
        plan = request.get("plan") or {}
        if (request.get("agent_id") != transport["agent_id"]
                or request.get("identity") != record.identity or request.get("target") != target
                or request.get("action_type") != record.action_type
                or request.get("parameters") != record.action_parameters
                or request.get("expected_target") != transport["expected_target"]
                or plan.get("plan_digest") != binding["plan_digest"]
                or (request.get("approval") or {}).get("action_hash") != record.action_hash
                or (request.get("authorization") or {}).get("approved_by") != record.approved_by):
            raise ValueError("remote_deployment_status_plan_mismatch")

    def _execute_deployment_record(self, record, target, approved_by):
        action = record.action_type
        try:
            configured = self._deployment_mapping(record.identity, record.targets, action)
            binding = record.target_bindings[target]
            native = {k: v for k, v in binding.items() if k != "transport"}
            from executor.deployment import valid_plan_digest
            if (record.state != "EXECUTING" or record.executor_name != self.name
                    or record.requires_approval is not True or not record.approved_by
                    or approved_by is not None and approved_by != record.approved_by
                    or not store_mod.approval_valid(record)
                    or record.ttl_seconds is not None or record.recovery_mode not in (None, "none")
                    or binding["transport"] != self._transport(configured)
                    or not valid_plan_digest(native)
                    or ((record.evidence or {}).get("targets") or {}).get(target) != binding
                    or record.action_hash != store_mod.action_hash(action, record.targets, None, "none", record.action_parameters)):
                raise ValueError()
            expires_at = min(int(time.time()) + 120, int(datetime.fromisoformat(
                record.approval_expires_at.replace("Z", "+00:00")).timestamp()))
            command = DeploymentCommand(
                remediation_id=record.remediation_id, action_type=action, target=target,
                identity=record.identity, agent_id=configured["agent_id"],
                expected_target=binding["transport"]["expected_target"], parameters=record.action_parameters,
                authorization=self.authorization(record, approved_by), plan=native, expires_at=expires_at,
                approval={key: getattr(record, key) for key in ("incident_key", "action_hash", "approval_requested_at",
                    "approval_expires_at", "approved_at", "action_started_at", "approved_by")})
        except (ValueError, TypeError, KeyError, AttributeError, ExecutorError):
            return blocked(action, target, "durable_remote_deployment_approval_required")
        try:
            response = self.request("POST", "/v1/deployments", command.model_dump())
            if response.status_code == 409:
                return blocked(action, target, "agent_deployment_request_conflict_manual_review")
            if response.status_code == 200:
                document = response.json()
                self.verify_deployment_status(document, record, target)
                return self.result_from_status(document, action, target, record.remediation_id)
            document = self.status(record.remediation_id, target)
            if document:
                self.verify_deployment_status(document, record, target)
                return self.result_from_status(document, action, target, record.remediation_id)
            if response.status_code in (400, 401, 403, 413, 422):
                return blocked(action, target, f"agent_deployment_rejected_http_{response.status_code}")
        except (*HTTP_ERRORS, ValueError, TypeError, KeyError):
            try:
                document = self.status(record.remediation_id, target)
                if document:
                    self.verify_deployment_status(document, record, target)
                    return self.result_from_status(document, action, target, record.remediation_id)
            except (*HTTP_ERRORS, ValueError, TypeError, KeyError):
                pass
        return ExecutionResult(action, target, "UNKNOWN", detail="remote_deployment_ledger_query_required_no_retry")

    def snapshot(self, target):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", target):
            raise ExecutorError("invalid_remote_target")
        try:
            response = self.request("GET", f"/v1/targets/{target}")
            response.raise_for_status()
            document = response.json()
            if document.get("target") != target:
                raise ValueError("snapshot_target_mismatch")
            return document
        except (*HTTP_ERRORS, ValueError, TypeError, KeyError):
            raise ExecutorError("remote_target_snapshot_unavailable") from None

    def capture(self, target):
        """Agent 의 읽기 전용 증거 수집 (허용 목록·고정 컨테이너 ID 만)."""
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", target):
            raise ExecutorError("invalid_remote_target")
        try:
            response = self.request("GET", f"/v1/targets/{target}/capture")
            response.raise_for_status()
            document = response.json()
            if document.get("target") != target or not isinstance(document.get("log_lines"), list):
                raise ValueError("capture_target_mismatch")
            return document
        except (*HTTP_ERRORS, ValueError, TypeError, KeyError):
            raise ExecutorError("remote_target_capture_unavailable") from None

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
        if record.action_type in DEPLOYMENT_ACTIONS:
            if recovery_action:
                return blocked(action, target, "deployment_recovery_requires_new_plan_and_approval")
            return self._execute_deployment_record(record, target, approved_by)
        binding = (getattr(record, "target_bindings", {}) or {}).get(target)
        if (not binding or binding.get("executor") != self.name
                or binding.get("agent_url", "").rstrip("/") != self.base_url
                or binding.get("identity") != getattr(record, "identity", None)
                or action not in binding.get("container", {}).get("actions", [])):
            return blocked(action, target, "approved_target_binding_required")
        expiry = getattr(record, "recovery_approval_expires_at" if recovery_action else "approval_expires_at", None)
        try:
            approval_deadline = datetime.fromisoformat(str(expiry).replace("Z", "+00:00")).timestamp()
        except (TypeError, ValueError):
            return blocked(action, target, "stored_approval_expired_or_missing")
        # Transport TTL may shorten an approval, never renew it. The Agent
        # rechecks this absolute deadline after evidence/ledger persistence.
        expires_at = min(int(time.time()) + 120, int(approval_deadline))
        if expires_at <= time.time() or not (approved_by or record.approved_by):
            return blocked(action, target, "stored_approval_expired_or_missing")
        # Recovery keeps the original target identity. It must never approve a
        # new container merely because an operator refreshed the Agent allowlist.
        approved_target = {k: binding["container"][k] for k in ("container_id", "image_id", "labels")}
        command = Command(remediation_id=record.remediation_id, action_type=action, target=target,
                          authorization=self.authorization(record, approved_by, bool(recovery_action)),
                          identity=record.identity, agent_id=binding["agent_id"],
                          approved_target=approved_target,
                          expires_at=expires_at,
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
        if action in DEPLOYMENT_ACTIONS and state == "SUCCESS":
            after = result.get("after") or {}
            if (not re.fullmatch(r"[a-f0-9]{64}", str(after.get("container_id", "")))
                    or after.get("container_id") == after.get("old_container_id")
                    or after.get("requires_rebinding") is not True):
                return ExecutionResult(action, target, "UNKNOWN", detail="remote_new_container_identity_unconfirmed")
        # Keep durable remote evidence/timings in the PC 1 record for recovery/audit.
        return ExecutionResult(action, target, state, result.get("verified") is True,
                               result.get("detail", ""), document.get("evidence", {}),
                               {**result.get("after", {}), "remote": document})

    def execute(self, action, target, evidence):
        if action in DEPLOYMENT_ACTIONS:
            return blocked(action, target, "approved_deployment_record_required")
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
        except (*HTTP_ERRORS, ValueError, TypeError, KeyError):
            try:
                document = self.status(command.remediation_id, target)
                if document:
                    return self.result_from_status(document, action, target, command.remediation_id, is_recovery)
            except (*HTTP_ERRORS, ValueError, TypeError, KeyError):
                pass
        return ExecutionResult(action, target, "UNKNOWN", detail="query_agent_ledger_manual_reconciliation_required")

    @staticmethod
    def iso(timestamp):
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat() if timestamp else None
