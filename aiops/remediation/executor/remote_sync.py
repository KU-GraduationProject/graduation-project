"""Read-only reconciliation of PC 1 records with the Agent's durable state."""
import httpx

from executor.base import RECOVERY_ACTION
import store as states


def reconcile(store, executor, record):
    if record.executor_name != "remote" or executor.name != "remote":
        return record
    expected_state = record.state
    documents, results, recoveries = [], [], []
    try:
        for target in record.targets:
            doc = executor.status(record.remediation_id, target)
            if doc is None:
                return record  # Not found is not proof an in-flight request won't arrive.
            documents.append(doc)
            results.append(executor.result_from_status(doc, record.action_type, target, record.remediation_id))
            if doc.get("recovery_state"):
                recoveries.append(executor.result_from_status(
                    doc, RECOVERY_ACTION[record.action_type], target, record.remediation_id, True))
    except (httpx.HTTPError, ValueError, TypeError, KeyError):
        return record
    if not results:
        return record
    fields = {"results": [r.as_dict() for r in results],
              "evidence": {"targets": {doc["target"]: doc.get("evidence", {}) for doc in documents}}}
    if all(r.ok for r in results):
        verified = [d.get("verified_at") for d in documents]
        if not all(verified):
            return record
        fields["action_verified_at"] = executor.iso(max(verified))
        if record.action_type in RECOVERY_ACTION:
            fields["state"] = (states.RECOVERY_APPROVAL_REQUIRED
                               if record.state == states.RECOVERY_APPROVAL_REQUIRED else states.RECOVERY_PENDING)
            deadlines = [d.get("deadline") for d in documents]
            if all(deadlines):
                fields["recovery_due_at"] = executor.iso(min(deadlines))
        else:
            fields["state"] = states.VERIFIED
    elif any(r.status == "UNKNOWN" for r in results):
        fields["state"] = states.UNKNOWN
    elif all(r.status == "SKIPPED" for r in results):
        fields["state"] = states.SKIPPED
    elif all(r.status == "BLOCKED" for r in results):
        fields["state"] = states.BLOCKED
    else:
        fields["state"] = states.FAILED
    if recoveries:
        fields["recovery_results"] = [r.as_dict() for r in recoveries]
        if len(recoveries) == len(results) and all(r.ok for r in recoveries):
            verified = [d.get("recovery_verified_at") for d in documents]
            if all(verified):
                fields.update(state=states.RECOVERED, recovery_verified_at=executor.iso(max(verified)))
        elif any(r.status == "UNKNOWN" for r in recoveries):
            fields["state"] = states.RECOVERY_UNKNOWN
        elif any(not r.ok for r in recoveries):
            fields["state"] = states.RECOVERY_FAILED
    elif record.state == states.RECOVERY_UNKNOWN:
        fields["state"] = states.RECOVERY_UNKNOWN
    if expected_state == states.RECOVERING and not recoveries:
        fields["state"] = states.RECOVERING
    return store.update_if_state(record.remediation_id, expected_state, **fields)
