"""Bounded read model for the presentation client; contains no execution entrypoint."""
import json
import os
from pathlib import Path
from datetime import datetime


def contexts(identity, since):
    directory = os.getenv("PRESENTATION_CONTEXT_DIR", "")
    if not directory:
        return [], "unconfigured"
    if not Path(directory).is_dir():
        return [], "unavailable"
    found = []
    since_epoch = datetime.fromisoformat(since.replace("Z", "+00:00")).timestamp()
    files = sorted(Path(directory).glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in files[:100]:
        try:
            if path.stat().st_size > 2_000_000:
                continue
            ctx = json.loads(path.read_text(encoding="utf-8"))
            labels = ctx.get("alert", {}).get("labels", {})
            received = datetime.fromisoformat(ctx.get("received_at", "").replace("Z", "+00:00"))
            if all(labels.get(k) == v for k, v in identity.items()) and received.tzinfo and received.timestamp() >= since_epoch:
                found.append(ctx)
                if len(found) >= 20:
                    break
        except (OSError, ValueError, TypeError):
            continue
    return found, "ok"


def record_view(record):
    # Deliberately omit evidence snapshots, bindings, parameters and credentials.
    keys = ("remediation_id", "identity", "alert_context", "state", "action_type", "targets",
            "approval_requested_at", "approval_expires_at", "approved_at", "rejected_at",
            "action_started_at", "action_verified_at", "service_recovered_at", "service_verification",
            "slack_message_url", "slack_dispatch_status", "results")
    body = {key: getattr(record, key, None) for key in keys}
    body["results"] = [{k: r[k] for k in ("target", "status", "verified", "blocked_reason", "message", "detail") if k in r}
                       for r in record.results]
    body["alert_context"] = {k: record.alert_context.get(k) for k in ("labels", "fingerprint", "startsAt")}
    return body
