"""Signal response limits, independent of evaluation labels and LLM prompts.

Profiles constrain recommendations; they never select actions or grant execution
rights. New ambiguous signals always require an incident-bound manual proposal.
"""
from dataclasses import dataclass

import store


@dataclass(frozen=True)
class ResponseProfile:
    service: str
    runtime: str
    actions: tuple[str, ...]
    note: str


PROFILES = {
    "V2ReconScan": ResponseProfile("frontend", "container", (), "Scan attempt: notify; no path/rate-limit executor."),
    "V2RepeatedExternalConnections": ResponseProfile("backend", "container", ("ISOLATE", "BLOCK_EGRESS"), "Repeated unauthorized connections; not proof of C2."),
    "V2UnauthorizedDataTransfer": ResponseProfile("backend", "container", ("ISOLATE",), "Unauthorized byte transfer; verify context before isolation."),
    "V2UnauthorizedTransferEarly": ResponseProfile("backend", "container", ("ISOLATE",), "Observer transfer threshold reached; final bytes are not yet known."),
    "V2InternalPortScan": ResponseProfile("backend", "container", ("ISOLATE",), "Many internal endpoints; verify authorized administration."),
    "V2DBReadSurge": ResponseProfile("db", "host", (), "Read volume cannot distinguish backup from theft; notify only."),
    "V2LoginBruteForce": ResponseProfile("backend", "container", (), "Aggregate login failures do not identify an account to lock."),
    "V2DependencyErrors": ResponseProfile("backend", "container", ("RESTART", "RECREATE", "ROLLBACK"), "Dependency failure symptom; verify cause and immutable deployment plan."),
}


def profile_for(alert):
    """Names identify signals, never scenario IDs or ground truth."""
    return PROFILES.get(alert.get("labels", {}).get("alertname"))


def validate_response(alert, analysis):
    """No cross-target repair or guessed DB/account identity from aggregate alerts."""
    profile = profile_for(alert)
    if profile is None:
        return
    labels = alert.get("labels", {})
    if labels.get("service") != profile.service or labels.get("runtime") != profile.runtime:
        raise ValueError("response_profile_identity_mismatch")
    action = str(analysis.get("action_type", "NONE")).upper()
    if action in {"NONE", "NOTIFY"}:
        return
    if action not in profile.actions:
        raise ValueError("response_profile_requires_notification")
    _, identity = store.incident_key(alert)
    if analysis.get("action_targets") != [identity["target"]]:
        raise ValueError("response_profile_target_mismatch")


def capabilities():
    return {name: {"service": p.service, "runtime": p.runtime,
                   "actions": ["NONE", "NOTIFY", *p.actions],
                   "manual_proposal_required": True, "note": p.note}
            for name, p in PROFILES.items()}
