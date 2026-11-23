"""Notion action/scenario vocabulary. Membership never grants execution rights.

Risk and readiness are fixed by remediation_policy.yml. Names for unimplemented
prose proposals are future interface contracts, not claims of working executors.
"""
ACTION_FAMILIES = {
    "NONE": "human", "NOTIFY": "human", "SCALE": "deployment",
    "RESTART": "docker", "PAUSE": "docker", "UNPAUSE": "docker",
    "THROTTLE": "docker", "UNTHROTTLE": "docker",
    "ISOLATE": "docker", "RECONNECT": "docker", "CAPTURE": "observation",
    "BLOCK_EGRESS": "network", "KILL_SESSIONS": "db",
    "BACKUP_DB": "db", "RESTORE_DB": "db", "DISABLE_DB_ROLE": "db",
    "ROLLBACK": "deployment", "RECREATE": "deployment",
    "LOCK_ACCOUNT": "app_api", "REVOKE_SESSION": "app_api",
    "DISABLE_FEATURE": "app_api", "UNLOCK_ACCOUNT": "app_api", "ENABLE_FEATURE": "app_api",
    "SET_LOG_LEVEL": "observation",
    "PACKET_CAPTURE": "observation", "SILENCE_ALERT": "observation",
    "BLOCK_PATH": "nginx", "RATE_LIMIT": "nginx", "MAINTENANCE_MODE": "nginx",
    "RESTRICT_BUCKET": "minio", "DISABLE_KEY": "minio",
    "RESTART_HOST_SVC": "host", "CLEAN_DISK": "host", "RECORD_INCIDENT": "record",
}
DOCKER_ACTIONS = frozenset({"RESTART", "PAUSE", "UNPAUSE", "THROTTLE",
                            "UNTHROTTLE", "ISOLATE", "RECONNECT"})
RECOVERY_ACTIONS = frozenset({"UNPAUSE", "UNTHROTTLE", "RECONNECT"})

# Design candidates only: this mapping is never an automatic execution rule.
SCENARIO_RECOMMENDATIONS = {
    "S1-a": ("BLOCK_PATH",), "S1-b": ("NOTIFY", "RATE_LIMIT"),
    "S1-c": ("LOCK_ACCOUNT",), "S1-d": ("RATE_LIMIT",),
    "S2-a": ("THROTTLE", "RECREATE"), "S2-b": ("BLOCK_EGRESS", "ISOLATE"),
    "S2-c": ("ISOLATE",), "S2-d": ("ISOLATE",),
    "S2-e": ("ISOLATE", "KILL_SESSIONS"), "S3-a": ("ISOLATE",),
    "S3-b": ("RECREATE",), "F1-a": ("THROTTLE",), "F1-b": ("RESTART",),
    "F1-c": ("RESTART", "ROLLBACK"), "F1-d": ("CLEAN_DISK",),
    "F2-a": ("RESTART",), "F2-b": ("RESTART_HOST_SVC",),
    "F2-c": ("KILL_SESSIONS",), "F2-d": ("NOTIFY",),
    "F3-a": ("ROLLBACK",), "F3-b": ("RECREATE",),
    "F2-cause-classification": ("NOTIFY",),
}


def scenario_candidates(scenario_id):
    """For planning/reporting; policy, approval and identity gates remain mandatory."""
    return SCENARIO_RECOMMENDATIONS.get(scenario_id, ())
