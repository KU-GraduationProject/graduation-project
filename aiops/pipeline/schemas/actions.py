"""RCA recommendation vocabulary; accepting a name never makes an executor available.

Names mirror the Notion Remediation proposal and its policy action catalog. The Pipeline
image deliberately has no dependency on the Controller's executable policy modules.
"""
from typing import Literal, get_args

ActionType = Literal[
    "NONE", "NOTIFY", "THROTTLE", "RESTART", "PAUSE", "ISOLATE", "SCALE",
    "CAPTURE", "UNPAUSE", "RECONNECT", "UNTHROTTLE", "BLOCK_EGRESS",
    "KILL_SESSIONS", "BACKUP_DB", "RESTORE_DB", "DISABLE_DB_ROLE", "ROLLBACK",
    "RECREATE", "LOCK_ACCOUNT", "REVOKE_SESSION", "DISABLE_FEATURE", "SET_LOG_LEVEL",
    "PACKET_CAPTURE", "SILENCE_ALERT", "BLOCK_PATH", "RATE_LIMIT", "MAINTENANCE_MODE",
    "RESTRICT_BUCKET", "DISABLE_KEY", "RESTART_HOST_SVC", "CLEAN_DISK", "RECORD_INCIDENT",
    "UNLOCK_ACCOUNT", "ENABLE_FEATURE",
]
RECOMMENDED_ACTIONS = get_args(ActionType)
