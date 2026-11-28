"""Explicitly supported planned adapters; construction performs no service IO."""
EGRESS = frozenset({"BLOCK_EGRESS", "UNBLOCK_EGRESS"})
DATABASE = frozenset({"RESTORE_DB", "DISABLE_DB_ROLE", "ENABLE_DB_ROLE"})
PROMOTION = frozenset({"PROMOTE_RESTORED_DB", "ROLLBACK_DB_PROMOTION"})
OBSERVATION = frozenset({"SET_LOG_LEVEL", "RESTORE_LOG_LEVEL", "PACKET_CAPTURE", "SILENCE_ALERT", "EXPIRE_SILENCE"})
OPERATIONS = frozenset({"BLOCK_PATH", "RATE_LIMIT", "MAINTENANCE_MODE", "RESTORE_NGINX", "RESTRICT_BUCKET", "RESTORE_BUCKET", "DISABLE_KEY", "ENABLE_KEY", "RESTART_HOST_SVC", "CLEAN_DISK", "RECORD_INCIDENT"})
ACTIONS = EGRESS | DATABASE | PROMOTION | OBSERVATION | OPERATIONS
REMOTE_ACTIONS = EGRESS | OBSERVATION | (OPERATIONS - {"RESTART_HOST_SVC", "CLEAN_DISK", "RECORD_INCIDENT"})
NAMES = frozenset({"egress", "database_admin", "database_promotion", "observability", "operations"})
RECOVERY_MAP = {"PROMOTE_RESTORED_DB": "ROLLBACK_DB_PROMOTION", "BLOCK_EGRESS": "UNBLOCK_EGRESS", "DISABLE_DB_ROLE": "ENABLE_DB_ROLE",
                "SET_LOG_LEVEL": "RESTORE_LOG_LEVEL", "SILENCE_ALERT": "EXPIRE_SILENCE",
                "BLOCK_PATH": "RESTORE_NGINX", "RATE_LIMIT": "RESTORE_NGINX", "MAINTENANCE_MODE": "RESTORE_NGINX",
                "RESTRICT_BUCKET": "RESTORE_BUCKET", "DISABLE_KEY": "ENABLE_KEY"}
RESTORE_ACTIONS = frozenset(RECOVERY_MAP.values())


def module_for(action):
    if action in EGRESS:
        from executor import egress as module
    elif action in DATABASE:
        from executor import database_admin as module
    elif action in PROMOTION:
        from executor import database_promotion as module
    elif action in OBSERVATION:
        from executor import observability as module
    elif action in OPERATIONS:
        from executor import edge_storage_host as module
    else:
        raise ValueError("unsupported_managed_action")
    return module


def create_executor(action):
    module = module_for(action)
    if action in EGRESS:
        return module.EgressExecutor()
    if action in DATABASE:
        return module.DatabaseAdminExecutor()
    if action in PROMOTION:
        return module.DatabasePromotionExecutor()
    if action in OBSERVATION:
        return module.ObservabilityExecutor()
    return module.EdgeStorageHostExecutor()


def validate_parameters(action, parameters):
    return module_for(action).validate_parameters(action, parameters)
