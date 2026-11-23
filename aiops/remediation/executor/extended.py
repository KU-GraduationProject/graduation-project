"""Explicitly enabled DB, deployment and application-API executor dispatch.

Factories are lazy: disabled mode and unconfigured startup never connect to
Docker, databases or application APIs. Each execution keeps its own selection;
the Controller's global executor is never swapped between concurrent incidents.
"""
import threading

from executor.base import DisabledExecutor
from policy.catalog import ACTION_FAMILIES

EXTENDED_ACTIONS = frozenset({"KILL_SESSIONS", "ROLLBACK", "RECREATE", "LOCK_ACCOUNT",
                              "REVOKE_SESSION", "DISABLE_FEATURE", "UNLOCK_ACCOUNT", "ENABLE_FEATURE"})
FAMILY_NAMES = {"db": "postgres", "deployment": "deployment", "app_api": "app_api"}


class ExtendedExecutorRouter:
    name = "extended"
    changes_system = True

    def __init__(self, executors=None, docker_executor=None):
        self._executors = dict(executors or {})
        self._docker = docker_executor or DisabledExecutor()
        self._lock = threading.RLock()

    def for_action(self, action_type):
        action = str(action_type or "").upper()
        if action not in EXTENDED_ACTIONS:
            return self._docker
        if action in {"RECREATE", "ROLLBACK"} and getattr(self._docker, "name", None) == "remote":
            # A disabled remote capability must not silently select PC1 Docker.
            # route_action will reject until the remote feature is opted in.
            return self._docker
        name = FAMILY_NAMES[ACTION_FAMILIES[action]]
        with self._lock:
            if name not in self._executors:
                if name == "postgres":
                    from executor.postgres import PostgresExecutor
                    instance = PostgresExecutor()
                elif name == "deployment":
                    from executor.deployment import DeploymentExecutor
                    instance = DeploymentExecutor()
                else:
                    from executor.app_api import AppApiExecutor
                    instance = AppApiExecutor()
                self._executors[name] = instance
            return self._executors[name]

    def for_record(self, record):
        selected = self.for_action(record.action_type)
        # A record cannot move to another execution family after approval.
        if record.executor_name and record.executor_name != selected.name:
            return DisabledExecutor()
        return selected


def select_executor(action_type, configured):
    if isinstance(configured, ExtendedExecutorRouter):
        return configured.for_action(action_type)
    return configured


def is_extended_executor(executor):
    return getattr(executor, "name", None) in set(FAMILY_NAMES.values())
