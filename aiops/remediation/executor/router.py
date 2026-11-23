"""Independent capability gate. A policy edit cannot invent an executor."""
from policy.catalog import ACTION_FAMILIES, DOCKER_ACTIONS
from executor.extended import EXTENDED_ACTIONS, FAMILY_NAMES, select_executor


def route_action(action_type, runtime, executor):
    action = str(action_type or "").strip().upper()
    family = ACTION_FAMILIES.get(action)
    if family is None:
        return False, "undefined_action_type"
    executor = select_executor(action, executor)
    if action in EXTENDED_ACTIONS:
        if runtime not in ({"container"} if family == "deployment" else {"container", "host"}):
            return False, f"unsupported_runtime:{runtime or 'missing'}"
        name = getattr(executor, "name", None)
        if family == "deployment" and name == "remote" and getattr(executor, "supports_deployment", False):
            return True, "remote_deployment_approval_required"
        if name == "disabled" and not getattr(executor, "changes_system", True):
            return True, "execution_disabled"
        if name != FAMILY_NAMES[family]:
            return False, "executor_family_mismatch"
        return True, "ok"
    if action not in DOCKER_ACTIONS:
        return False, ("notification_only" if family == "human" else
                       f"executor_not_implemented:{family}")
    if runtime != "container":
        return False, f"unsupported_runtime:{runtime or 'missing'}"
    name = getattr(executor, "name", None)
    if name == "disabled" and not getattr(executor, "changes_system", True):
        return True, "execution_disabled"
    if name not in {"local_docker", "remote"}:
        return False, "executor_family_mismatch"
    return True, "ok"
