"""Memory THROTTLE primitives; operator limits only, never LLM kernel values.

Caller supplies existing immutable target binding and approval deadline. These
helpers use that executor's _mutation_container hook immediately before writes.
"""
import time

from executor.base import blocked, succeeded, ExecutionResult

MIN_HEADROOM_BYTES = 32 * 1024 * 1024


def _limits(doc):
    host = doc.get("HostConfig") or {}
    return {"memory": host.get("Memory", 0), "memory_swap": host.get("MemorySwap", 0),
            "cpu_quota": host.get("CpuQuota", 0), "cpu_period": host.get("CpuPeriod", 0),
            "nano_cpus": host.get("NanoCpus", 0)}


def _headroom(container, limit):
    sample = container.stats(stream=False)
    memory = sample.get("memory_stats") or {}
    usage = memory.get("usage")
    # Total usage (including reclaimable cache) is deliberately conservative.
    # A limit below current allocation is an OOM injection, not remediation.
    if type(usage) is not int or usage < 0 or usage + max(MIN_HEADROOM_BYTES, usage // 4) > limit:
        raise ValueError("memory_limit_below_safe_current_usage_headroom")
    return usage


def apply_memory_limit(executor, target, evidence, limit):
    action = "THROTTLE"
    mutated = False
    try:
        if type(limit) is not int or not 64 * 1024 * 1024 <= limit <= 64 * 1024**3:
            raise ValueError("operator_memory_limit_required")
        before_doc = executor._reload_inspect(target)
        original = _limits(before_doc)
        # A finite original limit must actually be reduced, while retaining safe
        # headroom. No swap-default guessing: zero is Docker's unspecified value
        # and is rejected because restoring it via update is ambiguous.
        if type(original["memory"]) is not int or original["memory"] <= limit:
            raise ValueError("finite_stricter_memory_limit_required")
        if type(original["memory_swap"]) is not int or original["memory_swap"] == 0:
            raise ValueError("explicit_original_memory_swap_required")
        if original["memory_swap"] != -1 and original["memory_swap"] < original["memory"]:
            raise ValueError("invalid_original_memory_swap")
        expected = (evidence.get("resources") or {})
        if any(expected.get(k) != original[k] for k in ("memory", "memory_swap")):
            raise ValueError("original_memory_evidence_changed")
        container = executor._mutation_container(target)
        usage = _headroom(container, limit)
        # Bound executor rechecks deadline/identity at this second boundary,
        # after a potentially slow stats call.
        container = executor._mutation_container(target)
        mutated = True
        container.update(mem_limit=limit, memswap_limit=limit)  # memory-only; no swap growth.
        after = _limits(executor._reload_inspect(target))
        if after["memory"] != limit or after["memory_swap"] != limit or any(after[k] != original[k] for k in ("cpu_quota", "cpu_period", "nano_cpus")):
            raise ValueError("memory_limit_effect_unconfirmed")
        return succeeded(action, target, "memory_limit_verified",
                         before={**original, "resource": "memory", "memory_usage": usage},
                         after={**after, "resource": "memory", "applied_memory": limit, "applied_memory_swap": limit})
    except Exception:
        return ExecutionResult(action, target, "UNKNOWN", detail="memory_limit_effect_unconfirmed_no_retry") if mutated else blocked(action, target, "memory_throttle_preflight_rejected")


def restore_memory_limit(executor, target, evidence):
    action = "UNTHROTTLE"
    mutated = False
    try:
        original = evidence.get("resources") or {}
        applied = evidence.get("memory_throttle") or {}
        current_doc = executor._reload_inspect(target)
        current = _limits(current_doc)
        limit, swap = original.get("memory"), original.get("memory_swap")
        if (type(limit) is not int or limit < 64 * 1024 * 1024 or type(swap) is not int
                or swap == 0 or swap != -1 and swap < limit
                or current["memory"] != applied.get("applied_memory")
                or current["memory_swap"] != applied.get("applied_memory_swap")):
            raise ValueError("memory_restore_original_or_ownership_missing")
        container = executor._mutation_container(target)
        _headroom(container, limit)
        container = executor._mutation_container(target)
        mutated = True
        container.update(mem_limit=limit, memswap_limit=swap)
        after = _limits(executor._reload_inspect(target))
        if after["memory"] != limit or after["memory_swap"] != swap or any(after[k] != current[k] for k in ("cpu_quota", "cpu_period", "nano_cpus")):
            raise ValueError("memory_restore_effect_unconfirmed")
        return succeeded(action, target, "original_memory_limit_restored", before=current, after=after)
    except Exception:
        return ExecutionResult(action, target, "UNKNOWN", detail="memory_restore_effect_unconfirmed_no_retry") if mutated else blocked(action, target, "memory_restore_preflight_rejected")
