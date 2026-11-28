"""Read-only reuse of the team's v2 evidence formatter in an isolated interpreter.

No model calls, prompt changes or schema changes. Capture + collector reports
reproduce the metric/log IDs displayed to the model, including ranking/budgets.
"""
from datetime import datetime
import json
import inspect
from pathlib import Path
import sys
from types import SimpleNamespace


def render(context, sources):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "aiops" / "pipeline"))
    from prompt.builder_v2 import _metrics_section, _logs_section, SECTION_BUDGETS
    from identity import LogEvidence
    anchor = datetime.fromisoformat(context["alert"]["startsAt"].replace("Z", "+00:00")).timestamp()
    metrics = _metrics_section(context.get("metrics", {}), anchor, SECTION_BUDGETS["metrics"])[0]
    rule = SimpleNamespace(**context["rule"]) if context.get("rule") else None
    logs = LogEvidence(context.get("logs", []), **sources.get("logs", {}))
    meta = dict(context.get("log_query") or {})
    for key in ("start", "end"):
        if meta.get(key):
            meta[key] = datetime.fromisoformat(meta[key].replace("Z", "+00:00"))
    # Current main collects account target candidates while formatting logs.
    # Older deployed formatters lack this output argument; neither is mutated.
    options = {"targets": {}} if "targets" in inspect.signature(_logs_section).parameters else {}
    log_text = _logs_section(logs, rule, meta, SECTION_BUDGETS["logs"], **options)[0]
    return metrics + "\n" + log_text


if __name__ == "__main__":
    payload = json.load(sys.stdin)
    try:
        if payload["context"].get("builder") != "v2":
            raise ValueError("not_v2")
        print(json.dumps({"text": render(payload["context"], payload.get("sources", {}))}, ensure_ascii=False))
    except Exception as exc:
        print(json.dumps({"error": type(exc).__name__}))
