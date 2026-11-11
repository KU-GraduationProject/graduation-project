"""
경보 시점 입력 컨텍스트 저장 (평가용, 기본 꺼짐).

CONTEXT_CAPTURE_DIR 가 있을 때만 analyze_alerts 가 경보별로 수집 결과를 JSON 으로 남긴다.
키는 eval/harness.py 가 읽는 observations 형식과 같다:
  received_at, container, rule, metrics, logs, log_query, network (+ alert, builder, identity_status)

pipeline 은 시나리오를 모르므로 시나리오 id·변형·정답을 넣지 않는다. 시나리오 쪽 도구
(scenarios/v2/fixtures.py pair)가 실행 기록과 시각으로 짝지어 픽스처를 만든다.
저장 전에 로그 줄과 네트워크 이벤트의 비밀값을 가린다.
"""

import hashlib
import json
import logging
import os
import re
from datetime import datetime

from prompt.log_line import _SECRET_KEY, mask_secrets

logger = logging.getLogger(__name__)
_SECRET_KEY_RE = re.compile(r"(?i)" + _SECRET_KEY)


def _iso(t):
    return t.isoformat() if isinstance(t, datetime) else t


def _mask_obj(o):
    """dict/list 안 문자열을 가린다. 비밀값 이름의 키는 값을 통째로 가린다."""
    if isinstance(o, dict):
        return {k: ("***" if _SECRET_KEY_RE.fullmatch(str(k)) and isinstance(o[k], (str, int, float))
                    else _mask_obj(v)) for k, v in o.items()}
    if isinstance(o, list):
        return [_mask_obj(v) for v in o]
    return mask_secrets(o) if isinstance(o, str) else o


def mask_line(line: str) -> str:
    """JSON 줄은 구조를 유지한 채 가린다(원문에 바로 쓰면 JSON 이 깨져 렌더링이 달라진다)."""
    try:
        rec = json.loads(line)
    except (ValueError, TypeError):
        rec = None
    if isinstance(rec, dict):
        return json.dumps(_mask_obj(rec), ensure_ascii=False)
    return mask_secrets(line)


def build_context(alert, received_at, container, rule, metrics, logs, log_meta, network,
                  builder, identity_status) -> dict:
    return {
        "received_at": _iso(received_at),
        "alert": {"status": alert.status, "labels": alert.labels.model_dump(exclude_none=True),
                  "annotations": dict(alert.annotations), "startsAt": alert.startsAt,
                  "endsAt": alert.endsAt, "fingerprint": alert.fingerprint},
        "container": container,
        "rule": rule.as_dict() if rule else None,
        "metrics": dict(metrics),
        "logs": [{"ts": r["ts"], "labels": r.get("labels", {}), "line": mask_line(r.get("line", ""))}
                 for r in logs],
        "log_query": ({"start": _iso(log_meta["start"]), "end": _iso(log_meta["end"]),
                       "limit": log_meta.get("limit")} if log_meta else None),
        "network": {"service": network.service, "start": _iso(network.start), "end": _iso(network.end),
                    "events": _mask_obj(list(network.events)), "errors": list(network.errors),
                    "skipped": network.skipped, "truncated": network.truncated},
        "builder": builder,
        "identity_status": identity_status,
    }


def save_context(directory: str, ctx: dict) -> str:
    os.makedirs(directory, exist_ok=True)
    a = ctx["alert"]
    key = a.get("fingerprint") or hashlib.sha256(
        json.dumps(a, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:12]
    stamp = re.sub(r"[^0-9T]", "", ctx["received_at"] or "")[:15]
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{stamp}-{a['labels'].get('alertname', 'alert')}-{key}") + ".json"
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(ctx, fh, ensure_ascii=False, indent=1, default=str)
    return path
