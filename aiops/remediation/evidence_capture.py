"""
증거 보존(CAPTURE) — 파괴적 조치 직전의 읽기 전용 조사 자료 (노션 선행 단계).

evidence.py 의 스냅샷은 "되돌리기"용 상태다. 이 모듈은 "나중에 조사"할 자료를 남긴다.
  - 컨테이너 로그 마지막 MAX_LOG_LINES 줄 (최대 MAX_LOG_BYTES)
  - docker top 프로세스 목록 (최대 MAX_PROCESSES 개)
  - Loki 의 사건 시간대 Zeek 네트워크 이벤트 (최대 MAX_NETWORK_LINES 줄, 실패해도 차단하지 않음)

docker exec·패킷 캡처는 하지 않는다. 비밀값으로 보이는 값은 저장 전에 가린다.
수집물은 state 디렉터리 밖으로 나가지 않고(0600), 레코드에는 manifest 만 남는다.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import time
from pathlib import Path

logger = logging.getLogger(__name__)

MAX_LOG_LINES = 500
MAX_LOG_BYTES = 256 * 1024
MAX_PROCESSES = 200
MAX_NETWORK_LINES = 200
DEFAULT_RETENTION_DAYS = 14

_AUTH_HEADER = re.compile(r"(?i)\b((?:proxy-)?authorization\s*[:=]\s*)(?:(?:bearer|basic|token)\s+)?[^\s\"',;&]+")
_BEARER = re.compile(r"(?i)\b(bearer\s+)[^\s\"',;&]+")
_SECRET = re.compile(
    r"(?i)\b(authorization|bearer|token|access_token|refresh_token|password|passwd|pwd|secret|"
    r"api[_-]?key|cookie|set-cookie|jwt)\b(\"?\s*[:=]\s*\"?|\s+)([^\s\"',;&]+)")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")


class CaptureError(RuntimeError):
    """조사 자료를 남길 수 없다 — 대상 조치를 차단하는 근거."""


def mask(text: str) -> str:
    text = _JWT.sub("[MASKED_JWT]", str(text))
    text = _AUTH_HEADER.sub(lambda m: m.group(1) + "[MASKED]", text)
    text = _BEARER.sub(lambda m: m.group(1) + "[MASKED]", text)
    return _SECRET.sub(lambda m: m.group(0) if m.group(3).startswith("[MASKED") else
                       m.group(1) + m.group(2) + "[MASKED]", text)


def container_capture(container) -> dict:
    """SDK 컨테이너 객체에서 로그·프로세스를 읽는다 (읽기 전용)."""
    raw = container.logs(tail=MAX_LOG_LINES, timestamps=True, stdout=True, stderr=True)
    data = raw if isinstance(raw, bytes) else str(raw).encode("utf-8", "replace")
    truncated = len(data) > MAX_LOG_BYTES
    text = data[-MAX_LOG_BYTES:].decode("utf-8", "replace")
    lines = [mask(line) for line in text.splitlines()[-MAX_LOG_LINES:]]
    top = container.top() or {}
    rows = list(top.get("Processes") or [])
    return {
        "log_lines": lines,
        "log_truncated": truncated,
        "process_titles": [str(t) for t in top.get("Titles") or []],
        "processes": [[mask(str(col)) for col in row] for row in rows[:MAX_PROCESSES]],
        "processes_truncated": len(rows) > MAX_PROCESSES,
    }


def network_events(loki_url: str | None, service: str | None, start_ns: int, end_ns: int,
                   http_get=None) -> dict:
    """Loki 의 Zeek 네트워크 이벤트. 보조 자료라 실패는 기록만 하고 차단하지 않는다."""
    if not loki_url or not service:
        return {"status": "not_configured", "lines": []}
    try:
        if http_get is None:
            import httpx
            http_get = httpx.get
        lines = []
        for side in ("src_service", "dst_service"):
            response = http_get(loki_url.rstrip("/") + "/loki/api/v1/query_range", params={
                "query": '{log_type="network", %s="%s"}' % (side, service),
                "start": str(start_ns), "end": str(end_ns),
                "limit": str(MAX_NETWORK_LINES), "direction": "backward"}, timeout=5)
            response.raise_for_status()
            for stream in response.json().get("data", {}).get("result", []):
                lines.extend(mask(value[1]) for value in stream.get("values", []))
        return {"status": "ok", "lines": lines[:MAX_NETWORK_LINES],
                "truncated": len(lines) > MAX_NETWORK_LINES}
    except Exception as exc:
        return {"status": "unavailable:" + type(exc).__name__, "lines": []}


def _prune(root: Path, retention_days: int) -> None:
    cutoff = time.time() - retention_days * 86400
    for child in root.iterdir() if root.exists() else ():
        try:
            if child.is_dir() and child.stat().st_mtime < cutoff:
                shutil.rmtree(child)
        except OSError:
            logger.warning("[Capture] 보관 기한이 지난 수집물을 지우지 못했다: %s", child.name)


def preserve(capture_for, remediation_id: str, targets, state_dir: str, *,
             loki_url: str | None = None, service: str | None = None, alert_started_at: str | None = None,
             retention_days: int | None = None, http_get=None) -> list:
    """
    대상별로 수집해 저장하고 manifest 목록을 돌려준다. 하나라도 실패하면 CaptureError.

    capture_for(target) -> dict 는 실행기의 읽기 전용 수집 함수다 (로컬 Docker 또는 원격 Agent).
    """
    if not _ID.fullmatch(str(remediation_id)):
        raise CaptureError("invalid_remediation_id")
    targets = [t for t in (targets or ()) if t]
    if not targets:
        raise CaptureError("no_targets_to_capture")
    if retention_days is None:
        retention_days = int(os.getenv("REMEDIATION_CAPTURE_RETENTION_DAYS", str(DEFAULT_RETENTION_DAYS)))
    root = Path(state_dir) / "captures"
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        _prune(root, retention_days)
        folder = root / remediation_id
        folder.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        raise CaptureError("capture_store_unavailable") from exc

    end_ns = time.time_ns()
    start_ns = end_ns - 3600 * 10**9
    if alert_started_at:
        from datetime import datetime
        try:
            start_ns = int(datetime.fromisoformat(str(alert_started_at).replace("Z", "+00:00"))
                           .timestamp() * 10**9) - 300 * 10**9
        except ValueError:
            pass
    network = network_events(loki_url, service, start_ns, end_ns, http_get=http_get)

    manifests = []
    for target in targets:
        if not _ID.fullmatch(str(target)):
            raise CaptureError("invalid_capture_target")
        try:
            document = capture_for(target)
        except Exception as exc:
            raise CaptureError(f"capture_failed:{target}:{type(exc).__name__}") from exc
        if not isinstance(document, dict) or not isinstance(document.get("log_lines"), list):
            raise CaptureError(f"capture_unavailable:{target}")
        document = {**document, "target": target, "remediation_id": remediation_id,
                    "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "network_events": network}
        body = json.dumps(document, ensure_ascii=False, sort_keys=True).encode("utf-8")
        path = folder / f"{target}.json"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(body)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            raise CaptureError(f"capture_store_failed:{target}") from exc
        manifests.append({"target": target, "path": str(path), "sha256": hashlib.sha256(body).hexdigest(),
                          "bytes": len(body), "collected_at": document["collected_at"],
                          "log_lines": len(document["log_lines"]),
                          "processes": len(document.get("processes") or []),
                          "network_events": network["status"]})
    return manifests
