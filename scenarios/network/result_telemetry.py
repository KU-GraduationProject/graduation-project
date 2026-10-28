"""Publish measured experiment results to the existing Loki HTTP interface.

The JSONL result file is the durable source. Retries reuse its exact timestamp and
line; an endpoint-specific receipt avoids sending an acknowledged file twice.
No detector, notification route, or evaluation formula is changed here.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import urllib.request
from datetime import datetime, timezone


EVENT_TYPE = "network_experiment_result"


def result_metadata(experiment_id, repetition, transfer_id, verify, endpoint):
    recorded_ns = time.time_ns()
    return {
        "schema_version": 1,
        "event_type": EVENT_TYPE,
        "experiment_id": experiment_id,
        "result_id": f"{experiment_id}:{repetition}",
        "repetition": repetition,
        "transfer_id": transfer_id,
        "started_at": verify.t0,
        "detected_at": verify.firing_active_at,
        "measurement_endpoint": endpoint,
        "measurement_basis": "loki_ruler_activeAt_minus_orchestrator_t0",
        "recorded_at": datetime.fromtimestamp(recorded_ns / 1e9, timezone.utc).isoformat(),
        "recorded_at_ns": str(recorded_ns),
        "stages": {name: stage.ok for name, stage in verify.stages.items()},
    }


def enrich_result(outcome, metadata):
    """Keep the original measured seconds; a missed detection has no latency."""
    event = {**outcome.as_dict(), **metadata}
    event["detection_status"] = (
        "invalid" if not outcome.valid else "detected" if outcome.detected else "not_detected"
    )
    # Invalid/missed samples are visible in the table but never become zero MTTD.
    if not outcome.detected:
        event["mttd_seconds"] = None
    return event


def publish_result_file(path, loki_url, timeout=5):
    """Send persisted structured rows. Raises on failure; files remain retryable.

    Loki also deduplicates identical stream/timestamp/line entries if an HTTP
    acknowledgement is lost. No ingestion-time timestamp is generated on retry.
    """
    path = Path(path)
    raw = path.read_bytes()
    endpoint = loki_url.rstrip("/") + "/loki/api/v1/push"
    digest = hashlib.sha256(raw + endpoint.encode()).hexdigest()
    receipt = path.with_name(path.name + ".loki-receipt.json")
    if receipt.exists() and json.loads(receipt.read_text(encoding="utf8")).get("sha256") == digest:
        return 0

    values = []
    seen = set()
    for line in raw.decode("utf8").splitlines():
        event = json.loads(line)
        if event.get("event_type") != EVENT_TYPE or not event.get("result_id"):
            raise ValueError("Structured result metadata required; do not invent legacy timestamps")
        if event["result_id"] in seen:
            raise ValueError("Duplicate result_id in result file")
        seen.add(event["result_id"])
        timestamp = str(event["recorded_at_ns"])
        if not timestamp.isdigit():
            raise ValueError("Invalid recorded_at_ns")
        values.append([timestamp, line])
    if not values:
        return 0

    values.sort(key=lambda value: int(value[0]))
    payload = {"streams": [{
        "stream": {"job": "network-experiment", "event_type": EVENT_TYPE},
        "values": values,
    }]}
    request = urllib.request.Request(
        endpoint, data=json.dumps(payload, ensure_ascii=False).encode("utf8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        # Loki can return non-2xx success-shaped responses when ingestion is blocked.
        if response.status != 204:
            raise RuntimeError(f"Loki ingestion returned HTTP {response.status}")

    # Receipt is written only after acknowledgement and replaced atomically.
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf8", dir=path.parent,
                                     prefix=receipt.name, delete=False) as fh:
        json.dump({"sha256": digest, "endpoint": endpoint, "count": len(values)}, fh)
        pending = fh.name
    os.replace(pending, receipt)
    return len(values)
