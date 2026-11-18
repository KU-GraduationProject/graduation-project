"""`RunContext` (05 §4): every entry point gets its clock, id source and run identity injected."""
from __future__ import annotations

import os
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from contracts import canonical

CODE_VERSION = "0.1.0"
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _random_hex8() -> str:
    return secrets.token_hex(4)


@dataclass
class RunContext:
    orchestrator: str
    dag_id: str | None
    airflow_run_id: str | None
    task_id: str | None
    try_number: int | None
    git_sha: str
    git_dirty: bool = False
    map_index: int | None = None
    code_version: str = CODE_VERSION
    image_ref: str | None = None
    params: dict = field(default_factory=dict)
    clock: Callable[[], datetime] = _utcnow
    hex8: Callable[[], str] = _random_hex8
    started_at: datetime | None = None

    def __post_init__(self):
        if not _GIT_SHA.fullmatch(self.git_sha or ""):
            # 03 §2: unknown git_sha is refused, never stored as "unknown".
            raise ValueError("git_sha must be 40 lowercase hex characters (set DP_GIT_SHA)")
        self.map_index = canonical.normalize_map_index(self.map_index)
        if self.started_at is None:
            self.started_at = self.clock()

    @property
    def run_id(self) -> str:
        return canonical.run_id(self.orchestrator, self.dag_id, self.airflow_run_id, self.task_id,
                                self.try_number, self.map_index)

    def now(self) -> datetime:
        return self.clock()

    def new_build_id(self, prefix: str, at: datetime | None = None) -> str:
        return canonical.build_id(prefix, at or self.now(), self.hex8())

    def require_clean(self) -> None:
        """Operational DAGs refuse images built from uncommitted changes (03 §2)."""
        if self.git_dirty and os.environ.get("DP_ENV", "development") == "production":
            raise RuntimeError("git_dirty=true image refused in production (03 §2)")

    def run_record(self, status: str, ended_at: datetime | None = None) -> dict:
        return {
            "run_id": self.run_id, "orchestrator": self.orchestrator, "dag_id": self.dag_id,
            "airflow_run_id": self.airflow_run_id, "task_id": self.task_id, "try_number": self.try_number,
            "map_index": self.map_index, "code_version": self.code_version, "git_sha": self.git_sha,
            "git_dirty": self.git_dirty, "image_ref": self.image_ref, "params": canonical.canonical_str(self.params),
            "started_at": canonical.fmt_ts(self.started_at),
            "ended_at": canonical.fmt_ts(ended_at) if ended_at else None,
            "status": status, "_schema_version": "1.0",
        }


def from_env(orchestrator: str, dag_id=None, airflow_run_id=None, task_id=None, try_number=None,
             map_index=None, params=None) -> RunContext:
    """Build a context from `DP_GIT_SHA` / `DP_GIT_DIRTY` / `DP_IMAGE_REF` (injected at image build)."""
    return RunContext(orchestrator=orchestrator, dag_id=dag_id, airflow_run_id=airflow_run_id, task_id=task_id,
                      try_number=try_number, map_index=map_index,
                      git_sha=os.environ.get("DP_GIT_SHA", "").strip().lower(),
                      git_dirty=os.environ.get("DP_GIT_DIRTY", "false").lower() in ("1", "true", "yes"),
                      image_ref=os.environ.get("DP_IMAGE_REF") or None, params=params or {})
