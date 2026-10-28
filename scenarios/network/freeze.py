"""
설정 동결 (Step 6 / E4) — 최종 평가(V2) 전에 탐지에 영향을 주는 모든 설정을 고정한다.

동결 대상:
  - Allowlist 정책 (aiops/policy/allowlist.yml)
  - 생성된 Loki Ruler 규칙 (monitoring/loki/rules/fake/network-allowlist.yml)
  - Zeek 설정 (aiops/network-observer/zeek/local.zeek) — ConnThreshold N 포함
  - 전송 파라미터 / 탐지 제한시간 T / 임계값 등 (params)
  - Git SHA (가능하면)

각 파일의 SHA-256 과 params, git SHA, 생성 시각을 함께 저장한다. 평가 결과에 이 지문을
붙여 "어떤 설정으로 측정했는지" 를 재현 가능하게 만든다. V2 는 held-out 이므로, 동결
스냅샷과 현재 파일이 달라지면 평가를 신뢰할 수 없다(verify_unchanged 로 확인).

순수 로직(해시·비교)만 담는다. 파일 경로만 받으면 되므로 단독 테스트 가능하다.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone

# 동결 대상 파일 (repo 루트 기준 상대경로)
FROZEN_FILES = [
    "aiops/policy/allowlist.yml",
    "monitoring/loki/rules/fake/network-allowlist.yml",
    "aiops/network-observer/zeek/local.zeek",
]


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_sha(repo_root: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", repo_root, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5)
        return out.stdout.strip() or None if out.returncode == 0 else None
    except Exception:
        return None


@dataclass
class FrozenConfig:
    created_at: str
    git_sha: str | None
    params: dict
    file_hashes: dict  # repo 상대경로 -> sha256 (파일 없으면 None)

    def as_dict(self) -> dict:
        return {
            "created_at": self.created_at, "git_sha": self.git_sha,
            "params": self.params, "file_hashes": self.file_hashes,
        }

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.as_dict(), fh, ensure_ascii=False, indent=2)

    @classmethod
    def load(cls, path: str) -> "FrozenConfig":
        with open(path, "r", encoding="utf-8") as fh:
            d = json.load(fh)
        return cls(created_at=d["created_at"], git_sha=d.get("git_sha"),
                   params=d.get("params") or {}, file_hashes=d.get("file_hashes") or {})


def freeze_config(repo_root: str, params: dict, files=FROZEN_FILES) -> FrozenConfig:
    """현재 파일 해시 + params + git SHA 로 동결 스냅샷을 만든다."""
    hashes = {}
    for rel in files:
        full = os.path.join(repo_root, rel)
        hashes[rel] = sha256_file(full) if os.path.exists(full) else None
    return FrozenConfig(
        created_at=datetime.now(timezone.utc).isoformat(),
        git_sha=_git_sha(repo_root),
        params=dict(params),
        file_hashes=hashes,
    )


def verify_unchanged(frozen: FrozenConfig, repo_root: str, files=FROZEN_FILES) -> list[str]:
    """동결 이후 바뀐(또는 사라진/생긴) 파일 목록. 빈 리스트면 설정이 그대로다."""
    drift = []
    for rel in files:
        full = os.path.join(repo_root, rel)
        current = sha256_file(full) if os.path.exists(full) else None
        if frozen.file_hashes.get(rel) != current:
            drift.append(rel)
    return drift
