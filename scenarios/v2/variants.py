"""
변형 생성 — (scenario_id, variant_id, seed) 구조 (scenarios-v2).

- **랜덤 변형:** 변형마다 축별 분포를 두고, seed 로 결정적으로 인스턴스를 뽑는다.
  같은 (scenario_id, variant_id, seed) → 같은 인스턴스. 다른 seed → (거의 항상) 다른 인스턴스.
- **정답 레이블은 뽑지 않는다.** 인스턴스는 주입 파라미터만 담고, 정답은 registry 에서 조회한다.
- **튜닝용 형태 변형만 여기(저장소) 둔다.** 평가용 형태 변형은 scenarios/v2/heldout/ 에만 있고
  (gitignore), 폴더가 없으면 조용히 건너뛴다 — 저장소 코드는 heldout 없이도 동작한다.

분포 표기: ("choice",[..]) / ("int",lo,hi) / ("float",lo,hi) / ("fixed",v).
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field

from v2 import registry

# --------------------------------------------------------------------------- #
# 튜닝용 변형 스펙 (VARIANTS.md 와 일치). 평가용은 heldout 에만.
# --------------------------------------------------------------------------- #
VARIANT_SPECS: dict[str, dict[str, dict]] = {
    "s1_a_input_attack": {
        "single-path": {"strength": ("choice", ["weak", "medium", "strong"]),
                        "time_pattern": ("choice", ["burst", "spread"]),
                        "requests": ("int", 6, 20), "paths": ("fixed", 1)},
        "slow-probe": {"strength": ("choice", ["weak", "medium"]),
                       "time_pattern": ("fixed", "spread"), "requests": ("int", 6, 15)},
        "mixed-family": {"strength": ("choice", ["weak", "medium", "strong"]),
                         "families": ("fixed", ["sqli", "path"]), "requests": ("int", 8, 20)},
        "multi-path": {"strength": ("choice", ["weak", "medium", "strong"]),
                       "paths": ("int", 3, 8), "requests": ("int", 10, 30),
                       "time_pattern": ("choice", ["burst", "spread"])},
    },
    "s1_c_login_bruteforce": {
        "single-account": {"strength": ("choice", ["weak", "medium", "strong"]),
                           "time_pattern": ("choice", ["burst", "spread"]), "accounts": ("fixed", 1)},
        "low-and-slow": {"strength": ("choice", ["weak", "medium"]), "time_pattern": ("fixed", "spread")},
        "burst": {"strength": ("choice", ["medium", "strong"]), "time_pattern": ("fixed", "burst")},
    },
    "s2_a_resource_theft": {
        "steady": {"strength": ("choice", ["weak", "medium", "strong"]),
                   "duration_seconds": ("int", 60, 180)},
        "ramp": {"strength": ("choice", ["medium", "strong"]), "duration_seconds": ("int", 90, 180)},
    },
    "f1_b_memory_leak": {
        "gradual": {"rate_mib_per_min": ("float", 2, 9), "duration_min": ("int", 8, 12)},
        "fast-spike": {"rate_mib_per_min": ("float", 20, 40), "duration_min": ("fixed", 1)},
    },
    "f2_a_minio_outage": {
        "full-stop": {"down_seconds": ("int", 60, 180)},
        "prolonged": {"down_seconds": ("int", 180, 420)},
    },
    "f2_c_db_pool_exhaustion": {
        "sudden-grab": {"strength": ("choice", ["weak", "medium", "strong"]),
                        "hold_seconds": ("int", 60, 180)},
        "gradual-leak": {"strength": ("choice", ["weak", "medium"]), "hold_seconds": ("int", 120, 300)},
    },
    "f3_a_bad_image_deploy": {
        "crashloop": {"mode": ("fixed", "crashloop"), "duration_seconds": ("int", 120, 240)},
        "healthcheck-fail": {"mode": ("fixed", "healthcheck-fail"), "duration_seconds": ("int", 120, 240)},
    },
    "s2_c_data_exfil": {
        "single-dest": {"bytes_mib": ("int", 5, 20)},
        "slow-trickle": {"bytes_mib": ("int", 5, 20), "rate": ("fixed", "low")},
        "burst-bulk": {"bytes_mib": ("int", 10, 30), "rate": ("fixed", "high")},
    },
    "c_a_authorized_transfer": {
        "single-dest": {"bytes_mib": ("int", 5, 20)},
        "slow": {"bytes_mib": ("int", 5, 20), "rate": ("fixed", "low")},
        "burst": {"bytes_mib": ("int", 10, 30), "rate": ("fixed", "high")},
    },
    "c_g_jvm_normal_memory": {
        "idle": {"background": ("fixed", "none"), "duration_min": ("int", 10, 30)},
        "normal-load": {"background": ("fixed", "normal_load"), "duration_min": ("int", 10, 30)},
    },
    "c_n_aiops_self_load": {
        "model-pull": {"task": ("fixed", "model_pull")},
        "replay": {"task": ("fixed", "replay")},
    },
    "c_c_blocked_attack": {
        "single-type": {"family": ("fixed", "sqli"), "requests": ("int", 20, 60),
                        "time_pattern": ("choice", ["burst", "spread"])},
        "mixed-4xx": {"families": ("fixed", ["sqli", "path", "scan"]), "requests": ("int", 20, 60)},
    },
    "c_e_password_mistype": {
        "occasional": {"failures": ("int", 1, 3), "time_pattern": ("fixed", "spread")},
        "one-user-retry": {"failures": ("int", 1, 3), "then_success": ("fixed", True)},
    },
}


@dataclass
class Instance:
    scenario_id: str
    variant_id: str
    seed: int
    params: dict = field(default_factory=dict)

    def instance_id(self) -> str:
        return f"{self.scenario_id}:{self.variant_id}:{self.seed}"


def all_specs() -> dict[str, dict[str, dict]]:
    """튜닝 스펙에 heldout 스펙을 병합(있으면). 없으면 튜닝 스펙만."""
    specs = {sid: dict(vmap) for sid, vmap in VARIANT_SPECS.items()}
    held = registry.load_heldout_specs()
    if held:
        for sid, vmap in held.items():
            specs.setdefault(sid, {}).update(vmap)
    return specs


def variant_ids(scenario_id: str, specs=None) -> list[str]:
    specs = specs if specs is not None else all_specs()
    return list(specs.get(scenario_id, {}))


def _rng(scenario_id: str, variant_id: str, seed: int) -> random.Random:
    h = hashlib.sha256(f"{scenario_id}|{variant_id}|{seed}".encode()).digest()
    return random.Random(int.from_bytes(h[:8], "big"))


def _sample(rng: random.Random, dist):
    kind = dist[0]
    if kind == "choice":
        return rng.choice(dist[1])
    if kind == "int":
        return rng.randint(dist[1], dist[2])
    if kind == "float":
        return round(rng.uniform(dist[1], dist[2]), 3)
    if kind == "fixed":
        return dist[1]
    raise ValueError(f"unknown dist kind: {kind}")


def generate(scenario_id: str, variant_id: str, seed: int, specs=None) -> Instance:
    """결정적 인스턴스 생성. 같은 (id, variant, seed) → 같은 params."""
    specs = specs if specs is not None else all_specs()
    if scenario_id not in specs:
        raise KeyError(f"unknown scenario_id: {scenario_id}")
    if variant_id not in specs[scenario_id]:
        raise KeyError(f"unknown variant_id: {scenario_id}/{variant_id}")
    rng = _rng(scenario_id, variant_id, seed)
    params = {axis: _sample(rng, dist) for axis, dist in specs[scenario_id][variant_id].items()}
    return Instance(scenario_id, variant_id, seed, params)


def labels_for(scenario_id: str) -> dict:
    """정답 레이블은 변형이 아니라 레지스트리(단일 소스)에서 조회한다."""
    row = next((r for r in registry.SCENARIO_REGISTRY_V2 if r["id"] == scenario_id), None)
    if row is None:
        raise KeyError(scenario_id)
    return {k: row[k] for k in ("threat_level", "expected_action", "expected_action_ideal", "incident_class")}
