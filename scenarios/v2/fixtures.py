"""
경보 컨텍스트 픽스처 저장 (scenarios-v2).

시나리오 실행 중 경보가 오면 그 시점 컨텍스트 — 경보 payload 와 pipeline 이 조회한
Loki·Prometheus 결과 — 를 JSON 픽스처로 저장한다. LLM 평가를 오프라인으로 반복하는 입력이다.

규율:
  - **정답 레이블은 픽스처에 넣지 않는다.** 시나리오는 레지스트리 id 로만 연결한다.
    (threat_level/expected_action/ideal 은 평가 시 registry 에서 조회한다.)
  - 저장 전에 컨텍스트에 정답 레이블 키가 섞이지 않았는지 검사한다(방어).

순수 로직(픽스처 구성·레이블 검사·직렬화)은 단위 테스트. 경보 수신·질의는 라이브 스택
필요 — UNVERIFIED (측정 PC).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

# 픽스처에 절대 들어가면 안 되는 정답 레이블 키(어느 깊이든 금지).
ANSWER_LABEL_KEYS = ("threat_level", "expected_action", "expected_action_ideal")

DEFAULT_FIXTURE_DIR = os.getenv("V2_FIXTURE_DIR", "scenarios/v2/fixtures_data")


# --------------------------------------------------------------------------- #
# 순수 로직 (단위 테스트 대상)
# --------------------------------------------------------------------------- #

def find_answer_label_keys(obj) -> list[str]:
    """obj(중첩 dict/list) 안에 정답 레이블 키가 있으면 그 목록을 돌려준다(없으면 빈 목록)."""
    found = []

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in ANSWER_LABEL_KEYS:
                    found.append(k)
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(obj)
    return found


def build_fixture(scenario_id: str, alert: dict, observations: dict,
                  variant_id: str | None = None, seed: int | None = None,
                  captured_at: str | None = None) -> dict:
    """
    경보 payload 와 관측 결과로 픽스처 dict 를 만든다. 정답 레이블이 섞여 있으면 거부한다.
    observations 예: {"loki": [...], "prometheus": [...]}.
    """
    payload = {"alert": alert, "observations": observations}
    leaked = find_answer_label_keys(payload)
    if leaked:
        raise ValueError(f"픽스처에 정답 레이블이 섞임(금지): {sorted(set(leaked))}")
    return {
        "scenario_id": scenario_id,     # 정답은 여기 id 로만 연결(레지스트리에서 조회)
        "variant_id": variant_id,
        "seed": seed,
        "captured_at": captured_at or datetime.now(timezone.utc).isoformat(),
        "alert": alert,
        "observations": observations,
    }


def fixture_filename(fixture: dict) -> str:
    """픽스처 파일명. 시나리오 id + 변형 + 시각으로 구성(정답 미포함)."""
    stamp = fixture["captured_at"].replace(":", "").replace("-", "").replace(".", "")
    parts = [fixture["scenario_id"]]
    if fixture.get("variant_id"):
        parts.append(str(fixture["variant_id"]))
    if fixture.get("seed") is not None:
        parts.append(f"seed{fixture['seed']}")
    parts.append(stamp)
    return "-".join(parts) + ".json"


# --------------------------------------------------------------------------- #
# 저장 (파일 I/O)
# --------------------------------------------------------------------------- #

def save_fixture(fixture: dict, out_dir: str = DEFAULT_FIXTURE_DIR) -> str:
    """픽스처를 JSON 으로 저장한다. 저장 전 정답 레이블 검사를 다시 한다."""
    leaked = find_answer_label_keys(fixture.get("alert")) + \
        find_answer_label_keys(fixture.get("observations"))
    if leaked:
        raise ValueError(f"저장 거부 — 정답 레이블 섞임: {sorted(set(leaked))}")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, fixture_filename(fixture))
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(fixture, fh, ensure_ascii=False, indent=2)
    return path


# --------------------------------------------------------------------------- #
# 라이브 수집 (UNVERIFIED — 측정 PC)
# --------------------------------------------------------------------------- #

def capture_on_alert(scenario_id, alert, observations, out_dir=DEFAULT_FIXTURE_DIR,
                     variant_id=None, seed=None) -> str:
    """경보 수신 시 호출 — 컨텍스트를 픽스처로 저장하고 경로를 돌려준다."""
    fx = build_fixture(scenario_id, alert, observations, variant_id, seed)
    path = save_fixture(fx, out_dir)
    print(f"[fixture] saved {path}", flush=True)
    return path
