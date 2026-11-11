"""
scenarios-v2 최소 실행 진입점.

사용법:
  python -m scenarios.v2.run <id> [--variant <v> --seed <n>] [--dry-run]
  python -m scenarios.v2.run --list

--dry-run 은 Docker/HTTP 를 건드리지 않고 레지스트리 정답 레이블과 각 시나리오의 주입 계획만
출력한다. 실제 실행(주입/정리)은 측정 PC 의 Docker 환경에서만 한다.

기존 scenarios/run.py(레거시 런처)는 건드리지 않는다 — 이 진입점은 v2 전용이다.
"""

from __future__ import annotations

import argparse
import importlib
import sys
from datetime import datetime, timezone

from v2.registry import SCENARIO_REGISTRY_V2

# id -> 모듈 경로
_MODULES = {
    "s1_a_input_attack": "v2.s1a_input_attack",
    "s1_c_login_bruteforce": "v2.s1c_login_bruteforce",
    "f1_b_memory_leak": "v2.f1b_memory_leak",
    "f2_a_minio_outage": "v2.f2a_minio_outage",
    "s2_a_resource_theft": "v2.s2a_resource_theft",
    "f2_c_db_pool_exhaustion": "v2.f2c_db_pool_exhaustion",
    "f3_a_bad_image_deploy": "v2.f3a_bad_image_deploy",
}


def _row(scenario_id: str) -> dict | None:
    return next((r for r in SCENARIO_REGISTRY_V2 if r["id"] == scenario_id), None)


def _print_list() -> None:
    print("사용 가능한 v2 시나리오:")
    for r in SCENARIO_REGISTRY_V2:
        if r["id"] in _MODULES:
            tag = "실행가능"
        elif r.get("reuse"):
            tag = f"재사용({r['reuse']}, 팀원)"
        elif r.get("external_tool"):
            tag = "외부도구(측정 PC)"
        else:
            tag = "미구현"
        print(f"  {r['id']:<26s} {r['label']}  [{tag}]")


def run(scenario_id: str, dry_run: bool, variant_id: str | None = None,
        seed: int | None = None) -> int:
    row = _row(scenario_id)
    if row is None or scenario_id not in _MODULES:
        print(f"알 수 없거나 미구현 id: {scenario_id}\n")
        _print_list()
        return 2
    mod = importlib.import_module(_MODULES[scenario_id])

    inst = None
    if variant_id is not None:
        from v2 import variants
        inst = variants.generate(scenario_id, variant_id, seed if seed is not None else 0)
        print(f"[variant] {inst.instance_id()} params={inst.params}")

    if dry_run:
        # 정답 레이블은 평가 메타일 뿐 — 주입/프롬프트 경로에는 안 들어간다. dry-run 표시용으로만 출력.
        print(f"[dry-run] id={row['id']} label={row['label']}")
        print(f"  threat={row['threat_level']} action={row['expected_action']} "
              f"ideal={row['expected_action_ideal']} targets={row['targets']}")
        print(f"  evidence={row['evidence']}")
        if hasattr(mod, "dry_run"):
            print(f"  plan={mod.dry_run()}")
        else:
            print("  (이 모듈은 dry_run() 미제공)")
        return 0

    # 실행 기록(시나리오 id·변형·seed·시각 구간). 경보 컨텍스트와 시각으로 짝지어 픽스처를 만든다
    # (python -m v2.fixtures pair). 정답 레이블은 넣지 않는다.
    from v2 import fixtures
    started = datetime.now(timezone.utc)
    status = "error"
    try:
        # 변형 파라미터 중 기존 주입기가 받는 축(strength/mode)만 전달. 나머지 축(타이밍 등)은
        # 측정 PC 런타임에서 처리한다(VARIANTS 참조).
        if inst is not None and hasattr(mod, "inject"):
            kw = {k: inst.params[k] for k in ("strength", "mode") if k in inst.params}
            mod.inject(**kw)
        else:
            mod.main()
        status = "ok"
    finally:
        fixtures.append_run_record(scenario_id, variant_id, seed, started, datetime.now(timezone.utc), status)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="scenarios.v2.run", description="scenarios-v2 실행 진입점")
    p.add_argument("id", nargs="?", help="시나리오 id (--list 로 조회)")
    p.add_argument("--variant", help="변형 id (VARIANTS 참조)")
    p.add_argument("--seed", type=int, help="변형 seed (재현용)")
    p.add_argument("--dry-run", action="store_true", help="Docker/HTTP 없이 계획만 출력")
    p.add_argument("--list", action="store_true", help="시나리오 목록")
    args = p.parse_args(argv)
    if args.list or not args.id:
        _print_list()
        return 0
    return run(args.id, args.dry_run, args.variant, args.seed)


if __name__ == "__main__":
    sys.exit(main())
