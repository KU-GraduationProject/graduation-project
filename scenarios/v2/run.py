"""
scenarios-v2 최소 실행 진입점.

사용법:
  python -m scenarios.v2.run <id> [--dry-run]
  python -m scenarios.v2.run --list

--dry-run 은 Docker/HTTP 를 건드리지 않고 레지스트리 정답 레이블과 각 시나리오의 주입 계획만
출력한다. 실제 실행(주입/정리)은 측정 PC 의 Docker 환경에서만 한다.

기존 scenarios/run.py(레거시 런처)는 건드리지 않는다 — 이 진입점은 v2 전용이다.
"""

from __future__ import annotations

import argparse
import importlib
import sys

from v2.registry import SCENARIO_REGISTRY_V2

# id -> 모듈 경로
_MODULES = {
    "s1_a_input_attack": "v2.s1a_input_attack",
    "s1_c_login_bruteforce": "v2.s1c_login_bruteforce",
    "f1_b_memory_leak": "v2.f1b_memory_leak",
    "f2_a_minio_outage": "v2.f2a_minio_outage",
}


def _row(scenario_id: str) -> dict | None:
    return next((r for r in SCENARIO_REGISTRY_V2 if r["id"] == scenario_id), None)


def _print_list() -> None:
    print("사용 가능한 v2 시나리오:")
    for r in SCENARIO_REGISTRY_V2:
        runnable = "실행가능" if r["id"] in _MODULES else "미구현(배치 ②/③)"
        print(f"  {r['id']:<24s} {r['label']}  [{runnable}]")


def run(scenario_id: str, dry_run: bool) -> int:
    row = _row(scenario_id)
    if row is None or scenario_id not in _MODULES:
        print(f"알 수 없거나 미구현 id: {scenario_id}\n")
        _print_list()
        return 2
    mod = importlib.import_module(_MODULES[scenario_id])

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

    mod.main()
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="scenarios.v2.run", description="scenarios-v2 실행 진입점")
    p.add_argument("id", nargs="?", help="시나리오 id (--list 로 조회)")
    p.add_argument("--dry-run", action="store_true", help="Docker/HTTP 없이 계획만 출력")
    p.add_argument("--list", action="store_true", help="시나리오 목록")
    args = p.parse_args(argv)
    if args.list or not args.id:
        _print_list()
        return 0
    return run(args.id, args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
