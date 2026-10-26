"""
S2/C-a 실험 러너 (Step 5 V1 / Step 6 V2).

기존 송신 코드(orchestrator) · 검증기(verifier) · 판정/집계(evaluation) · 동결(freeze)을
묶어, 같은 전송 코드로 S2(비인가)/C-a(인가)를 반복 실행하고 TP/FP/TN/FN · MTTD 를
기록한다.

E4 — V1 은 튜닝용(분할), 개발용 저속(dev-slow)도 튜닝용, V2 는 held-out 최종 평가.
  V2 는 반드시 동결(freeze) 스냅샷을 요구하고, 평가 직전 파일이 동결 당시와 같은지
  확인한다(drift 있으면 평가 거부). 기본 반복: S2-V2=30, C-a-V2=75(50~100), 설정 가능.

실행 간 격리: 매 실행 전 Sink /stats 초기화 + verifier.wait_ruler_inactive 로 이전
경보가 섞이지 않게 한다.

Docker/Loki 런타임이 필요한 부분(실제 전송·검증)은 UNVERIFIED. 계획 수립·판정·집계·
결과 저장 등 순수 로직은 단독 테스트한다. 추정 수치는 만들지 않는다.
"""

from __future__ import annotations

import csv
import json
import os
import time
from dataclasses import dataclass

from evaluation import ConfusionMatrix, RunOutcome
from orchestrator import SinkEndpoint, run_transfer
from transfer_spec import DEV_VARIANTS, Destination, build_pair

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))

# 기본 배치(leafy-net) 기준 목적지/ readout 엔드포인트. 배치가 바뀌면 함께 바꾼다.
SINK_A = Destination(name="sink-a", ip="10.210.0.30", port=8080, host="sink-a")
SINK_B = Destination(name="sink-b", ip="10.210.0.31", port=8080, host="sink-b")
SINK_ENDPOINTS = {
    "sink-a": SinkEndpoint(name="sink-a", stats_url="http://127.0.0.1:8091"),
    "sink-b": SinkEndpoint(name="sink-b", stats_url="http://127.0.0.1:8092"),
}

DEFAULT_V1_REPS = {"S2": 5, "C-a": 5}
DEFAULT_V2_REPS = {"S2": 30, "C-a": 75}   # 문서 기준: S2-V2 30회, C-a-V2 50~100회


# --------------------------------------------------------------------------- #
# 계획 수립 (순수)
# --------------------------------------------------------------------------- #

def build_plan(variant: str, s2_reps: int, ca_reps: int, transfer=None) -> list:
    """
    variant 에 대해 S2/C-a 런 목록을 만든다. 두 시나리오를 번갈아 배치해 시간적 편향을
    줄이고, 많은 쪽의 나머지를 뒤에 붙인다. S2/C-a 는 동일 TransferSpec 을 공유한다(E2).
    """
    pair = build_pair(variant, SINK_A, SINK_B, transfer=transfer)
    s2_runs = [pair["S2"]] * s2_reps
    ca_runs = [pair["C-a"]] * ca_reps
    plan = []
    for i in range(max(len(s2_runs), len(ca_runs))):
        if i < len(s2_runs):
            plan.append(s2_runs[i])
        if i < len(ca_runs):
            plan.append(ca_runs[i])
    return plan


def evaluate_run(run, crosscheck_ok: bool, detected: bool,
                 mttd_seconds: float | None, detail: str = "") -> RunOutcome:
    """런 1회의 결과(전송 교차검증·탐지 여부·MTTD)를 RunOutcome 으로. 순수."""
    return RunOutcome(
        label=run.label, scenario=run.scenario, variant=run.variant,
        should_alert=run.should_alert,     # GT (평가 전용)
        detected=detected,
        valid=crosscheck_ok,               # 전송이 실제 도달·검증돼야 판정 가능
        mttd_seconds=mttd_seconds,
        detail=detail,
    )


# --------------------------------------------------------------------------- #
# 결과 저장 (순수 — tmp 디렉터리로 테스트)
# --------------------------------------------------------------------------- #

def write_results(outcomes, matrix: ConfusionMatrix, out_dir: str,
                  label: str, frozen=None) -> dict:
    """실행별 결과(JSONL/CSV)와 집계(JSON)를 저장. 저장 경로 dict 반환."""
    os.makedirs(out_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    base = f"{label}_{stamp}"

    runs_json = os.path.join(out_dir, f"{base}_runs.jsonl")
    with open(runs_json, "w", encoding="utf-8") as fh:
        for o in outcomes:
            fh.write(json.dumps(o.as_dict(), ensure_ascii=False) + "\n")

    runs_csv = os.path.join(out_dir, f"{base}_runs.csv")
    with open(runs_csv, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["label", "scenario", "variant", "should_alert", "detected",
                    "valid", "outcome", "mttd_seconds", "detail"])
        for o in outcomes:
            d = o.as_dict()
            w.writerow([d["label"], d["scenario"], d["variant"], d["should_alert"],
                        d["detected"], d["valid"], d["outcome"], d["mttd_seconds"], d["detail"]])

    summary = {
        "label": label, "created_at": stamp,
        "confusion_matrix": matrix.as_dict(),
        "frozen_config": frozen.as_dict() if frozen is not None else None,
    }
    summary_json = os.path.join(out_dir, f"{base}_summary.json")
    with open(summary_json, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)

    return {"runs_jsonl": runs_json, "runs_csv": runs_csv, "summary_json": summary_json}


# --------------------------------------------------------------------------- #
# 런타임 실행 (Docker/Loki 필요 — UNVERIFIED)
# --------------------------------------------------------------------------- #

@dataclass
class ExperimentConfig:
    db_password: str
    verifier: object                 # NetworkScenarioVerifier (지연 주입)
    verify_timeout: int = 120
    cooldown_timeout: int = 90
    inter_run_sleep: float = 2.0


def _sink_for(run) -> SinkEndpoint:
    return SINK_ENDPOINTS[run.destination.name]


def run_experiment(plan, cfg: ExperimentConfig, out_dir: str, label: str,
                   frozen=None, require_frozen: bool = False) -> dict:
    """
    계획된 런들을 순서대로 실행한다. V2(held-out)는 require_frozen=True 로 동결 확인을
    강제한다 — 동결 이후 설정이 바뀌었으면(drift) 평가를 거부한다.
    """
    if require_frozen:
        if frozen is None:
            raise RuntimeError("V2(held-out) 평가에는 동결 스냅샷이 필요하다")
        from freeze import verify_unchanged
        drift = verify_unchanged(frozen, REPO_ROOT)
        if drift:
            raise RuntimeError(f"동결 이후 설정이 변경됨 — V2 평가 거부: {drift}")

    outcomes = []
    for i, run in enumerate(plan):
        sink = _sink_for(run)
        # 실행 간 격리: 이전 경보가 inactive 될 때까지 대기
        cfg.verifier.wait_ruler_inactive(timeout=cfg.cooldown_timeout)

        from datetime import datetime, timezone
        t0 = datetime.now(timezone.utc)
        transfer_id = f"{run.label}-{i}-{int(t0.timestamp())}"
        result = run_transfer(run, cfg.db_password, transfer_id, sink, reset_sink=True)
        crosscheck_ok = bool(result["crosscheck"]["ok"])

        verify = cfg.verifier.verify(t0, timeout=cfg.verify_timeout)
        detected = verify.stages["loki_ruler_firing"].ok
        stage_flags = {k: v.ok for k, v in verify.stages.items()}
        detail = f"crosscheck_ok={crosscheck_ok}; stages={stage_flags}"
        outcomes.append(evaluate_run(run, crosscheck_ok, detected,
                                     verify.mttd_seconds, detail))
        time.sleep(cfg.inter_run_sleep)

    matrix = ConfusionMatrix.from_outcomes(outcomes)
    paths = write_results(outcomes, matrix, out_dir, label, frozen=frozen)
    return {"outcomes": [o.as_dict() for o in outcomes],
            "confusion_matrix": matrix.as_dict(), "paths": paths}


# --------------------------------------------------------------------------- #
# CLI (호스트에서 실행; 실제 실행은 Docker/Loki 필요 — UNVERIFIED)
# --------------------------------------------------------------------------- #

def _default_out_dir() -> str:
    return os.path.join(HERE, "results")


def main(argv=None) -> int:
    import argparse

    p = argparse.ArgumentParser(description="S2/C-a 실험 러너 (V1 튜닝 / V2 held-out)")
    sub = p.add_subparsers(dest="cmd", required=True)

    pf = sub.add_parser("freeze", help="최종 평가 전 설정 동결 스냅샷 생성")
    pf.add_argument("--out", default=os.path.join(_default_out_dir(), "frozen.json"))
    pf.add_argument("--N", type=int, default=1048576, help="Zeek ConnThreshold 바이트 N")
    pf.add_argument("--T", type=float, default=60.0, help="탐지 제한시간 T(초)")

    pr = sub.add_parser("run", help="실험 실행 (DB_PASSWORD 환경변수 사용)")
    pr.add_argument("variant", choices=list(DEV_VARIANTS))
    pr.add_argument("--s2-reps", type=int)
    pr.add_argument("--ca-reps", type=int)
    pr.add_argument("--out-dir", default=_default_out_dir())
    pr.add_argument("--loki-url", default=os.getenv("LOKI_URL", "http://localhost:3100"))
    pr.add_argument("--am-url", default=os.getenv("ALERTMANAGER_URL", "http://localhost:9093"))
    pr.add_argument("--frozen", help="V2 held-out: 동결 스냅샷 경로(필수)")
    args = p.parse_args(argv)

    if args.cmd == "freeze":
        from freeze import freeze_config
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        fc = freeze_config(REPO_ROOT, {"zeek_byte_threshold_N": args.N, "detect_limit_T_sec": args.T})
        fc.save(args.out)
        print(f"동결 완료: {args.out}  git_sha={fc.git_sha}")
        return 0

    # run
    is_v2 = args.variant == "V2"
    default_reps = DEFAULT_V2_REPS if is_v2 else DEFAULT_V1_REPS
    s2_reps = args.s2_reps if args.s2_reps is not None else default_reps["S2"]
    ca_reps = args.ca_reps if args.ca_reps is not None else default_reps["C-a"]

    db_password = os.getenv("DB_PASSWORD")
    if not db_password:
        print("DB_PASSWORD 환경변수가 필요하다 (자격증명을 인자로 넘기지 않는다)")
        return 2

    frozen = None
    if is_v2:
        if not args.frozen:
            print("V2(held-out) 평가에는 --frozen <동결 스냅샷> 이 필요하다")
            return 2
        from freeze import FrozenConfig
        frozen = FrozenConfig.load(args.frozen)

    from verifier import NetworkScenarioVerifier
    verifier = NetworkScenarioVerifier(loki_url=args.loki_url, alertmanager_url=args.am_url)
    cfg = ExperimentConfig(db_password=db_password, verifier=verifier)

    plan = build_plan(args.variant, s2_reps, ca_reps)
    label = f"S2CA-{args.variant}"
    out = run_experiment(plan, cfg, args.out_dir, label, frozen=frozen, require_frozen=is_v2)
    print(json.dumps(out["confusion_matrix"], ensure_ascii=False, indent=2))
    print("결과 저장:", out["paths"]["summary_json"])
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
