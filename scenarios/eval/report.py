#!/usr/bin/env python3
"""
scenarios/eval/report.py
─────────────────────────
저장된 배치 결과 JSON을 읽어 상세 리포트를 출력하는 독립 스크립트.
배치 실행 완료 후 재분석하거나, 여러 배치를 합쳐서 볼 때 사용.

실행 방법:
  # 가장 최신 결과 자동 선택
  cd scenarios
  python -m eval.report

  # 특정 파일 지정
  python -m eval.report eval/results/cpu_stress_20260601_120000.json

  # 두 결과를 비교 (프롬프트 개선 전/후 비교 등)
  python -m eval.report --compare \\
    eval/results/cpu_stress_before.json \\
    eval/results/cpu_stress_after.json
"""

import json
import sys
from collections import Counter
from pathlib import Path

RESULTS_DIR = Path(__file__).parent / "results"


# ── 단일 결과 파일 로드 ────────────────────────────────────────────────────────
def load_results(path: Path) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ── 최신 파일 자동 선택 ────────────────────────────────────────────────────────
def find_latest(scenario: str) -> Path | None:
    files = sorted(RESULTS_DIR.glob(f"{scenario}_*.json"), reverse=True)
    return files[0] if files else None


# ── 통계 계산 ─────────────────────────────────────────────────────────────────
def compute_stats(values: list[float]) -> dict:
    if not values:
        return {"count": 0}
    n   = len(values)
    avg = sum(values) / n
    var = sum((x - avg) ** 2 for x in values) / n
    return {
        "count":  n,
        "mean":   round(avg, 2),
        "std":    round(var ** 0.5, 2),
        "min":    round(min(values), 2),
        "max":    round(max(values), 2),
        "median": round(sorted(values)[n // 2], 2),
    }


# ── 단일 시나리오 리포트 ──────────────────────────────────────────────────────
def report_single(results: list[dict], label: str = "") -> None:
    n        = len(results)
    title    = f"{results[0]['scenario']}  {label}".strip() if results else "?"
    mttds    = [r["mttd_seconds"]  for r in results if r.get("mttd_seconds")  is not None]
    mttas    = [r["mtta_seconds"]  for r in results if r.get("mtta_seconds")  is not None]
    scores   = [r["llm_score"]     for r in results if r.get("llm_score")]

    print(f"\n{'='*65}")
    print(f"  📊 {title}  ({n}회 실행)")
    print(f"{'='*65}")

    # MTTD
    st = compute_stats(mttds)
    print(f"\n  [MTTD] Alert 탐지까지 걸린 시간  (성공 {st.get('count',0)}/{n}회)")
    if st.get("count"):
        print(f"    평균±σ : {st['mean']}s ± {st['std']}s")
        print(f"    범위   : {st['min']}s ~ {st['max']}s  |  중앙값: {st['median']}s")

    # MTTA
    st = compute_stats(mttas)
    print(f"\n  [MTTA] LLM 결과 생성까지 걸린 시간  (성공 {st.get('count',0)}/{n}회)")
    if st.get("count"):
        print(f"    평균±σ : {st['mean']}s ± {st['std']}s")
        print(f"    범위   : {st['min']}s ~ {st['max']}s  |  중앙값: {st['median']}s")

    # LLM 품질
    m = len(scores)
    print(f"\n  [LLM 품질]  (결과 수집 {m}/{n}회)")
    if scores:
        confs   = [s["confidence"]    for s in scores]
        qs      = [s["quality_score"] for s in scores]
        ev_cnts = [s["evidence_count"] for s in scores]
        rc_wds  = [s["root_cause_words"] for s in scores]
        tl_ok   = sum(1 for s in scores if s["threat_level_ok"])
        act_ok  = sum(1 for s in scores if s["action_ok"])
        ev_ok   = sum(1 for s in scores if s["evidence_ok"])

        conf_st = compute_stats(confs)
        qs_st   = compute_stats(qs)

        print(f"    confidence    : 평균 {conf_st['mean']:.3f} ± {conf_st['std']:.3f}")
        print(f"    quality_score : 평균 {qs_st['mean']:.3f} ± {qs_st['std']:.3f}")
        print(f"    threat_level 정확도: {tl_ok}/{m} ({tl_ok/m*100:.0f}%)")
        print(f"    action 관련성      : {act_ok}/{m} ({act_ok/m*100:.0f}%)")
        print(f"    evidence 충분성    : {ev_ok}/{m} ({ev_ok/m*100:.0f}%)")
        print(f"    평균 evidence 수   : {sum(ev_cnts)/m:.1f}개")
        print(f"    평균 root_cause 길이: {sum(rc_wds)/m:.0f} 단어")

        tl_dist = Counter(s["threat_level"] for s in scores)
        print(f"\n    threat_level 분포: {dict(tl_dist)}")

        # run별 상세 테이블
        print(f"\n  {'Run':>3}  {'MTTD':>7}  {'MTTA':>7}  {'conf':>5}  {'threat':>8}  "
              f"{'TL✓':>3}  {'Act✓':>4}  {'Ev':>3}  {'Q':>5}")
        print(f"  {'─'*3}  {'─'*7}  {'─'*7}  {'─'*5}  {'─'*8}  {'─'*3}  {'─'*4}  {'─'*3}  {'─'*5}")
        for r in results:
            run_n  = r["run"]
            mttd_v = f"{r['mttd_seconds']:.1f}s" if r.get("mttd_seconds") is not None else "  —  "
            mtta_v = f"{r['mtta_seconds']:.1f}s" if r.get("mtta_seconds") is not None else "  —  "
            s = r.get("llm_score")
            if s:
                cf  = f"{s['confidence']:.2f}"
                tl  = s['threat_level'][:8]
                tok = "✅" if s["threat_level_ok"] else "❌"
                aok = "✅" if s["action_ok"] else "❌"
                ev  = str(s["evidence_count"])
                q   = f"{s['quality_score']:.3f}"
            else:
                cf = tl = tok = aok = ev = q = "—"
            print(f"  {run_n:>3}  {mttd_v:>7}  {mtta_v:>7}  {cf:>5}  {tl:>8}  {tok:>3}  {aok:>4}  {ev:>3}  {q:>5}")


# ── 두 결과 비교 (프롬프트 개선 전/후) ────────────────────────────────────────
def report_compare(before_path: Path, after_path: Path) -> None:
    before = load_results(before_path)
    after  = load_results(after_path)

    def _avg(results: list[dict], key: str, subkey: str | None = None) -> float | None:
        if subkey:
            vals = [r[key][subkey] for r in results if r.get(key) and r[key].get(subkey) is not None]
        else:
            vals = [r[key] for r in results if r.get(key) is not None]
        return sum(vals) / len(vals) if vals else None

    def _rate(results: list[dict], key: str) -> str:
        total  = len(results)
        ok     = sum(1 for r in results if r.get("llm_score") and r["llm_score"].get(key))
        return f"{ok}/{total} ({ok/total*100:.0f}%)" if total else "—"

    def fmt(v): return f"{v:.3f}" if v is not None else "—"

    scenario = before[0]["scenario"] if before else "?"
    print(f"\n{'='*65}")
    print(f"  🔄 비교 리포트: {scenario}")
    print(f"  Before: {before_path.name}  ({len(before)}회)")
    print(f"  After : {after_path.name}  ({len(after)}회)")
    print(f"{'='*65}")
    print(f"\n  {'지표':30s} {'Before':>10}  {'After':>10}  {'변화':>8}")
    print(f"  {'─'*30}  {'─'*10}  {'─'*10}  {'─'*8}")

    # lower_is_better=True: 값이 줄면 개선 (MTTD, MTTA)
    # lower_is_better=False: 값이 늘면 개선 (confidence, quality_score 등)
    metrics = [
        ("MTTD 평균 (s)",        "mttd_seconds",  None,               False, True),
        ("MTTA 평균 (s)",        "mtta_seconds",  None,               False, True),
        ("confidence 평균",      "llm_score",     "confidence",       True,  False),
        ("quality_score 평균",   "llm_score",     "quality_score",    True,  False),
        ("evidence 수 평균",     "llm_score",     "evidence_count",   True,  False),
        ("root_cause 길이 평균", "llm_score",     "root_cause_words", True,  False),
    ]

    for label, key, subkey, is_llm, lower_is_better in metrics:
        if is_llm:
            bv = _avg(before, key, subkey)
            av = _avg(after,  key, subkey)
        else:
            bv = _avg(before, key)
            av = _avg(after,  key)
        if bv is not None and av is not None:
            diff = av - bv
            improved = (diff < 0) if lower_is_better else (diff > 0)
            sign  = "+" if diff > 0 else ""
            arrow = "✅" if improved else ("➡️" if diff == 0 else "❌")
            delta = f"{arrow} {sign}{diff:.3f}"
        else:
            delta = "—"
        print(f"  {label:30s}  {fmt(bv):>10}  {fmt(av):>10}  {delta}")

    print(f"\n  {'분류 지표':30s} {'Before':>10}  {'After':>10}")
    print(f"  {'─'*30}  {'─'*10}  {'─'*10}")
    for label, key in [
        ("threat_level 정확도", "threat_level_ok"),
        ("action 관련성",       "action_ok"),
        ("evidence 충분성",     "evidence_ok"),
    ]:
        br = _rate(before, key)
        ar = _rate(after,  key)
        print(f"  {label:30s}  {br:>10}  {ar:>10}")

    print()


# ── 진입점 ────────────────────────────────────────────────────────────────────
def main():
    args = sys.argv[1:]

    # --compare mode
    if "--compare" in args:
        idx = args.index("--compare")
        paths = args[idx + 1:]
        if len(paths) < 2:
            print("사용법: python -m eval.report --compare <before.json> <after.json>")
            sys.exit(1)
        report_compare(Path(paths[0]), Path(paths[1]))
        return

    # 파일 직접 지정
    if args:
        for path_str in args:
            path    = Path(path_str)
            results = load_results(path)
            report_single(results, label=f"[{path.stem}]")
        return

    # 자동: results/ 에 저장된 모든 시나리오 파일 탐색
    # batch_runner에 시나리오가 추가돼도 여기는 수정 불필요
    all_files = sorted(RESULTS_DIR.glob("*.json"), reverse=True)
    seen_scenarios: set[str] = set()
    found_any = False
    for f in all_files:
        # 파일명 = <scenario>_<datetime>.json → scenario 추출
        parts = f.stem.rsplit("_", 2)
        scenario = "_".join(parts[:-2]) if len(parts) >= 3 else parts[0]
        if scenario in seen_scenarios:
            continue  # 같은 시나리오의 이전 파일은 건너뜀 (최신만)
        seen_scenarios.add(scenario)

    for scenario in seen_scenarios:
        path = find_latest(scenario)
        if path:
            results = load_results(path)
            report_single(results, label=f"[최신: {path.name}]")
            found_any = True
        else:
            print(f"  결과 파일 없음: {scenario}")

    if not found_any:
        print(f"\n결과 파일이 없습니다. 먼저 batch_runner.py를 실행하세요:")
        print(f"  cd scenarios && python -m eval.batch_runner\n")


if __name__ == "__main__":
    main()
