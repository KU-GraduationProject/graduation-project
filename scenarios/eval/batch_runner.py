#!/usr/bin/env python3
"""
scenarios/eval/batch_runner.py
────────────────────────────────
SCENARIOS dict에 등록된 시나리오를 각 RUNS회 자동 반복 실행.

각 실행마다 측정하는 항목:
  - MTTD  : anomaly_log.json 최신 verification 레코드에서 추출
  - MTTA  : 시나리오 시작(run_start_ts) → LLM 결과 등장까지 pipeline /results 폴링
  - LLM 품질:
      · confidence (0.0~1.0)
      · threat_level 정확도 (시나리오별 예상 레벨과 비교)
      · action 관련성 (키워드 포함 여부)
      · evidence 수 (3개 이상 = 충분)
      · 종합 quality_score (4개 항목 단순 평균)

결과는 scenarios/eval/results/<scenario>_<datetime>.json 에 저장.
실행이 끝나면 콘솔에 요약 리포트 출력.

새 시나리오 추가 방법:
  SCENARIOS dict에 항목 하나만 추가하면 됨.
  main()의 target_scenarios는 SCENARIOS.keys()를 자동 참조.

  필수 필드:
    script              : 시나리오 스크립트 경로 (Path)
    log_key             : verifier.py ScenarioVerifier(scenario_name=...) 값과 일치해야 함
                          불일치 시 MTTD가 항상 None → 시작 시 자동 경고 출력
    uses_alertmanager   : True면 매 run 후 alertmanager 재시작
    expected_threat_levels : set[str] — LLM 정답 위협 레벨
    expected_action_keywords: list[str] — action 텍스트에 포함돼야 할 키워드

실행 방법:
  cd scenarios
  python -m eval.batch_runner                        # 전체 시나리오
  python -m eval.batch_runner cpu_stress             # 특정 시나리오만
  RUNS=5 COOLDOWN_SEC=60 python -m eval.batch_runner

환경변수:
  PIPELINE_URL   기본값 http://localhost:8000
  RUNS           기본값 10
  COOLDOWN_SEC   기본값 90
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
import urllib.request

# ── 경로 설정 ──────────────────────────────────────────────────────────────────
EVAL_DIR      = Path(__file__).parent
SCENARIOS_DIR = EVAL_DIR.parent
RESULTS_DIR   = EVAL_DIR / "results"
LOG_PATH      = SCENARIOS_DIR / "logs" / "anomaly_log.json"
RESULTS_DIR.mkdir(exist_ok=True)

# ── 실행 설정 ──────────────────────────────────────────────────────────────────
PIPELINE_URL = os.getenv("PIPELINE_URL", "http://localhost:8000")
RUNS         = int(os.getenv("RUNS", "10"))
COOLDOWN_SEC = int(os.getenv("COOLDOWN_SEC", "90"))

# ── 시나리오 정의 ──────────────────────────────────────────────────────────────
SCENARIOS = {
    "cpu_stress": {
        "script":         SCENARIOS_DIR / "category1_infra" / "cpu_stress.py",
        "log_key":        "cpu_stress",          # anomaly_log의 scenario 값
        "uses_alertmanager": True,               # repeat_interval 초기화 필요
        "expected_threat_levels": {"high", "medium"},
        "expected_action_keywords": [
            "restart", "rate", "limit", "isolate", "scale", "investigate", "throttle",
        ],
        "expected_evidence_keywords": ["cpu", "usage", "peak", "%"],
    },
    "lateral_movement": {
        "script":         SCENARIOS_DIR / "category2_security" / "lateral_movement.py",
        "log_key":        "lateral_movement",
        "uses_alertmanager": False,              # 직접 pipeline webhook POST 방식
        "expected_threat_levels": {"critical", "high"},
        "expected_action_keywords": [
            "isolate", "block", "disconnect", "network", "deny",
            "investigate", "lateral", "unauthorized",
        ],
        "expected_evidence_keywords": ["authentication", "failed", "unauthorized", "connection", "ip"],
    },
}


# ── AlertManager 재시작 ────────────────────────────────────────────────────────
def restart_alertmanager() -> None:
    """
    AlertManager 컨테이너를 재시작해 repeat_interval 상태를 초기화한다.
    cpu_stress처럼 AlertManager 경유 시나리오에서만 호출.

    docker 패키지 없이도 동작하도록 subprocess로 docker CLI 호출.
    """
    print("  → AlertManager 재시작 중 (repeat_interval 초기화)...", flush=True)
    result = subprocess.run(
        ["docker", "restart", "alertmanager"],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        time.sleep(15)  # 재시작 후 안정화
        print("  → AlertManager 재시작 완료")
    else:
        print(f"  [!] AlertManager 재시작 실패: {result.stderr.strip()}")
        print("  → docker restart alertmanager 를 수동으로 실행하세요")


# ── pipeline /results 폴링 ─────────────────────────────────────────────────────
def poll_llm_result(since_ts: float, timeout: int = 180) -> dict | None:
    """
    pipeline GET /results 를 5초 간격으로 폴링.
    since_ts 이후에 추가된 가장 최근 결과를 반환.
    timeout 초 내에 없으면 None 반환.
    """
    print(f"  → LLM 결과 대기 (최대 {timeout}초)", end="", flush=True)
    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            resp = urllib.request.urlopen(f"{PIPELINE_URL}/results", timeout=8)
            data = json.loads(resp.read())
            entries = data.get("data", [])

            # since_ts 이후 레코드 필터
            recent = []
            for e in entries:
                ts_str = e.get("timestamp", "")
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
                    if ts >= since_ts:
                        recent.append((ts, e))
                except Exception:
                    pass

            if recent:
                # 가장 최신 결과 반환
                recent.sort(key=lambda x: x[0])
                print(f" 완료")
                return recent[-1][1]

        except Exception:
            pass

        print(".", end="", flush=True)
        time.sleep(5)

    print(" 타임아웃 ❌")
    return None


# ── anomaly_log에서 최신 MTTD 추출 ────────────────────────────────────────────
def get_latest_mttd(scenario_log_key: str, since_ts: float) -> float | None:
    """
    anomaly_log.json에서 시나리오 실행 이후(since_ts) 기록된
    verification 레코드의 mttd_seconds를 반환.
    """
    if not LOG_PATH.exists():
        return None
    try:
        with open(LOG_PATH, "r", encoding="utf-8") as f:
            records = json.load(f)
        # since_ts 이후 해당 시나리오 verification 레코드만
        candidates = [
            r for r in records
            if r.get("category") == "verification"
            and r.get("scenario") == scenario_log_key
        ]
        if not candidates:
            return None
        # timestamp 필드 기준 필터
        filtered = []
        for r in candidates:
            ts_str = r.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
                if ts >= since_ts:
                    filtered.append((ts, r))
            except Exception:
                pass
        if not filtered:
            # timestamp 파싱 실패 — 이전 실행 데이터 오염 방지를 위해 None 반환
            return None
        filtered.sort(key=lambda x: x[0])
        return filtered[-1][1].get("mttd_seconds")
    except Exception:
        return None


# ── LLM 품질 점수 계산 ─────────────────────────────────────────────────────────
def score_llm(entry: dict, scenario_name: str) -> dict:
    """
    LLM 출력 품질을 4가지 항목으로 평가, 종합 quality_score(0~1) 산출.

    항목:
      threat_level_ok  : 예상 위협 수준과 일치 여부 (0 or 1)
      action_ok        : 예상 액션 키워드 포함 여부 (0 or 1)
      evidence_ok      : evidence 3개 이상 여부 (0 or 1)
      confidence       : LLM이 직접 보고한 신뢰도 (0~1)
    """
    cfg    = SCENARIOS[scenario_name]
    result = entry.get("result", {})

    threat_level  = result.get("threat_level", "").lower()
    action        = result.get("action", "").lower()
    root_cause    = result.get("root_cause", "")
    evidence      = result.get("evidence", [])
    confidence    = float(result.get("confidence", 0.0))

    threat_ok   = threat_level in cfg["expected_threat_levels"]
    action_ok   = any(kw in action for kw in cfg["expected_action_keywords"])
    evidence_ok = len(evidence) >= 3

    quality_score = (int(threat_ok) + int(action_ok) + int(evidence_ok) + min(confidence, 1.0)) / 4

    return {
        "threat_level":     threat_level,
        "threat_level_ok":  threat_ok,
        "action_ok":        action_ok,
        "evidence_count":   len(evidence),
        "evidence_ok":      evidence_ok,
        "confidence":       round(confidence, 3),
        "root_cause_words": len(root_cause.split()),
        "quality_score":    round(quality_score, 3),
        "raw_result":       result,
    }


# ── 단일 실행 ─────────────────────────────────────────────────────────────────
def run_once(scenario_name: str, run_num: int) -> dict:
    cfg = SCENARIOS[scenario_name]
    print(f"\n{'='*60}")
    print(f"  [{scenario_name}] Run {run_num}/{RUNS}  |  {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*60}")

    run_start_ts  = time.time()
    run_start_iso = datetime.now(timezone.utc).isoformat()

    # ── 시나리오 스크립트 실행 (subprocess) ──────────────────────────────────
    proc = subprocess.run(
        [sys.executable, str(cfg["script"])],
        cwd=str(SCENARIOS_DIR),
    )
    scenario_duration = round(time.time() - run_start_ts, 1)
    print(f"\n  → 시나리오 종료 (소요: {scenario_duration}s, exit={proc.returncode})")

    # ── MTTD 추출 (anomaly_log의 verifier 기록) ───────────────────────────────
    mttd = get_latest_mttd(cfg["log_key"], since_ts=run_start_ts)

    # ── MTTA 직접 측정 (pipeline /results 폴링) ───────────────────────────────
    # 기준점: run_start_ts (시나리오 시작 시각) → LLM 결과 등장까지의 전체 시간
    llm_entry  = poll_llm_result(since_ts=run_start_ts, timeout=180)
    mtta       = round(time.time() - run_start_ts, 1) if llm_entry else None

    # ── LLM 품질 점수 계산 ───────────────────────────────────────────────────
    llm_score = score_llm(llm_entry, scenario_name) if llm_entry else None

    # ── 결과 출력 ─────────────────────────────────────────────────────────────
    print(f"\n  ┌── Run {run_num} 결과 ──────────────────────────────────")
    print(f"  │  MTTD          : {mttd}s")
    print(f"  │  MTTA          : {mtta}s")
    if llm_score:
        print(f"  │  confidence    : {llm_score['confidence']:.2f}")
        tl = llm_score['threat_level']
        ok = '✅' if llm_score['threat_level_ok'] else '❌'
        print(f"  │  threat_level  : {tl} {ok}")
        print(f"  │  action 관련성 : {'✅' if llm_score['action_ok'] else '❌'}")
        print(f"  │  evidence 수   : {llm_score['evidence_count']} ({'✅' if llm_score['evidence_ok'] else '❌'})")
        print(f"  │  quality_score : {llm_score['quality_score']:.3f}")
    else:
        print(f"  │  LLM 결과 없음 (alert 미발화 또는 pipeline 타임아웃)")
    print(f"  └{'─'*46}")

    return {
        "run":                  run_num,
        "scenario":             scenario_name,
        "start_time":           run_start_iso,
        "scenario_duration_s":  scenario_duration,
        "exit_code":            proc.returncode,
        "mttd_seconds":         mttd,
        "mtta_seconds":         mtta,
        "llm_score":            llm_score,
    }


# ── 배치 실행 ─────────────────────────────────────────────────────────────────
def run_batch(scenario_name: str) -> tuple[list[dict], Path]:
    cfg         = SCENARIOS[scenario_name]
    all_results = []
    ts_str      = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_path = RESULTS_DIR / f"{scenario_name}_{ts_str}.json"

    print(f"\n{'#'*60}")
    print(f"  배치 시작: {scenario_name}  ({RUNS}회)")
    print(f"  alertmanager 경유: {'예' if cfg['uses_alertmanager'] else '아니오 (직접 webhook)'}")
    print(f"  결과 저장: {result_path}")
    print(f"{'#'*60}")

    for i in range(1, RUNS + 1):
        result = run_once(scenario_name, i)
        all_results.append(result)

        # 중간 저장 (실행 도중 중단돼도 데이터 보존)
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False)

        if i < RUNS:
            if cfg["uses_alertmanager"]:
                restart_alertmanager()

            remaining_cooldown = COOLDOWN_SEC - (15 if cfg["uses_alertmanager"] else 0)
            if remaining_cooldown > 0:
                print(f"\n  → 쿨다운 {remaining_cooldown}s 대기 (alert 해소 + 안정화)...", flush=True)
                time.sleep(remaining_cooldown)

    return all_results, result_path


# ── 콘솔 리포트 출력 ──────────────────────────────────────────────────────────
def print_report(scenario_name: str, results: list[dict]) -> None:
    n = len(results)
    print(f"\n{'='*60}")
    print(f"  📊 {scenario_name} 종합 리포트  ({n}회 실행)")
    print(f"{'='*60}")

    # MTTD
    mttds = [r["mttd_seconds"] for r in results if r.get("mttd_seconds") is not None]
    print(f"\n  [MTTD] Alert 탐지 시간  ({len(mttds)}/{n}회 측정 성공)")
    if mttds:
        avg = sum(mttds) / len(mttds)
        print(f"    평균: {avg:.1f}s  |  최소: {min(mttds):.1f}s  |  최대: {max(mttds):.1f}s")
        # 표준편차
        variance = sum((x - avg) ** 2 for x in mttds) / len(mttds)
        print(f"    표준편차: {variance**0.5:.1f}s")
    else:
        print(f"    측정 데이터 없음")

    # MTTA
    mttas = [r["mtta_seconds"] for r in results if r.get("mtta_seconds") is not None]
    print(f"\n  [MTTA] LLM 결과 생성 시간  ({len(mttas)}/{n}회 측정 성공)")
    if mttas:
        avg = sum(mttas) / len(mttas)
        print(f"    평균: {avg:.1f}s  |  최소: {min(mttas):.1f}s  |  최대: {max(mttas):.1f}s")
        variance = sum((x - avg) ** 2 for x in mttas) / len(mttas)
        print(f"    표준편차: {variance**0.5:.1f}s")
    else:
        print(f"    측정 데이터 없음")

    # LLM 품질
    scores = [r["llm_score"] for r in results if r.get("llm_score")]
    print(f"\n  [LLM 품질]  ({len(scores)}/{n}회 결과 수집 성공)")
    if scores:
        confs   = [s["confidence"]   for s in scores]
        qs      = [s["quality_score"] for s in scores]
        ev_cnts = [s["evidence_count"] for s in scores]
        rc_wds  = [s["root_cause_words"] for s in scores]

        threat_ok_cnt   = sum(1 for s in scores if s["threat_level_ok"])
        action_ok_cnt   = sum(1 for s in scores if s["action_ok"])
        evidence_ok_cnt = sum(1 for s in scores if s["evidence_ok"])

        m = len(scores)
        print(f"    평균 confidence    : {sum(confs)/m:.3f}")
        print(f"    평균 quality_score : {sum(qs)/m:.3f}")
        print(f"    threat_level 정확도: {threat_ok_cnt}/{m}  ({threat_ok_cnt/m*100:.0f}%)")
        print(f"    action 관련성      : {action_ok_cnt}/{m}  ({action_ok_cnt/m*100:.0f}%)")
        print(f"    evidence 충분성    : {evidence_ok_cnt}/{m}  ({evidence_ok_cnt/m*100:.0f}%)")
        print(f"    평균 evidence 수   : {sum(ev_cnts)/m:.1f}개")
        print(f"    평균 root_cause 길이: {sum(rc_wds)/m:.0f} 단어")

        # threat_level 분포
        from collections import Counter
        tl_dist = Counter(s["threat_level"] for s in scores)
        print(f"\n    threat_level 분포: {dict(tl_dist)}")

        # 개별 run 요약 테이블
        print(f"\n  {'Run':>3}  {'MTTD':>7}  {'MTTA':>7}  {'conf':>5}  {'threat':>8}  {'TL':>2}  {'Act':>3}  {'Ev':>3}  {'Q-score':>7}")
        print(f"  {'─'*3}  {'─'*7}  {'─'*7}  {'─'*5}  {'─'*8}  {'─'*2}  {'─'*3}  {'─'*3}  {'─'*7}")
        for r in results:
            run    = r["run"]
            mttd_v = f"{r['mttd_seconds']:.1f}s" if r.get("mttd_seconds") is not None else "  -  "
            mtta_v = f"{r['mtta_seconds']:.1f}s" if r.get("mtta_seconds") is not None else "  -  "
            s = r.get("llm_score")
            if s:
                conf_v  = f"{s['confidence']:.2f}"
                tl_v    = s['threat_level'][:8]
                tl_ok   = "✅" if s["threat_level_ok"] else "❌"
                act_ok  = "✅" if s["action_ok"] else "❌"
                ev_ok   = f"{s['evidence_count']}"
                q_v     = f"{s['quality_score']:.3f}"
            else:
                conf_v = tl_v = tl_ok = act_ok = ev_ok = q_v = "  -  "
            print(f"  {run:>3}  {mttd_v:>7}  {mtta_v:>7}  {conf_v:>5}  {tl_v:>8}  {tl_ok:>2}  {act_ok:>3}  {ev_ok:>3}  {q_v:>7}")
    else:
        print(f"    LLM 결과 없음 (alert 미발화)")

    print(f"\n{'='*60}\n")


# ── 시작 시 검증 ──────────────────────────────────────────────────────────────
def validate_scenarios(target: list[str]) -> bool:
    """
    실행 전 SCENARIOS 설정의 일관성을 검사.
    - 스크립트 파일 존재 여부
    - log_key가 시나리오 스크립트의 scenario_name과 일치하는지
      (ScenarioVerifier(scenario_name=...) 호출 라인을 정규식으로 탐색)
    문제 발견 시 경고 출력 후 계속 진행 (중단하지 않음).
    """
    import re
    ok = True
    print("\n  [검증] SCENARIOS 설정 확인 중...")
    for name in target:
        cfg = SCENARIOS[name]
        script = cfg["script"]

        # 스크립트 파일 존재 확인
        if not Path(script).exists():
            print(f"  ❌ [{name}] 스크립트 없음: {script}")
            ok = False
            continue

        # log_key vs ScenarioVerifier(scenario_name=...) 비교
        content = Path(script).read_text(encoding="utf-8")
        matches = re.findall(r'ScenarioVerifier\s*\([^)]*scenario_name\s*=\s*["\']([^"\']+)["\']', content)
        if matches:
            script_key = matches[0]
            if script_key != cfg["log_key"]:
                print(
                    f"  ⚠️  [{name}] log_key 불일치 — "
                    f"SCENARIOS에 '{cfg['log_key']}' 설정됐으나 "
                    f"스크립트엔 '{script_key}'. MTTD가 항상 None이 될 수 있음."
                )
                ok = False
        else:
            print(f"  ⚠️  [{name}] ScenarioVerifier scenario_name 탐지 실패 (확인 불가)")

        print(f"  ✅ [{name}] 검증 통과  (script=.../{Path(script).name}, log_key={cfg['log_key']})")

    print()
    return ok


# ── 진입점 ────────────────────────────────────────────────────────────────────
def main():
    # CLI 인자로 특정 시나리오 지정 가능: python -m eval.batch_runner cpu_stress
    # 없으면 SCENARIOS에 등록된 전체 실행
    import sys as _sys
    cli_args = _sys.argv[1:]
    if cli_args:
        unknown = [a for a in cli_args if a not in SCENARIOS]
        if unknown:
            print(f"알 수 없는 시나리오: {unknown}")
            print(f"등록된 시나리오: {list(SCENARIOS.keys())}")
            _sys.exit(1)
        target_scenarios = cli_args
    else:
        target_scenarios = list(SCENARIOS.keys())  # 추가 시 자동 포함

    validate_scenarios(target_scenarios)

    all_batch_results = {}

    for scenario_name in target_scenarios:
        results, path = run_batch(scenario_name)
        all_batch_results[scenario_name] = results
        print_report(scenario_name, results)
        print(f"  💾 결과 저장 완료: {path}\n")

    # 전체 요약
    print(f"\n{'#'*60}")
    print(f"  ✅ 전체 배치 완료")
    print(f"{'#'*60}")
    for sname, results in all_batch_results.items():
        scores = [r["llm_score"] for r in results if r.get("llm_score")]
        mttds  = [r["mttd_seconds"] for r in results if r.get("mttd_seconds") is not None]
        q_avg  = sum(s["quality_score"] for s in scores) / len(scores) if scores else None
        m_avg  = sum(mttds) / len(mttds) if mttds else None
        q_str  = f"{q_avg:.3f}" if q_avg is not None else "N/A"
        m_str  = f"{m_avg:.1f}s" if m_avg is not None else "N/A"
        print(f"  {sname:25s}  MTTD 평균={m_str:8s}  LLM quality 평균={q_str}")
    print()


if __name__ == "__main__":
    main()
