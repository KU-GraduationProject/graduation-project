"""
LLM 품질 평가 스크립트

[1단계] 모델 선택: 3개 모델 × 4개 대표 케이스 × temperature=0 × 1회
[2단계] 집중 평가: 선택 모델 × 8개 전체 케이스 × {baseline, few-shot} × temperature=0.3 × 5회

실행:
  python run_eval.py                          # 전체 실행
  python run_eval.py --phase 1               # 1단계만
  python run_eval.py --phase 2 --model 3b    # 2단계, 모델 지정
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from eval.test_cases import (
    TEST_CASES,
    REPRESENTATIVE_CASE_IDS,
    SYSTEM_PROMPT_BASELINE,
)
from pipeline.prompt.builder import SYSTEM_PROMPT as SYSTEM_PROMPT_FEWSHOT

# ── 설정 ──────────────────────────────────────────────────────────────────────
OLLAMA_URL   = os.getenv("OLLAMA_URL", "http://localhost:11434")
RESULTS_DIR  = os.path.join(os.path.dirname(__file__), "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

MODELS = {
    "3b":       "llama3.2:3b",
    "8b":       "llama3.1:8b",
    # Note: llama3.1:8b-instruct-q4_K_M == llama3.1:8b (동일 ID)
    # Ollama 기본 8b가 이미 Q4 양자화 → 별도 실험 불필요
}

PHASE1_OPTIONS = {"temperature": 0, "num_ctx": 2048, "num_predict": 400}
PHASE2_OPTIONS = {"temperature": 0.3, "num_ctx": 2048, "num_predict": 400}


# ── Ollama 호출 ───────────────────────────────────────────────────────────────
def call_ollama(model: str, system: str, user: str, options: dict) -> tuple[dict | None, float]:
    """Ollama /api/chat 호출. (파싱결과, 소요시간초) 반환."""
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
        "format": "json",
        "stream": False,
        "options": options,
    }).encode()

    t0 = time.time()
    try:
        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=180) as resp:
            raw = json.loads(resp.read())["message"]["content"]
        elapsed = time.time() - t0
        return json.loads(raw), elapsed
    except urllib.error.URLError as e:
        print(f"    [ERROR] Ollama 연결 실패: {e}")
        return None, time.time() - t0
    except json.JSONDecodeError as e:
        print(f"    [ERROR] JSON 파싱 실패: {e}")
        return None, time.time() - t0
    except Exception as e:
        print(f"    [ERROR] 예외: {e}")
        return None, time.time() - t0


# ── 단일 케이스 평가 ──────────────────────────────────────────────────────────
def evaluate_case(
    model_key: str,
    model_name: str,
    case: dict,
    prompt_variant: str,   # "baseline" | "few-shot"
    options: dict,
    run_idx: int = 0,
) -> dict:
    system_prompt = SYSTEM_PROMPT_FEWSHOT if prompt_variant == "few-shot" else SYSTEM_PROMPT_BASELINE
    result, elapsed = call_ollama(model_name, system_prompt, case["user_prompt"], options)

    expected = case["expected"]
    actual_action   = result.get("action_type", "PARSE_ERROR") if result else "CALL_ERROR"
    actual_risk     = result.get("action_risk", "")            if result else ""
    actual_threat   = result.get("threat_level", "")           if result else ""
    actual_conf     = result.get("confidence", 0.0)            if result else 0.0
    actual_rc       = result.get("root_cause", "")             if result else ""

    action_correct  = actual_action == expected["action_type"]
    risk_correct    = actual_risk   == expected["action_risk"]
    threat_correct  = actual_threat == expected["threat_level"]
    parse_ok        = result is not None

    entry = {
        "case_id":         case["case_id"],
        "description":     case["description"],
        "model":           model_key,
        "model_name":      model_name,
        "prompt_variant":  prompt_variant,
        "options":         options,
        "run_idx":         run_idx,
        "expected":        expected,
        "actual": {
            "action_type":   actual_action,
            "action_risk":   actual_risk,
            "threat_level":  actual_threat,
            "confidence":    actual_conf,
            "root_cause":    actual_rc,
            "raw":           result,
        },
        "action_correct":  action_correct,
        "risk_correct":    risk_correct,
        "threat_correct":  threat_correct,
        "parse_ok":        parse_ok,
        "inference_time_sec": round(elapsed, 2),
        "timestamp":       datetime.now(timezone.utc).isoformat(),
    }

    status = "✓" if action_correct else "✗"
    print(f"    [{status}] action={actual_action:<10} (expected={expected['action_type']:<10}) "
          f"conf={actual_conf:.2f}  {elapsed:.1f}s")
    return entry


# ── 결과 저장 ─────────────────────────────────────────────────────────────────
def save_results(entries: list[dict], phase: int) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(RESULTS_DIR, f"eval_phase{phase}_{ts}.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(f"\n[SAVED] {path}")
    return path


# ── 집계 출력 ─────────────────────────────────────────────────────────────────
def print_phase1_summary(entries: list[dict]):
    print("\n" + "="*60)
    print("  1단계 결과 — 모델별 정확도 (대표 케이스 4개)")
    print("="*60)
    print(f"{'모델':<12} {'action_acc':>10} {'risk_acc':>8} {'parse_ok':>8} {'avg_time':>10}")
    print("-"*60)

    for model_key in MODELS:
        rows = [e for e in entries if e["model"] == model_key]
        if not rows:
            continue
        action_acc = sum(1 for r in rows if r["action_correct"]) / len(rows)
        risk_acc   = sum(1 for r in rows if r["risk_correct"])   / len(rows)
        parse_rate = sum(1 for r in rows if r["parse_ok"])       / len(rows)
        avg_time   = sum(r["inference_time_sec"] for r in rows)  / len(rows)
        print(f"{model_key:<12} {action_acc:>9.0%} {risk_acc:>8.0%} {parse_rate:>8.0%} {avg_time:>9.1f}s")
    print("="*60)


def print_phase2_summary(entries: list[dict]):
    print("\n" + "="*70)
    print("  2단계 결과 — baseline vs few-shot 비교 (8케이스 × 5회)")
    print("="*70)
    print(f"{'프롬프트':<12} {'action_acc':>10} {'risk_acc':>8} {'consistency':>12} {'conf_mean':>10} {'avg_time':>10}")
    print("-"*70)

    for variant in ["baseline", "few-shot"]:
        rows = [e for e in entries if e["prompt_variant"] == variant]
        if not rows:
            continue

        action_acc   = sum(1 for r in rows if r["action_correct"]) / len(rows)
        risk_acc     = sum(1 for r in rows if r["risk_correct"])   / len(rows)
        conf_mean    = sum(r["actual"]["confidence"] for r in rows) / len(rows)
        avg_time     = sum(r["inference_time_sec"] for r in rows)  / len(rows)

        # 일관성: 케이스별로 5회 모두 같은 action_type 비율
        consistency_scores = []
        for case_id in range(1, 9):
            case_rows = [e for e in rows if e["case_id"] == case_id]
            if len(case_rows) == 0:
                continue
            actions = [r["actual"]["action_type"] for r in case_rows]
            most_common = max(set(actions), key=actions.count)
            consistency_scores.append(actions.count(most_common) / len(actions))
        consistency = sum(consistency_scores) / len(consistency_scores) if consistency_scores else 0.0

        print(f"{variant:<12} {action_acc:>9.0%} {risk_acc:>8.0%} {consistency:>12.0%} {conf_mean:>10.2f} {avg_time:>9.1f}s")

    print("-"*70)

    # Δ 개선폭 계산
    baseline_rows  = [e for e in entries if e["prompt_variant"] == "baseline"]
    fewshot_rows   = [e for e in entries if e["prompt_variant"] == "few-shot"]
    if baseline_rows and fewshot_rows:
        b_acc = sum(1 for r in baseline_rows if r["action_correct"]) / len(baseline_rows)
        f_acc = sum(1 for r in fewshot_rows  if r["action_correct"]) / len(fewshot_rows)
        delta = (f_acc - b_acc) / b_acc * 100 if b_acc > 0 else 0
        print(f"{'Δ few-shot':<12} {'':>10} {'':>8} {'':>12} {'':>10} +{delta:.1f}% action_acc")
    print("="*70)


# ── 메인 ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", type=int, choices=[1, 2], default=0,
                        help="0=전체, 1=1단계만, 2=2단계만")
    parser.add_argument("--model", type=str, choices=list(MODELS.keys()),
                        help="2단계에서 사용할 모델 (미지정 시 1단계 결과로 자동 선택)")
    args = parser.parse_args()

    all_phase1: list[dict] = []
    all_phase2: list[dict] = []
    selected_model_key: str | None = args.model

    # ── 1단계: 모델 선택 ──────────────────────────────────────────────────────
    if args.phase in (0, 1):
        print("\n" + "="*60)
        print("  1단계: 모델 선택 (3개 모델 × 4개 대표 케이스, temperature=0)")
        print("="*60)

        rep_cases = [c for c in TEST_CASES if c["case_id"] in REPRESENTATIVE_CASE_IDS]
        PHASE1_RUNS = 10  # 케이스당 반복 횟수 (temperature=0 → determinism 검증)

        for model_key, model_name in MODELS.items():
            print(f"\n[모델] {model_key} ({model_name})")
            for case in rep_cases:
                print(f"  케이스 {case['case_id']}: {case['description']}")
                for run_idx in range(PHASE1_RUNS):
                    entry = evaluate_case(
                        model_key, model_name, case,
                        prompt_variant="few-shot",
                        options=PHASE1_OPTIONS,
                        run_idx=run_idx,
                    )
                    all_phase1.append(entry)

        save_results(all_phase1, phase=1)
        print_phase1_summary(all_phase1)

        # 자동 모델 선택: action_type 정확도 최고 모델
        if selected_model_key is None:
            model_scores = {}
            for mk in MODELS:
                rows = [e for e in all_phase1 if e["model"] == mk]
                if rows:
                    model_scores[mk] = sum(1 for r in rows if r["action_correct"]) / len(rows)
            if model_scores:
                selected_model_key = max(model_scores, key=model_scores.get)
                print(f"\n[선택] 1단계 기준 최고 정확도 모델: {selected_model_key} "
                      f"({model_scores[selected_model_key]:.0%})")

    # ── 2단계: 집중 평가 ──────────────────────────────────────────────────────
    if args.phase in (0, 2):
        if selected_model_key is None:
            print("[ERROR] 2단계 실행 시 --model 옵션이 필요합니다.")
            sys.exit(1)

        model_name = MODELS[selected_model_key]
        print(f"\n" + "="*60)
        print(f"  2단계: 집중 평가 (모델={selected_model_key}, temperature=0.3, 5회)")
        print("="*60)

        PHASE2_RUNS = 20  # 케이스당 반복 횟수 (temperature=0.3 → 통계적 유의성)
        for variant in ["baseline", "few-shot"]:
            print(f"\n[프롬프트 변형] {variant}")
            for case in TEST_CASES:
                print(f"  케이스 {case['case_id']}: {case['description']}")
                for run_idx in range(PHASE2_RUNS):
                    entry = evaluate_case(
                        selected_model_key, model_name, case,
                        prompt_variant=variant,
                        options=PHASE2_OPTIONS,
                        run_idx=run_idx,
                    )
                    all_phase2.append(entry)

        save_results(all_phase2, phase=2)
        print_phase2_summary(all_phase2)

    print("\n[완료] 결과 파일이 aiops/eval/results/ 에 저장되었습니다.")
    print("[다음] 결과 파일을 Claude에게 보여주면 root_cause 품질 판별을 진행합니다.")


if __name__ == "__main__":
    main()
