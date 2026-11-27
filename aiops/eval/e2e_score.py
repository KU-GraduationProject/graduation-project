"""
E2E 실행 결과 채점 — pipeline 이 남긴 RCA 결과를 시나리오 실행 기록과 짝지어 지표를 계산한다.

입력:
  --results : pipeline RCA 결과. Loki {job="aiops-llm"} 를 내려받은 파일.
              (a) 한 줄에 RCA 항목 JSON 하나(JSONL, logcli --output=raw) 또는
              (b) Loki /loki/api/v1/query_range 응답 JSON 그대로.
  --runs    : 시나리오 실행 기록(scenarios/v2/run.py 가 남기는 runs.jsonl).
짝짓기: RCA 항목의 alert_starts_at 이 [실행 시작, 실행 끝 + grace] 안인 실행 하나(fixtures.pair_context).
채점: eval/harness.score 와 같다 — expected_action / expected_action_ideal 두 기준, 대상 일치율,
      증거에 없는 대상 생성률, 다운그레이드율. 평가 분할 실행은 --include-eval 일 때만 넣는다.

사용법과 측정 설정(LLM_PROVIDER=ollama)은 docs/llm/E2E_SCORING.md.

실행 (aiops 디렉터리에서):
  python -m eval.e2e_score --results rca.jsonl --runs ../scenarios/v2/fixtures_data/runs.jsonl --out <dir>
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from eval import harness
from v2 import fixtures


def load_results(path: str) -> list[dict]:
    """RCA 항목 목록. JSONL(항목 한 줄씩)과 Loki query_range 응답을 둘 다 받는다."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None
    if isinstance(doc, dict) and "data" in doc:
        lines = [line for stream in doc["data"].get("result", []) for _, line in stream.get("values", [])]
    elif isinstance(doc, dict):
        lines = [text]
    else:
        lines = [line for line in text.splitlines() if line.strip()]
    entries = []
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and isinstance(entry.get("result"), dict) and entry.get("alert_starts_at"):
            entries.append(entry)
    return entries


def pair(entries: list[dict], runs: list[dict], grace_seconds: float, include_eval: bool):
    """(채점할 레코드, 짝짓지 못한 항목 보고)"""
    records, skipped = [], []
    for entry in entries:
        run, reason = fixtures.pair_context(runs, entry["alert_starts_at"], grace_seconds)
        key = {"alert": entry.get("alert_name"), "alert_starts_at": entry["alert_starts_at"]}
        if run is None:
            skipped.append({**key, "reason": reason})
            continue
        split = harness.split_of(run["scenario_id"], run.get("variant_id"))
        if split == "eval" and not include_eval:
            skipped.append({**key, "reason": "eval_split_excluded"})
            continue
        if harness._row(run["scenario_id"]) is None:
            skipped.append({**key, "reason": "unknown_scenario_id"})
            continue
        rec = {
            "fixture": entry.get("alert_fingerprint") or entry["alert_starts_at"],
            "scenario_id": run["scenario_id"], "variant_id": run.get("variant_id"), "split": split,
            "builder": "e2e", "alert": entry.get("alert_name"), "alert_starts_at": entry["alert_starts_at"],
            "handoff_status": entry.get("handoff_status"),
            # E2E 항목에는 토큰·지연·프롬프트가 없다 (n/a 로 표시된다)
            "prompt_eval_count": None, "prompt_tokens_est": None, "input_truncated": None,
            "latency_s": None, "prompt_leaks": [], "result": entry["result"],
        }
        rec.update(harness.score(rec))
        records.append(rec)
    return records, skipped


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="E2E RCA 결과 채점")
    ap.add_argument("--results", required=True, help="Loki {job=\"aiops-llm\"} 내보내기 (JSONL 또는 query_range JSON)")
    ap.add_argument("--runs", required=True, help="scenarios/v2 실행 기록 runs.jsonl")
    ap.add_argument("--grace", type=float, default=300, help="실행 종료 후 경보를 받아 줄 여유(초)")
    ap.add_argument("--include-eval", action="store_true", help="평가 분할 실행도 포함")
    ap.add_argument("--out", default=None, help="scored.jsonl / summary.json / summary.md 를 쓸 폴더")
    args = ap.parse_args(argv)

    with open(args.runs, encoding="utf-8") as fh:
        runs = [json.loads(line) for line in fh if line.strip()]
    entries = load_results(args.results)
    records, skipped = pair(entries, runs, args.grace, args.include_eval)
    if not records:
        print(f"채점할 항목이 없다 (RCA {len(entries)}건, 제외 {len(skipped)}건)", file=sys.stderr)
        return 1
    summary = harness.summarize(records)
    table = harness.render_table(summary)
    print(table)
    print(f"RCA {len(entries)}건 중 채점 {len(records)}건, 제외 {len(skipped)}건")
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        with open(os.path.join(args.out, "scored.jsonl"), "w", encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        with open(os.path.join(args.out, "summary.json"), "w", encoding="utf-8") as fh:
            json.dump({"summary": summary, "skipped": skipped}, fh, ensure_ascii=False, indent=2)
        with open(os.path.join(args.out, "summary.md"), "w", encoding="utf-8") as fh:
            fh.write(table)
    return 0


if __name__ == "__main__":
    sys.exit(main())
