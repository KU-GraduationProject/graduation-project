"""
LLM 판단 평가 하네스 (scenarios-v2 픽스처 기반).

흐름: 픽스처(경보 시점 컨텍스트) → pipeline build()(legacy | v2) → 고정 LLM 설정으로 N회
      (seed = seed_base + 반복 번호) → 엄격 파싱(schemas/llm_output.parse_analysis)
      → 레지스트리(scenarios/v2/registry.py) 정답과 채점.

1학기 eval(run_eval.py, 고정 프롬프트 8개)은 build() 를 거치지 않아 실제 입력 결함을 못 잡는다.
그 eval 은 회귀용으로 그대로 두고, 이 하네스는 pipeline 이 실제로 만드는 프롬프트를 평가한다.

정답은 픽스처에 없다. 픽스처의 scenario_id 로 레지스트리에서 조회한다. build() 에는
alert 와 observations 만 넘긴다 — scenario_id·variant_id·seed 는 프롬프트에 들어가지 않는다
(만든 프롬프트를 prompt_leaks() 로 다시 검사해 기록한다).

튜닝/평가 분할: 저장소에 공개된 튜닝 변형(v2.variants.VARIANT_SPECS)이면 tuning, 그 밖은
eval 로 본다. eval 은 기본 실행에서 빠지고 --include-eval 일 때만 들어간다.

픽스처 observations 키 (fixtures.capture_on_alert 가 저장할 내용):
  received_at : 경보 수신 시각 (ISO)
  container   : 분석 대상 컨테이너 (없으면 alert.annotations.container)
  rule        : collector.rules.RuleContext.as_dict()  (없으면 "값 조회 실패" 로 표시됨)
  metrics     : MetricsCollector.fetch_around() 결과   (별칭: prometheus)
  logs        : LogsCollector.fetch() 결과              (별칭: loki)
  log_query   : {"start", "end", "limit"}  (선택)
  network     : NetworkContext 필드 dict (service, start, end, events, errors, skipped, truncated)

실행 (aiops 디렉터리에서):
  python -m eval.harness --fixtures ../scenarios/v2/fixtures_data --reps 5
  python -m eval.harness --fixtures DIR --builder both          # legacy vs v2 비교
  python -m eval.harness --fixtures DIR --include-eval          # 평가 분할 포함
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import statistics
import sys
import time
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from types import SimpleNamespace

_HERE = os.path.dirname(os.path.abspath(__file__))
_PIPELINE_DIR = os.path.abspath(os.path.join(_HERE, "..", "pipeline"))
_SCENARIOS_DIR = os.path.abspath(os.path.join(_HERE, "..", "..", "scenarios"))
for _p in (_PIPELINE_DIR, _SCENARIOS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from collector.network import NetworkContext  # noqa: E402
from collector.rules import RuleContext  # noqa: E402
from config import settings  # noqa: E402
from correlation import to_instant  # noqa: E402
from prompt.builder import make_builder  # noqa: E402
from prompt.builder_v2 import est_tokens  # noqa: E402
from schemas.llm_output import LLMAnalysisResult, output_schema, parse_analysis  # noqa: E402
from v2 import registry, variants  # noqa: E402

BUILDERS = ("legacy", "v2")
CONTROL_PREFIX = "c_"   # 대조 시나리오 (registry id 규칙)
# 조치 강도 순위: 과잉/과소 대응 판정용. 같은 순위끼리(PAUSE/ISOLATE)는 오답이지만 과잉·과소는 아니다.
ACTION_RANK = {"NONE": 0, "NOTIFY": 1, "THROTTLE": 2, "RESTART": 3, "PAUSE": 4, "ISOLATE": 4}

# 측정 재현을 위해 pipeline 과 같은 LLM 설정을 쓴다 (seed 만 반복마다 바꾼다)
LLM_OPTIONS = {"temperature": settings.llm_temperature, "num_ctx": settings.llm_num_ctx,
               "num_predict": settings.llm_num_predict}


# ─── 픽스처 ───────────────────────────────────────────────────────────────────
def split_of(scenario_id: str, variant_id: str | None) -> str:
    """공개 튜닝 변형이거나 변형 없음 → tuning. 그 밖(평가용·미등록) → eval."""
    if variant_id is None or variant_id in variants.VARIANT_SPECS.get(scenario_id, {}):
        return "tuning"
    return "eval"


def load_fixtures(directory: str) -> list[dict]:
    fixtures = []
    for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
        with open(path, encoding="utf-8") as fh:
            fx = json.load(fh)
        fx["_file"] = os.path.basename(path)
        fx["_split"] = split_of(fx["scenario_id"], fx.get("variant_id"))
        fixtures.append(fx)
    return fixtures


def select(fixtures: list[dict], include_eval: bool = False) -> list[dict]:
    return [f for f in fixtures if include_eval or f["_split"] == "tuning"]


def _alert_obj(alert: dict) -> SimpleNamespace:
    labels = dict(alert.get("labels") or {})
    labels.setdefault("severity", None)
    labels.setdefault("container", None)
    return SimpleNamespace(labels=SimpleNamespace(**labels), annotations=alert.get("annotations") or {},
                           startsAt=alert["startsAt"])


def build_inputs(fx: dict) -> dict:
    """픽스처 → build() 인자. 시나리오 메타(scenario_id·variant_id·seed)는 넘기지 않는다."""
    obs = fx.get("observations") or {}
    alert = fx["alert"]
    net = obs.get("network")
    network = None
    if net:
        network = NetworkContext(
            service=net.get("service"), start=to_instant(net["start"]), end=to_instant(net["end"]),
            events=tuple(net.get("events") or ()), errors=tuple(net.get("errors") or ()),
            skipped=net.get("skipped", 0), truncated=net.get("truncated", False))
    lq = obs.get("log_query")
    return {
        "alert": _alert_obj(alert),
        "metrics": obs.get("metrics", obs.get("prometheus")) or {},
        "logs": obs.get("logs", obs.get("loki")) or [],
        "container_name": obs.get("container") or (alert.get("annotations") or {}).get("container"),
        "network": network,
        "rule": RuleContext.from_dict(obs["rule"]) if obs.get("rule") else None,
        "received_at": to_instant(obs["received_at"]) if obs.get("received_at") else None,
        "log_meta": ({"start": to_instant(lq["start"]), "end": to_instant(lq["end"]), "limit": lq.get("limit")}
                     if lq else None),
    }


def prompt_leaks(prompt: dict, fx: dict) -> list[str]:
    """프롬프트에 시나리오 이름·레이블·변형 id·정답 키가 들어갔는지 (있으면 그 목록)."""
    text = (prompt["system"] + "\n" + prompt["user"]).lower()
    row = _row(fx["scenario_id"])
    needles = [fx["scenario_id"], row.get("label", "")] if row else [fx["scenario_id"]]
    if fx.get("variant_id"):
        needles.append(fx["variant_id"])
    needles += ["expected_action", "ground_truth", "should_alert"]
    return [n for n in needles if n and n.lower() in text]


def _row(scenario_id: str) -> dict | None:
    return next((r for r in registry.SCENARIO_REGISTRY_V2 if r["id"] == scenario_id), None)


# ─── LLM 호출 ────────────────────────────────────────────────────────────────
def chat_request(prompt: dict, seed: int) -> dict:
    return {
        "model": settings.llm_model,
        "messages": [{"role": "system", "content": prompt["system"]},
                     {"role": "user", "content": prompt["user"]}],
        "format": output_schema(prompt.get("evidence_ids")),
        "stream": False,
        "options": dict(LLM_OPTIONS, seed=seed),
    }


def ollama_chat(url: str, timeout: float = settings.llm_timeout):
    def chat(body: dict) -> dict:
        req = urllib.request.Request(f"{url}/api/chat", data=json.dumps(body).encode("utf-8"),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    return chat


# ─── 실행·채점 ───────────────────────────────────────────────────────────────
def run_one(fx: dict, builder: str, prompt: dict, rep: int, seed_base: int, chat) -> dict:
    seed = seed_base + rep
    started = time.monotonic()
    error, data = None, {}
    try:
        data = chat(chat_request(prompt, seed))
    except Exception as e:  # 호출 실패도 한 번의 결과로 남긴다
        error = repr(e)[:300]
    latency = time.monotonic() - started
    content = (data.get("message") or {}).get("content")
    if error:
        result = LLMAnalysisResult.invalid(["llm_call_failed"])
    else:
        result = parse_analysis(content, evidence_ids=prompt.get("evidence_ids"),
                                done_reason=data.get("done_reason"),
                                prompt_eval_count=data.get("prompt_eval_count"),
                                num_ctx=LLM_OPTIONS["num_ctx"], num_predict=LLM_OPTIONS["num_predict"])
    record = {
        "fixture": fx["_file"], "scenario_id": fx["scenario_id"], "variant_id": fx.get("variant_id"),
        "split": fx["_split"], "builder": builder, "rep": rep, "seed": seed,
        "model": settings.llm_model, "options": dict(LLM_OPTIONS, seed=seed),
        "prompt_tokens_est": est_tokens(prompt["system"] + prompt["user"]), "prompt_eval_count": data.get("prompt_eval_count"),
        "eval_count": data.get("eval_count"), "done_reason": data.get("done_reason"),
        "latency_s": round(latency, 3),
        "total_duration_s": (data.get("total_duration") or 0) / 1e9 or None,
        "input_truncated": prompt.get("truncated"), "sections": prompt.get("sections"),
        "prompt_leaks": prompt_leaks(prompt, fx), "call_error": error,
        "raw_content": content, "result": result.model_dump(),
    }
    record.update(score(record))
    if rep == 0:
        record["prompt"] = {"system": prompt["system"], "user": prompt["user"]}
    return record


def score(record: dict) -> dict:
    row = _row(record["scenario_id"])
    if row is None:
        raise KeyError(f"registry 에 없는 scenario_id: {record['scenario_id']}")
    r = record["result"]
    valid = r["analysis_status"] == "valid"
    exp_action = row["expected_action"]
    out = {
        "expected": {"action_type": exp_action, "threat_level": row["threat_level"],
                     "incident_class": row["incident_class"]},
        "is_control": record["scenario_id"].startswith(CONTROL_PREFIX),
        "valid": valid,
        # invalid 는 오답으로 센다 (분석 실패를 맞힌 것으로 치지 않는다)
        "action_correct": valid and r["action_type"] == exp_action,
        "threat_correct": valid and r["threat_level"] == row["threat_level"],
        "class_correct": valid and r["incident_class"] == row["incident_class"],
        "evidence_cited": valid and bool(r["evidence"]),
        "over_response": None, "under_response": None,
    }
    if valid:
        diff = ACTION_RANK[r["action_type"]] - ACTION_RANK[exp_action]
        out["over_response"], out["under_response"] = diff > 0, diff < 0
    return out


def run(fixtures: list[dict], builders=("v2",), reps: int = 5, seed_base: int = 1000, chat=None,
        out_dir: str | None = None) -> tuple[list[dict], dict]:
    if chat is None:
        chat = ollama_chat(settings.ollama_url)
    records = []
    for fx in fixtures:
        inputs = build_inputs(fx)
        for builder in builders:
            prompt = make_builder(builder).build(**inputs)
            for rep in range(reps):
                records.append(run_one(fx, builder, prompt, rep, seed_base, chat))
    summary = summarize(records)
    if out_dir:
        write_outputs(records, summary, out_dir)
    return records, summary


# ─── 요약 ────────────────────────────────────────────────────────────────────
def _rate(xs) -> float | None:
    xs = [x for x in xs if x is not None]
    return round(sum(map(bool, xs)) / len(xs), 4) if xs else None


def _dist(xs) -> dict | None:
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    return {"n": len(xs), "mean": round(statistics.fmean(xs), 4), "min": xs[0],
            "p50": statistics.median(xs), "p95": xs[min(len(xs) - 1, int(0.95 * len(xs)))], "max": xs[-1]}


def summarize(records: list[dict]) -> dict:
    by_builder = defaultdict(list)
    for rec in records:
        by_builder[rec["builder"]].append(rec)
    out = {}
    for builder, recs in by_builder.items():
        valid = [r for r in recs if r["valid"]]
        reasons = Counter(reason.split(":")[0] for r in recs if not r["valid"]
                          for reason in r["result"]["invalid_reasons"])
        has_ids = builder != "legacy"   # legacy 프롬프트에는 증거 ID 가 없다
        out[builder] = {
            "runs": len(recs),
            "fixtures": len({r["fixture"] for r in recs}),
            "splits": dict(Counter(r["split"] for r in recs)),
            "action_accuracy": _rate(r["action_correct"] for r in recs),
            "threat_accuracy": _rate(r["threat_correct"] for r in recs),
            "incident_class_accuracy": _rate(r["class_correct"] for r in recs),
            "evidence_cited_rate": _rate(r["evidence_cited"] for r in recs) if has_ids else None,
            "control_over_response_rate": _rate(r["over_response"] for r in valid if r["is_control"]),
            "control_under_response_rate": _rate(r["under_response"] for r in valid if r["is_control"]),
            "incident_over_response_rate": _rate(r["over_response"] for r in valid if not r["is_control"]),
            "incident_under_response_rate": _rate(r["under_response"] for r in valid if not r["is_control"]),
            "invalid_rate": _rate(not r["valid"] for r in recs),
            "invalid_by_reason": {k: round(v / len(recs), 4) for k, v in sorted(reasons.items())},
            "prompt_tokens": _dist(r["prompt_eval_count"] or r["prompt_tokens_est"] for r in recs),
            "input_truncated_rate": _rate(r["input_truncated"] for r in recs),
            "latency_s": _dist(r["latency_s"] for r in recs),
            "confidence_when_action_correct": _dist(r["result"]["confidence"] for r in valid if r["action_correct"]),
            "confidence_when_action_wrong": _dist(r["result"]["confidence"] for r in valid if not r["action_correct"]),
            "prompt_leak_runs": sum(1 for r in recs if r["prompt_leaks"]),
            "per_scenario_action_accuracy": {
                sid: _rate(r["action_correct"] for r in recs if r["scenario_id"] == sid)
                for sid in sorted({r["scenario_id"] for r in recs})},
        }
    return out


_TABLE_ROWS = (
    ("runs", "실행 수"), ("action_accuracy", "action 정확도"), ("threat_accuracy", "threat_level 정확도"),
    ("incident_class_accuracy", "incident_class 정확도"), ("evidence_cited_rate", "evidence 인용 비율"),
    ("control_over_response_rate", "대조 과잉대응률"), ("control_under_response_rate", "대조 과소대응률"),
    ("incident_over_response_rate", "사고 과잉대응률"), ("incident_under_response_rate", "사고 과소대응률"),
    ("invalid_rate", "invalid 비율"), ("input_truncated_rate", "입력 잘림 비율"),
    ("prompt_leak_runs", "프롬프트 누출 실행 수"),
)


def render_table(summary: dict) -> str:
    builders = list(summary)

    def cell(v):
        if isinstance(v, dict):
            return f"mean {v['mean']} / p50 {v['p50']} / max {v['max']} (n={v['n']})"
        return "n/a" if v is None else str(v)

    lines = ["| 지표 | " + " | ".join(builders) + " |", "|---|" + "---|" * len(builders)]
    rows = list(_TABLE_ROWS) + [("prompt_tokens", "프롬프트 토큰"), ("latency_s", "지연(초)"),
                                ("confidence_when_action_correct", "confidence(정답)"),
                                ("confidence_when_action_wrong", "confidence(오답)")]
    for key, label in rows:
        lines.append(f"| {label} | " + " | ".join(cell(summary[b].get(key)) for b in builders) + " |")
    reasons = sorted({k for b in builders for k in summary[b]["invalid_by_reason"]})
    for reason in reasons:
        lines.append(f"| invalid: {reason} | " + " | ".join(
            str(summary[b]["invalid_by_reason"].get(reason, 0)) for b in builders) + " |")
    return "\n".join(lines) + "\n"


def write_outputs(records: list[dict], summary: dict, out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "runs.jsonl"), "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "summary.md"), "w", encoding="utf-8") as fh:
        fh.write(render_table(summary))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--fixtures", required=True, help="픽스처 JSON 디렉터리")
    ap.add_argument("--builder", choices=BUILDERS + ("both",), default="v2")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--seed-base", type=int, default=1000)
    ap.add_argument("--include-eval", action="store_true", help="평가 분할 픽스처도 포함")
    ap.add_argument("--ollama-url", default=os.getenv("OLLAMA_URL", "http://localhost:11434"))
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    fixtures = select(load_fixtures(args.fixtures), args.include_eval)
    if not fixtures:
        print("선택된 픽스처가 없다", file=sys.stderr)
        return 1
    builders = BUILDERS if args.builder == "both" else (args.builder,)
    out = args.out or os.path.join(_HERE, "results",
                                   "harness_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    _, summary = run(fixtures, builders, args.reps, args.seed_base, ollama_chat(args.ollama_url), out)
    print(render_table(summary))
    print(f"결과: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
