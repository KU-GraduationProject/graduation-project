"""대조 이벤트(C-c/C-e) 집계. 측정이 끝난 뒤에만 실행한다(Loki query_range 를 쓴다).

    python -I collect_control.py --dir <run dir>

입력: control_plan.jsonl, requests.jsonl, alerts.jsonl, pipeline_window.log(docker logs -t 발췌)
출력: <run dir>/summary_control.json + 요약 출력
"""
import argparse
import ast
import collections
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))
from collect import alert_episodes, label_of  # noqa: E402

LOKI = "http://127.0.0.1:3100"
RULE_LHS = 'sum(count_over_time({service="frontend", log_format="json"} | json | status >= 400 and status < 500 [1m]))'


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def kst(t):
    return t.astimezone().strftime("%H:%M:%S")


def phases(path):
    rows = [json.loads(l) for l in open(path, encoding="utf-8")]
    out = {}
    for r in rows:
        p = out.setdefault(r["phase"], {"phase": r["phase"], "rate_per_min": r["rate_per_min"], "minutes": r["minutes"]})
        p[r["edge"]] = ts(r["ts"])
    return [out[k] for k in sorted(out)]


def loki_lhs(start, end):
    q = urllib.parse.urlencode({"query": RULE_LHS, "start": int(start.timestamp() * 1e9),
                                "end": int(end.timestamp() * 1e9), "step": "15s"})
    with urllib.request.urlopen(f"{LOKI}/loki/api/v1/query_range?{q}", timeout=120) as r:
        res = json.load(r)["data"]["result"]
    return [(datetime.fromtimestamp(float(t), timezone.utc), float(v)) for t, v in (res[0]["values"] if res else [])]


def pipeline_events(path):
    ev = []
    for line in open(path, encoding="utf-8-sig", errors="replace"):
        m = re.match(r"(\S+)\s+(.*)", line.rstrip("\n"))
        if not m:
            continue
        t, msg = ts(m.group(1)[:26] + "+00:00" if m.group(1).endswith("Z") else m.group(1)), m.group(2)
        if "[Pipeline] 분석 시작" in msg or "중복 Alert 스킵" in msg or "LLM 분석 시작" in msg or "컨테이너 정보 없음" in msg:
            ev.append({"ts": t, "kind": "pipeline", "msg": msg})
        elif "[LLM] model=" in msg:
            d = {"ts": t, "kind": "llm_call", "msg": msg}
            for k in ("prompt_eval_count", "eval_count", "total_duration", "done_reason"):
                mm = re.search(rf"(?<![a-z_]){k}=(\S+)", msg)  # eval_count 가 prompt_eval_count 에 걸리지 않게
                d[k] = mm.group(1) if mm else None
            ev.append(d)
        elif "LLM 분석 완료:" in msg:
            d = {"ts": t, "kind": "llm_result", "msg": msg}
            try:
                d["result"] = ast.literal_eval(msg.split("LLM 분석 완료:", 1)[1].strip())
            except Exception as e:
                d["parse_error"] = repr(e)
            ev.append(d)
        elif re.search(r"ERROR|실패|Traceback|WARNING:main:\[LLM\]", msg):
            ev.append({"ts": t, "kind": "error", "msg": msg})
    return ev


def main():
    global LOKI
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--loki", default=LOKI, help="Loki base URL (기본 http://127.0.0.1:3100)")
    a = ap.parse_args()
    LOKI = a.loki
    d = a.dir
    ph = phases(os.path.join(d, "control_plan.jsonl"))
    m_start, m_end = ph[0]["start"], ph[-1]["end"]
    req = [json.loads(l) for l in open(os.path.join(d, "requests.jsonl"), encoding="utf-8")]
    out = {"window": [m_start.isoformat(), m_end.isoformat()], "phases": []}

    lhs = loki_lhs(m_start, m_end)
    for p in ph:
        rows = [r for r in req if p["start"] <= ts(r["ts"]) < p["end"]]
        ctrl = [r for r in rows if r.get("control")]
        base = [r for r in rows if not r.get("control")]
        mins = (p["end"] - p["start"]).total_seconds() / 60
        c4 = [r for r in ctrl if 400 <= r["status"] < 500]
        b_bad = [r for r in base if r["status"] == 0 or r["status"] >= 400]
        vals = [v for t, v in lhs if p["start"] <= t < p["end"]]
        p.update({
            "baseline_requests": len(base), "baseline_rps": round(len(base) / (mins * 60), 3),
            "baseline_fail": len(b_bad), "baseline_fail_detail": collections.Counter(
                f'{r["method"]} {r["route"]} {r["status"]}' for r in b_bad).most_common(5),
            "control_by_tag_status": collections.Counter(f'{r["control"]} {r["status"]}' for r in ctrl).most_common(),
            "control_4xx": len(c4), "control_4xx_per_min": round(len(c4) / mins, 2),
            "loki_lhs_max": max(vals) if vals else 0, "loki_lhs_min": min(vals) if vals else 0,
            "loki_lhs_over_50_points": sum(v > 50 for v in vals), "loki_lhs_points": len(vals),
        })
        out["phases"].append({k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in p.items()})

    eps = alert_episodes(os.path.join(d, "alerts.jsonl"), m_start, m_end)
    out["alert_episodes"] = [{**e, "first": e["first"].isoformat(), "last": e["last"].isoformat()} for e in eps]
    out["loki_lhs_series"] = [(t.isoformat(), v) for t, v in lhs]

    pl = os.path.join(d, "pipeline_window.log")
    out["pipeline"] = [{**e, "ts": e["ts"].isoformat()} for e in pipeline_events(pl)] if os.path.exists(pl) else []

    with open(os.path.join(d, "summary_control.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1, default=str)

    print(f"window {kst(m_start)} ~ {kst(m_end)}")
    for p in out["phases"]:
        print(f" phase{p['phase']} {p['rate_per_min']}/min x{p['minutes']}m {kst(ts(p['start']))}-{kst(ts(p['end']))}: "
              f"ctrl4xx={p['control_4xx']} ({p['control_4xx_per_min']}/min) lokiLHS max={p['loki_lhs_max']} min={p['loki_lhs_min']} "
              f">50pts={p['loki_lhs_over_50_points']}/{p['loki_lhs_points']} base={p['baseline_requests']} ({p['baseline_rps']} rps) "
              f"base_fail={p['baseline_fail']} tags={p['control_by_tag_status']}")
    print(f"alert episodes: {len(eps)}")
    for e in eps:
        print(f"  {e['alertname']} [{label_of(e['labels'])}] startsAt={e['startsAt']} seen {kst(e['first'])}~{kst(e['last'])} "
              f"{e['duration_sec']:.0f}s states={e['states']}")
    for e in out["pipeline"]:
        print(f"  pipeline {e['ts'][11:19]}Z {e['kind']}: {e['msg'][:300]}")


if __name__ == "__main__":
    main()
