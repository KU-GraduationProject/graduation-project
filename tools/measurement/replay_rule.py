"""Prometheus 룰 식을 과거 구간에 다시 적용해 for 조건까지 반영한 발화를 계산한다.

    python -I replay_rule.py --expr "<PromQL>" --for 60 --start <ISO> --end <ISO> [--step 5] [--label name]

평가 규칙 (Prometheus alerting rule 과 같게):
- step(=evaluation_interval) 마다 식을 평가한다. 결과에 시리즈가 있으면 그 시점 '참'
- 참이 처음 된 시각 = activeAt. 평가 시각 - activeAt >= for 가 되는 첫 평가에서 firing
- 한 번이라도 거짓(시리즈 없음)이면 pending/firing 이 리셋된다
- 구간 시작 전 for+step 만큼 앞에서부터 평가해, 구간 시작 시점에 이미 진행 중인 pending 을 반영한다.
  발화 횟수·시간은 구간 안에 있는 부분만 센다
"""
import argparse
import json
import urllib.parse
import urllib.request
from datetime import datetime, timezone

PROM = "http://127.0.0.1:9090"


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).astimezone().isoformat(timespec="seconds")


def query_range(expr, start, end, step):
    out, t = {}, start
    chunk = step * 10000  # Prometheus 최대 11000 포인트
    while t <= end:
        e = min(end, t + chunk)
        q = urllib.parse.urlencode({"query": expr, "start": t, "end": e, "step": step})
        with urllib.request.urlopen(f"{PROM}/api/v1/query_range?{q}", timeout=120) as r:
            d = json.load(r)
        for s in d["data"]["result"]:
            key = json.dumps(s["metric"], sort_keys=True)
            out.setdefault(key, {}).update({round(float(p[0]), 3): float(p[1]) for p in s["values"]})
        t = e + step
    return out


def replay(points, start, end, step, for_sec):
    """points: {eval_ts: value}. 반환: 구간 안 에피소드 목록"""
    evals = sorted(points)
    eps, active, fire = [], None, None
    prev = None
    for t in evals + [None]:
        broken = t is None or (prev is not None and t - prev > step * 1.5)
        if broken and active is not None:
            eps.append((active, prev, fire))
            active, fire = None, None
        if t is None:
            break
        if active is None:
            active = t
        if fire is None and t - active >= for_sec:
            fire = t
        prev = t
    res = []
    for a, last, f in eps:
        if last < start or a > end:
            continue
        r = {"activeAt": iso(a), "last_true": iso(last), "pending_sec": (min(f, last + step) if f else last + step) - a}
        if f:
            fs, fe = max(f, start), min(last + step, end)
            r.update(firing_start=iso(f), firing_sec_in_window=max(0, fe - fs), fired_in_window=f <= end and last + step >= start)
        else:
            r.update(firing_start=None, firing_sec_in_window=0, fired_in_window=False)
        r["peak"] = max(points[t] for t in points if a <= t <= last)
        res.append(r)
    return res


def main():
    global PROM
    ap = argparse.ArgumentParser()
    ap.add_argument("--expr", required=True)
    ap.add_argument("--for", dest="for_sec", type=float, required=True)
    ap.add_argument("--start", required=True)
    ap.add_argument("--end", required=True)
    ap.add_argument("--step", type=float, default=5)
    ap.add_argument("--label", default="name")
    ap.add_argument("--prom", default=PROM, help="Prometheus base URL (기본 http://127.0.0.1:9090)")
    ap.add_argument("--out")
    a = ap.parse_args()
    PROM = a.prom
    start, end = ts(a.start), ts(a.end)
    series = query_range(a.expr, start - a.for_sec - a.step, end, a.step)
    report = {"expr": " ".join(a.expr.split()), "for_sec": a.for_sec, "step": a.step,
              "window": [iso(start), iso(end)], "series": []}
    for key, pts in series.items():
        m = json.loads(key)
        eps = replay(pts, start, end, a.step, a.for_sec)
        fired = [e for e in eps if e["fired_in_window"]]
        report["series"].append({"metric": m, "episodes": eps, "fired_count": len(fired),
                                 "firing_sec_total": sum(e["firing_sec_in_window"] for e in fired)})
    tot_n = sum(s["fired_count"] for s in report["series"])
    tot_s = sum(s["firing_sec_total"] for s in report["series"])
    report["total"] = {"fired_count": tot_n, "firing_sec": tot_s}
    print(f"expr: {report['expr']}\nfor={a.for_sec}s step={a.step}s window {report['window'][0]} ~ {report['window'][1]}")
    print(f"series with any true: {len(report['series'])}  -> fired {tot_n} times, {tot_s:.0f} s total")
    for s in report["series"]:
        lbl = s["metric"].get(a.label) or s["metric"].get("id") or json.dumps(s["metric"])
        print(f"  [{lbl}] fired={s['fired_count']} firing_sec={s['firing_sec_total']:.0f} episodes={len(s['episodes'])}")
        for e in s["episodes"][:20]:
            print(f"     active {e['activeAt']} -> last_true {e['last_true']}  pending {e['pending_sec']:.0f}s  "
                  f"firing_start {e['firing_start']}  firing_in_window {e['firing_sec_in_window']:.0f}s  peak {e['peak']:.3f}")
        if len(s["episodes"]) > 20:
            print(f"     ... {len(s['episodes']) - 20} more")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
