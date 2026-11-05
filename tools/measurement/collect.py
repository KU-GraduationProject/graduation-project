"""측정 구간 집계. 결과를 <run dir>/summary.json 에 쓰고 사람이 읽을 요약을 출력한다.

    python -I collect.py --dir <run dir> --start 2026-10-28T23:52:56.555Z --end 2026-10-29T01:52:56.555Z

- 경보: alerts.jsonl (Alertmanager 15 s 조회). 같은 fingerprint 가 연속으로 보이면 1회 발화로 센다
- Prometheus ALERTS: pending 까지 포함한 룰 상태 이력 (15 s 간격)
- 여유(headroom): 각 룰의 비교식 왼쪽 값을 측정 구간 동안 조회해 최댓값과 임계값을 나란히 둔다
- 수집 경로 확인: Loki 에 들어온 frontend 액세스 로그 수 vs 생성기 요청 수, Prometheus 타깃 up
- 트래픽: requests.jsonl
"""
import argparse
import collections
import json
import os
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

PROM, LOKI = "http://127.0.0.1:9090", "http://127.0.0.1:3100"
POLL = 15

# (룰, 왼쪽 식, 임계값, 연산자) — rules_snapshot 의 식에서 비교 부분만 떼어낸 것
PROM_HEADROOM = [
    ("HighCpuUsage", 'sum by (name) (irate(container_cpu_usage_seconds_total{cpu="total",id=~"/docker/.+"}[30s]) '
                     '* on (id) group_left (name) container_name_info) and on (name) '
                     'container_name_info{name=~"leafy-frontend|leafy-backend|leafy-db|leafy-minio"}', 0.5),
    ("HighMemoryUsage", 'max by (name) ((container_memory_working_set_bytes{id=~"/docker/.+"} / '
                        '(container_spec_memory_limit_bytes{id=~"/docker/.+"} > 0)) * on (id) group_left (name) '
                        'container_name_info)', 0.85),
    ("HighNetworkReceive", 'sum without (interface) (rate(container_network_receive_bytes_total{interface!="lo"}[1m])) '
                           '* on (id) group_left (name) container_name_info', 10_000_000),
    ("HighNetworkReceive(raw, 이름 없는 시리즈 포함)",
     'sum without (interface) (rate(container_network_receive_bytes_total{interface!="lo"}[1m]))', 10_000_000),
    ("HighNginxRequestRate", "rate(nginx_http_requests_total[1m])", 30),
    ("HighPostgresConnections", "pg_stat_activity_count", 40),
    ("ContainerRestarted(changes started_at)",
     'max by (name) (changes(aiops_docker_container_started_at_seconds{name="leafy-backend"}[10m]))', 2),
]
LOKI_HEADROOM = [
    ("UnauthorizedDBAccess", 'sum(count_over_time({service="db"} |= "authentication failed"[2m]))', 3),
    ("SQLInjectionAttempt", 'sum(count_over_time({service="frontend"} |~ "(?i)(union.{0,3}select|or.{0,3}1=1|drop.{0,3}table|sleep\\\\(|extractvalue|information_schema|admin\'--|and.{0,3}1=1)"[2m]))', 5),
    ("HighNginxErrorRate", 'sum(count_over_time({service="frontend", log_format="json"} | json | status>=500[1m]))', 10),
    ("VulnerabilityScanningDetected", 'sum(count_over_time({service="frontend", log_format="json"} | json | status>=400, status<500[1m]))', 50),
    ("PathTraversalAttempt", 'sum(count_over_time({service="frontend"} |~ "(?i)(\\\\.\\\\.\\\\/|\\\\.\\\\.\\\\\\\\|/etc/passwd|\\\\.env|/\\\\.git/)"[2m]))', 0),
    ("SuspiciousProcessExecution", 'sum(count_over_time({service=~"backend|frontend"} |~ "(?i)(wget http|wget -|curl http[^s]|curl -o |nc -|netcat|/bin/bash -i|/bin/sh -i)"[2m]))', 0),
    ("SecretDumpAttempt", 'sum(count_over_time({service="backend"} |= "printenv" |= "[ATTACK]"[2m]))', 0),
    ("SuspiciousProcessExec", 'sum(count_over_time({service="backend"} |~ "suspicious_outbound"[2m]))', 0),
    ("ContainerEscapeAttempt", 'sum(count_over_time({service="backend"} |~ "container_escape_attempt"[2m]))', 0),
    ("UnauthorizedTransferEarly", 'sum by (dst_ip,dst_port)(count_over_time({log_type="network", event_type="connection_threshold", src_service="backend", dst_service!~"db|minio|frontend"} | json | __error__="" | ( dst_ip!="10.210.0.30" or dst_port!=8080 )[5m]))', 0),
    ("UnauthorizedDataTransfer", 'sum by (dst_ip,dst_port)(sum_over_time({log_type="network", event_type="connection", src_service="backend", dst_service!~"db|minio|frontend"} | json | __error__="" | ( dst_ip!="10.210.0.30" or dst_port!=8080 ) | bytes_sent!="" | unwrap bytes_sent[5m]))', 1048576),
]


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def get(url, params):
    with urllib.request.urlopen(url + "?" + urllib.parse.urlencode(params), timeout=120) as r:
        return json.load(r)


def label_of(m):
    return m.get("name") or m.get("dst_ip") and f'{m.get("dst_ip")}:{m.get("dst_port")}' or m.get("id") or m.get("instance") or "-"


def series_max(result):
    out = []
    for s in result:
        vals = [(float(v), float(t)) for t, v in s["values"] if v not in ("NaN", "+Inf")]
        if vals:
            v, t = max(vals)
            out.append((v, t, label_of(s["metric"])))
    return sorted(out, reverse=True)


def alert_episodes(path, start, end):
    eps, open_ = [], {}
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        t = ts(r["poll_ts"])
        if not (start <= t <= end) or not r.get("ok"):
            continue
        seen = set()
        for a in r["alerts"]:
            key = (a["fingerprint"], a["startsAt"])
            seen.add(key)
            if key not in open_:
                open_[key] = {"alertname": a["alertname"], "labels": a["labels"], "startsAt": a["startsAt"],
                              "first": t, "last": t, "states": set()}
            open_[key]["last"] = t
            open_[key]["states"].add(a["state"])
        for key in [k for k in open_ if k not in seen]:
            eps.append(open_.pop(key))
    eps.extend(open_.values())
    for e in eps:
        e["duration_sec"] = (e["last"] - e["first"]).total_seconds() + POLL
        e["states"] = sorted(e["states"])
    return eps


def traffic(path, start, end):
    rows = [r for r in map(json.loads, open(path, encoding="utf-8")) if start <= ts(r["ts"]) <= end]
    st = collections.Counter(r["status"] for r in rows)
    fail = [r for r in rows if r["status"] == 0 or r["status"] >= 500 or (400 <= r["status"] < 500)]
    lat = sorted(r["ms"] for r in rows)
    span = (ts(rows[-1]["ts"]) - ts(rows[0]["ts"])).total_seconds()
    return {
        "total": len(rows), "first": rows[0]["ts"], "last": rows[-1]["ts"], "rps": round(len(rows) / span, 3),
        "status": dict(sorted(st.items())), "fail": len(fail), "fail_rate": round(len(fail) / len(rows), 5),
        "fail_detail": collections.Counter(f'{r["method"]} {r["route"]} {r["status"]} {r["err"]}' for r in fail).most_common(10),
        "routes": collections.Counter(f'{r["method"]} {r["route"]}' for r in rows).most_common(),
        "signups": sum(1 for r in rows if r["route"] == "/api/v1/auth/signup" and r["status"] == 201),
        "uploads": sum(1 for r in rows if r["route"] == "/api/images/upload" and r["status"] == 200),
        "logins": sum(1 for r in rows if r["route"] == "/api/v1/auth/login"),
        "latency_ms": {"p50": lat[len(lat) // 2], "p95": lat[int(len(lat) * .95)], "p99": lat[int(len(lat) * .99)], "max": lat[-1]},
        "max_rps_1min": max(collections.Counter(ts(r["ts"]).replace(second=0, microsecond=0) for r in rows).values()) / 60,
    }


def main():
    global PROM, LOKI
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--start", required=True)
    ap.add_argument("--end", required=True)
    ap.add_argument("--prom", default=PROM, help="Prometheus base URL (기본 http://127.0.0.1:9090)")
    ap.add_argument("--loki", default=LOKI, help="Loki base URL (기본 http://127.0.0.1:3100)")
    ap.add_argument("--authorized-dst-ip", default="10.210.0.30",
                    help="network 룰에서 '인가된' 전송 목적지 IP (이 값이 아니면 비인가로 집계)")
    ap.add_argument("--authorized-dst-port", default="8080",
                    help="network 룰에서 '인가된' 전송 목적지 포트")
    a = ap.parse_args()
    PROM, LOKI = a.prom, a.loki
    start, end = ts(a.start), ts(a.end)
    s_unix, e_unix = start.timestamp(), end.timestamp()
    out = {"window": [a.start, a.end], "hours": (end - start).total_seconds() / 3600}

    eps = alert_episodes(os.path.join(a.dir, "alerts.jsonl"), start, end)
    out["alert_episodes"] = [{**e, "first": e["first"].isoformat(), "last": e["last"].isoformat()} for e in eps]
    out["false_alarms_per_hour"] = len(eps) / out["hours"]

    al = get(f"{PROM}/api/v1/query_range", {"query": "ALERTS", "start": s_unix, "end": e_unix, "step": POLL})
    out["prom_ALERTS"] = [{"metric": s["metric"], "points": len(s["values"]),
                           "first": datetime.fromtimestamp(float(s["values"][0][0])).isoformat(),
                           "last": datetime.fromtimestamp(float(s["values"][-1][0])).isoformat()}
                          for s in al["data"]["result"]]

    out["headroom"] = []
    for name, q, thr in PROM_HEADROOM:
        r = get(f"{PROM}/api/v1/query_range", {"query": q, "start": s_unix, "end": e_unix, "step": POLL})
        top = series_max(r["data"]["result"])[:3]
        out["headroom"].append({"rule": name, "src": "prometheus", "threshold": thr,
                                "top": [(v, datetime.fromtimestamp(t).isoformat(), l) for v, t, l in top]})
    for name, q, thr in LOKI_HEADROOM:
        q = q.replace("10.210.0.30", a.authorized_dst_ip).replace("!=8080", f"!={a.authorized_dst_port}")
        try:
            r = get(f"{LOKI}/loki/api/v1/query_range", {"query": q, "start": int(s_unix * 1e9), "end": int(e_unix * 1e9),
                                                         "step": "60s", "limit": 1000})
            top = series_max(r["data"]["result"])[:3]
            err = None
        except Exception as ex:
            top, err = [], repr(ex)
        out["headroom"].append({"rule": name, "src": "loki", "threshold": thr, "error": err,
                                "top": [(v, datetime.fromtimestamp(t).isoformat(), l) for v, t, l in top]})

    # 수집 경로 확인
    win = f"{int(e_unix - s_unix)}s"
    chk = {}
    for k, q in {"loki_frontend_access_lines": f'sum(count_over_time({{service="frontend", log_format="json"}}[{win}]))',
                 "loki_backend_lines": f'sum(count_over_time({{service="backend"}}[{win}]))',
                 "loki_db_lines": f'sum(count_over_time({{service="db"}}[{win}]))',
                 "loki_network_events": f'sum(count_over_time({{log_type="network"}}[{win}]))'}.items():
        try:
            r = get(f"{LOKI}/loki/api/v1/query", {"query": q, "time": int(e_unix * 1e9)})
            chk[k] = float(r["data"]["result"][0]["value"][1]) if r["data"]["result"] else 0
        except Exception as ex:
            chk[k] = repr(ex)
    r = get(f"{PROM}/api/v1/query", {"query": f"min_over_time(up[{win}])", "time": e_unix})
    chk["prom_targets_min_up"] = {s["metric"].get("job"): s["value"][1] for s in r["data"]["result"]}
    r = get(f"{PROM}/api/v1/query", {"query": f"increase(nginx_http_requests_total[{win}])", "time": e_unix})
    chk["nginx_requests_increase"] = [float(s["value"][1]) for s in r["data"]["result"]]
    r = get(f"{PROM}/api/v1/query", {"query": f'count(count_over_time(container_name_info[{win}]))', "time": e_unix})
    chk["cadvisor_named_containers"] = r["data"]["result"][0]["value"][1] if r["data"]["result"] else 0
    out["pipeline_input_check"] = chk

    out["traffic"] = traffic(os.path.join(a.dir, "requests.jsonl"), start, end)

    with open(os.path.join(a.dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1, default=str)

    print(f"window {a.start} ~ {a.end} ({out['hours']:.2f} h)")
    print(f"alert episodes: {len(eps)}  -> {out['false_alarms_per_hour']:.2f}/h")
    for e in eps:
        print("  ", e["alertname"], label_of(e["labels"]), e["first"], e["duration_sec"], e["states"])
    print(f"prom ALERTS series (pending 포함): {len(out['prom_ALERTS'])}")
    for s in out["prom_ALERTS"]:
        print("  ", s["metric"].get("alertname"), s["metric"].get("alertstate"), label_of(s["metric"]), s["first"], s["points"])
    print("headroom (max in window vs threshold):")
    for h in out["headroom"]:
        t = h["top"][0] if h["top"] else None
        print(f"  [{h['src']}] {h['rule']}: thr={h['threshold']}  max={t[0] if t else 'no data'}  "
              f"at={t[1] if t else ''}  on={t[2] if t else ''}  {h.get('error') or ''}")
        for v, tt, l in h["top"][1:]:
            print(f"        {v} {tt} {l}")
    print("input check:", json.dumps(chk, ensure_ascii=False))
    tr = out["traffic"]
    print(f"traffic: total={tr['total']} rps={tr['rps']} max1m={tr['max_rps_1min']:.2f} status={tr['status']} "
          f"fail={tr['fail']} ({tr['fail_rate']:.3%}) signups={tr['signups']} uploads={tr['uploads']} logins={tr['logins']} "
          f"lat={tr['latency_ms']}")
    for d in tr["fail_detail"]:
        print("   fail:", d)


if __name__ == "__main__":
    main()
