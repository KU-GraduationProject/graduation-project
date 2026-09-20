#!/usr/bin/env python3
"""
scenarios/batch_runner.py
─────────────────────────
시나리오 반복 실행 + MTTD/MTTA 자동 집계 러너.

팀원 우선순위표 기반으로 각 시나리오를 지정 횟수만큼 반복 실행하고,
anomaly_log.json에 기록된 결과를 읽어 평균 MTTD/MTTA·성공률을 집계한다.

run.py와 동일한 호출 방식(module의 main() import)을 사용하되,
시각화 연출 없이 반복 실행·정리·집계에 집중한다.

사용법:
  python batch_runner.py                  # 전체 플랜 실행
  python batch_runner.py escape exfil     # 특정 시나리오만
  python batch_runner.py --dry-run        # 실행 계획만 출력

결과:
  scenarios/logs/batch_results_<타임스탬프>.csv  — 회차별 raw
  scenarios/logs/batch_summary_<타임스탬프>.csv  — 시나리오별 집계
"""

import csv
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.parse
from datetime import datetime

# ── 경로 ──────────────────────────────────────────────────────────────────────
SCENARIOS_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR       = os.path.join(SCENARIOS_DIR, "logs")
ANOMALY_LOG   = os.path.join(LOG_DIR, "anomaly_log.json")

PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://localhost:9090")
DB_CONTAINER   = os.getenv("DB_CONTAINER", "leafy-db")

# ── 실행 플랜 (팀원 우선순위표) ───────────────────────────────────────────────
# mode:
#   "fixed"        — runs회 무조건 실행
#   "until_success"— 성공 target_success회 채울 때까지 (최대 max_attempts회 시도)
PLAN = [
    {
        "key": "escape",
        "module": "category2_security.container_escape_attempt",
        "scenario_names": ["container_escape_attempt"],   # anomaly_log의 scenario 필드
        "mode": "until_success", "target_success": 5, "max_attempts": 10,
        "priority": "🔴 필수",
        "note": "MTTD/MTTA 측정 — 5절 4종 중 누락분",
    },
    {
        "key": "exfil",
        "module": "category2_security.data_exfil",
        "scenario_names": ["data_exfil", "secret_dump"],  # data_exfil은 verifier 미사용 가능성 → 아래 fallback 처리
        "mode": "fixed", "runs": 3,
        "priority": "🔴 필수",
        "note": "사각지대 확인 — alert 미발화 검증",
        "blind_spot": True,   # 결과가 anomaly_log에 안 남을 수 있음
    },
    {
        "key": "memory_leak",
        "module": "category1_infra.memory_leak",
        "scenario_names": ["memory_leak"],
        "mode": "until_success", "target_success": 5, "max_attempts": 10,
        "priority": "🟡 권장",
        "note": "MTTD 보완 — 기존 5/6 실패",
    },
    {
        "key": "oom",
        "module": "category1_infra.container_oom_restart",
        "scenario_names": ["container_oom_restart", "db_oom_restart"],
        "mode": "until_success", "target_success": 5, "max_attempts": 12,
        "priority": "🟡 권장",
        "note": "MTTD 보완 — 기존 7/8 실패",
    },
]


# ── HTTP 유틸 ─────────────────────────────────────────────────────────────────
def _prom_cpu_sum() -> float | None:
    """전체 컨테이너 CPU 합 (HighCpuUsage 판단 쿼리와 동일)."""
    q = 'sum(irate(container_cpu_usage_seconds_total{id=~"/docker/.+",cpu="total"}[30s]))'
    try:
        url = f"{PROMETHEUS_URL}/api/v1/query?" + urllib.parse.urlencode({"query": q})
        r = urllib.request.urlopen(url, timeout=5)
        data = json.loads(r.read().decode())
        result = data.get("data", {}).get("result", [])
        return float(result[0]["value"][1]) if result else None
    except Exception:
        return None


def _active_alerts() -> list[str]:
    """현재 firing/pending 중인 alert 이름 목록."""
    try:
        url = f"{PROMETHEUS_URL}/api/v1/alerts"
        r = urllib.request.urlopen(url, timeout=5)
        data = json.loads(r.read().decode())
        alerts = data.get("data", {}).get("alerts", [])
        return [a.get("labels", {}).get("alertname", "?")
                for a in alerts if a.get("state") in ("firing", "pending")]
    except Exception:
        return []


# ── anomaly_log 읽기 ──────────────────────────────────────────────────────────
def _load_anomaly_log() -> list:
    if os.path.exists(ANOMALY_LOG) and os.path.getsize(ANOMALY_LOG) > 0:
        try:
            with open(ANOMALY_LOG, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def _new_verification_entries(prev_len: int, scenario_names: list[str]) -> list[dict]:
    """
    실행 후 새로 추가된 엔트리 중, verifier가 남긴 검증 결과만 추출.
    verifier.log_result는 category="verification", mttd_seconds 필드를 남긴다.
    """
    records = _load_anomaly_log()
    new = records[prev_len:]
    out = []
    for r in new:
        # verifier 검증 결과만 (scenario 기록용 엔트리 제외)
        if r.get("category") == "verification" and r.get("scenario") in scenario_names:
            out.append(r)
        # fallback: scenario 이름만 맞고 mttd가 있으면 포함
        elif r.get("scenario") in scenario_names and r.get("mttd_seconds") is not None:
            out.append(r)
    return out


# ── 회차 사이 정리 ────────────────────────────────────────────────────────────
def cleanup_between_runs(wait_alert_inactive: bool = True, timeout: int = 90) -> None:
    """이전 회차 잔재 제거: dd 프로세스, abroxu 테이블, alert 가라앉기 대기."""
    # 1. RCE 잔여 dd 강력 정리
    subprocess.run(
        ["docker", "exec", DB_CONTAINER, "sh", "-c",
         "ps aux | grep '[d]d if=/dev/zero' | awk '{print $1}' | xargs -r kill -9"],
        capture_output=True, timeout=15,
    )
    # 2. abroxu 임시 테이블 제거
    subprocess.run(
        ["docker", "exec", DB_CONTAINER, "psql", "-U", "leafy", "-d", "leafy",
         "-c", "DROP TABLE IF EXISTS abroxu;"],
        capture_output=True, timeout=15,
    )

    # 3. Fluentd → Loki 적재 안정화 대기 (이전 회차 로그가 완전히 적재되도록)
    #    적재 자체는 정상이나 회차 간격이 짧으면 start_time 윈도우와 어긋나 타임아웃 발생
    time.sleep(15)

    if not wait_alert_inactive:
        return

    # 4. alert이 가라앉을 때까지 대기 (다음 회차 오염 방지)
    deadline = time.time() + timeout
    while time.time() < deadline:
        active = _active_alerts()
        cpu = _prom_cpu_sum()
        cpu_ok = (cpu is None) or (cpu < 0.5)
        if not active and cpu_ok:
            return
        remaining = int(deadline - time.time())
        cpu_str = f"{cpu*100:.1f}%" if cpu is not None else "N/A"
        print(f"    [정리] alert={active or '없음'} cpu={cpu_str} — 대기 {remaining}s", flush=True)
        time.sleep(5)
    print("    [정리] 타임아웃 — 잔여 alert 있는 채로 진행", flush=True)


# ── 시나리오 1회 실행 ─────────────────────────────────────────────────────────
def run_once(item: dict, run_idx: int) -> dict:
    """시나리오 1회 실행 후 결과 dict 반환."""
    module = item["module"]
    os.makedirs(LOG_DIR, exist_ok=True)
    run_log = os.path.join(LOG_DIR, f"batch_{item['key']}_run{run_idx}.log")

    prev_len = len(_load_anomaly_log())

    script = (
        f"import sys; sys.path.insert(0, {repr(SCENARIOS_DIR)}); "
        f"from {module} import main; main()"
    )

    t0 = time.time()
    status = "completed"
    # 자식 프로세스가 stdout을 UTF-8로 쓰도록 강제 (Windows cp949 이모지 에러 방지)
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    with open(run_log, "w", encoding="utf-8") as lf:
        try:
            subprocess.run(
                [sys.executable, "-c", script],
                stdout=lf, stderr=lf, timeout=600,   # 10분 상한
                env=env,
            )
        except subprocess.TimeoutExpired:
            status = "process_timeout"
        except Exception as e:
            status = f"process_error:{e}"
    elapsed = time.time() - t0

    # 결과 추출
    entries = _new_verification_entries(prev_len, item["scenario_names"])

    if item.get("blind_spot"):
        # 사각지대 시나리오: alert 미발화가 정상. verifier 결과 없을 수 있음
        result = {
            "run": run_idx, "status": status, "elapsed_sec": round(elapsed, 1),
            "success": True,   # 실행 자체 성공 = 사각지대 확인 성공
            "mttd": None, "mtta": None, "alert_fired": bool(entries),
            "failure_reason": "", "log": os.path.relpath(run_log),
        }
    elif entries:
        e = entries[-1]   # 가장 최근 검증 엔트리
        result = {
            "run": run_idx, "status": status, "elapsed_sec": round(elapsed, 1),
            "success": bool(e.get("success")),
            "mttd": e.get("mttd_seconds"), "mtta": e.get("mtta_seconds"),
            "alert_fired": e.get("success"),
            "failure_reason": e.get("failure_reason", ""),
            "log": os.path.relpath(run_log),
        }
    else:
        # 검증 엔트리 못 찾음
        result = {
            "run": run_idx, "status": status, "elapsed_sec": round(elapsed, 1),
            "success": False, "mttd": None, "mtta": None, "alert_fired": False,
            "failure_reason": "anomaly_log에 검증 결과 없음 (verifier 미실행 또는 실패)",
            "log": os.path.relpath(run_log),
        }
    return result


# ── 시나리오 배치 실행 ────────────────────────────────────────────────────────
def run_scenario_batch(item: dict) -> list[dict]:
    print()
    print("=" * 70)
    print(f"  {item['priority']}  {item['key']}  ({item['module']})")
    print(f"  {item['note']}")
    mode = item["mode"]
    if mode == "fixed":
        print(f"  모드: 고정 {item['runs']}회")
    else:
        print(f"  모드: {item['target_success']}회 성공까지 (최대 {item['max_attempts']}회 시도)")
    print("=" * 70)

    results = []

    if mode == "fixed":
        for i in range(1, item["runs"] + 1):
            print(f"\n  ── 회차 {i}/{item['runs']} ──", flush=True)
            cleanup_between_runs()
            r = run_once(item, i)
            results.append(r)
            _print_run_result(r)
    else:  # until_success
        success_count = 0
        attempt = 0
        while success_count < item["target_success"] and attempt < item["max_attempts"]:
            attempt += 1
            print(f"\n  ── 시도 {attempt} (성공 {success_count}/{item['target_success']}) ──", flush=True)
            cleanup_between_runs()
            r = run_once(item, attempt)
            results.append(r)
            _print_run_result(r)
            if r["success"]:
                success_count += 1
        if success_count < item["target_success"]:
            print(f"\n  ⚠ 최대 시도({item['max_attempts']}) 도달 — "
                  f"성공 {success_count}/{item['target_success']}", flush=True)

    return results


def _print_run_result(r: dict) -> None:
    mark = "✅" if r["success"] else "❌"
    mttd = f"{r['mttd']:.1f}s" if r["mttd"] is not None else "—"
    mtta = f"{r['mtta']:.1f}s" if r["mtta"] is not None else "—"
    line = f"    {mark} MTTD={mttd} MTTA={mtta} ({r['elapsed_sec']}s)"
    if not r["success"] and r["failure_reason"]:
        line += f"  사유: {r['failure_reason'][:50]}"
    print(line, flush=True)


# ── 집계 ──────────────────────────────────────────────────────────────────────
def summarize(item: dict, results: list[dict]) -> dict:
    succ = [r for r in results if r["success"]]
    mttds = [r["mttd"] for r in succ if r["mttd"] is not None]
    mttas = [r["mtta"] for r in succ if r["mtta"] is not None]

    def _avg(xs):
        return round(sum(xs) / len(xs), 1) if xs else None

    return {
        "scenario": item["key"],
        "module": item["module"],
        "total_runs": len(results),
        "success": len(succ),
        "success_rate": f"{len(succ)}/{len(results)}",
        "avg_mttd": _avg(mttds),
        "mttd_samples": ", ".join(f"{m:.1f}" for m in mttds) if mttds else "—",
        "avg_mtta": _avg(mttas),
        "mtta_samples": ", ".join(f"{m:.1f}" for m in mttas) if mttas else "—",
    }


def write_csvs(all_raw: list[dict], all_summary: list[dict]) -> tuple[str, str]:
    os.makedirs(LOG_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    raw_path = os.path.join(LOG_DIR, f"batch_results_{ts}.csv")
    sum_path = os.path.join(LOG_DIR, f"batch_summary_{ts}.csv")

    if all_raw:
        with open(raw_path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=list(all_raw[0].keys()))
            w.writeheader()
            w.writerows(all_raw)
    if all_summary:
        with open(sum_path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=list(all_summary[0].keys()))
            w.writeheader()
            w.writerows(all_summary)
    return raw_path, sum_path


def print_final_summary(summaries: list[dict]) -> None:
    print("\n")
    print("=" * 70)
    print("  최종 집계")
    print("=" * 70)
    for s in summaries:
        print(f"\n  [{s['scenario']}]  성공률 {s['success_rate']}")
        print(f"    평균 MTTD: {s['avg_mttd']}s   (samples: {s['mttd_samples']})")
        print(f"    평균 MTTA: {s['avg_mtta']}s   (samples: {s['mtta_samples']})")


# ── 진입점 ────────────────────────────────────────────────────────────────────
def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    dry_run = "--dry-run" in sys.argv

    # 시나리오 필터
    plan = PLAN if not args else [p for p in PLAN if p["key"] in args]
    if not plan:
        print(f"매칭되는 시나리오 없음. 가능한 키: {[p['key'] for p in PLAN]}")
        return

    if dry_run:
        print("[DRY RUN] 실행 계획:")
        for p in plan:
            mode = (f"고정 {p['runs']}회" if p["mode"] == "fixed"
                    else f"{p['target_success']}회 성공까지(최대 {p['max_attempts']})")
            print(f"  {p['priority']}  {p['key']:<14s} {mode}  — {p['note']}")
        return

    print(f"\n배치 실행 시작 — 대상 {len(plan)}개 시나리오")
    print(f"결과 기록: {LOG_DIR}")

    all_raw = []
    all_summary = []
    for item in plan:
        results = run_scenario_batch(item)
        for r in results:
            row = {"scenario": item["key"], **r}
            all_raw.append(row)
        all_summary.append(summarize(item, results))

    raw_path, sum_path = write_csvs(all_raw, all_summary)
    print_final_summary(all_summary)

    print(f"\n  raw CSV     : {os.path.relpath(raw_path)}")
    print(f"  summary CSV : {os.path.relpath(sum_path)}")
    print("\n완료.\n")


if __name__ == "__main__":
    main()