"""
scenarios/common/verifier.py
─────────────────────────────
시나리오 실행 결과를 자동으로 검증하는 공통 모듈.

Chaos Engineering 5단계를 코드로 자동화:
  1. Steady State 확인  → Prometheus 쿼리로 현재 메트릭 정상인지 체크
  2. Hypothesis 출력    → 터미널에 가설 표시
  3. 시나리오 실행      → 기존 공격 코드 (외부에서 호출)
  4. 측정              → Prometheus/AlertManager 반복 조회 → MTTD 자동 측정
  5. 결과 반영         → 성공/실패 + MTTD를 anomaly_log.json에 기록

사용법:
    from common.verifier import ScenarioVerifier

    verifier = ScenarioVerifier(
        scenario_name="cpu_stress",
        alert_name="HighCpuUsage",
        hypothesis="cpu_stress 실행 2분 내 HighCpuUsage FIRING",
    )
    verifier.check_steady_state()
    verifier.print_hypothesis()

    # ... 공격 코드 실행 ...

    result = verifier.verify(timeout=120)
    verifier.log_result(result)
"""

import http.client
import json
import os
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from dataclasses import dataclass, field


# ── 설정 ───────────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "logs", "anomaly_log.json"))

PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://localhost:9090")
ALERTMANAGER_URL = os.getenv("ALERTMANAGER_URL", "http://localhost:9093")
LOKI_URL = os.getenv("LOKI_URL", "http://localhost:3100")


# ── 결과 데이터 ────────────────────────────────────────────────────────────────
@dataclass
class VerifyResult:
    """검증 결과를 담는 데이터 클래스"""
    success: bool
    alert_name: str
    scenario_name: str
    mttd_seconds: float | None = None       # Alert 발화까지 걸린 시간
    mttr_seconds: float | None = None       # LLM 분석 완료까지 걸린 시간 (향후 확장)
    mtta_seconds: float | None = None
    slack_notified: bool = False
    steady_state_ok: bool = True
    failure_reason: str = ""
    actual_value: float | None = None       # 실패 시 실제 메트릭 값
    threshold: float | None = None          # 실패 시 임계값
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


# ── 메인 클래스 ────────────────────────────────────────────────────────────────
class ScenarioVerifier:
    """
    시나리오 검증기.

    Parameters:
        scenario_name: 시나리오 이름 (e.g. "cpu_stress")
        alert_name: 발화 기대하는 Alert 이름 (e.g. "HighCpuUsage")
        hypothesis: 가설 문자열
        steady_state_query: Prometheus 쿼리 (정상 상태 확인용, 선택)
        steady_state_threshold: 정상 상태 메트릭 상한값 (선택)
    """

    def __init__(
        self,
        scenario_name: str,
        alert_name: str,
        hypothesis: str,
        steady_state_query: str = "",
        steady_state_threshold: float = 0.0,
    ):
        self.scenario_name = scenario_name
        self.alert_name = alert_name
        self.hypothesis = hypothesis
        self.steady_state_query = steady_state_query
        self.steady_state_threshold = steady_state_threshold
        self._start_time: float = 0.0

    # ── 1단계: Steady State 확인 ───────────────────────────────────────────
    def check_steady_state(self) -> bool:
        """
        Prometheus에 쿼리해서 현재 메트릭이 정상 범위인지 확인.
        steady_state_query가 없으면 건너뜀.
        """
        print(f"\n{'='*60}")
        print(f"[1/5] Steady State 확인")
        print(f"{'='*60}")

        if not self.steady_state_query:
            print(f"  → 쿼리 미설정, 건너뜀")
            return True

        try:
            value = self._query_prometheus_instant(self.steady_state_query)
            if value is not None:
                is_normal = value < self.steady_state_threshold
                status = "정상 ✅" if is_normal else "비정상 ⚠️"
                print(f"  → 현재 값: {value:.4f} / 임계값: {self.steady_state_threshold}")
                print(f"  → 상태: {status}")
                if not is_normal:
                    print(f"  → 경고: 이미 메트릭이 높은 상태. 이전 시나리오 잔여 효과일 수 있음")
                return is_normal
            else:
                print(f"  → 메트릭 데이터 없음 (컨테이너 미실행 가능)")
                return True
        except Exception as e:
            print(f"  → Prometheus 조회 실패: {e}")
            return True

    # ── 2단계: Hypothesis 출력 ─────────────────────────────────────────────
    def print_hypothesis(self):
        """가설과 성공 기준을 터미널에 출력"""
        print(f"\n{'='*60}")
        print(f"[2/5] Hypothesis")
        print(f"{'='*60}")
        print(f"  시나리오: {self.scenario_name}")
        print(f"  목표 Alert: {self.alert_name}")
        print(f"  가설: {self.hypothesis}")
        print(f"  성공 기준: MTTD < 2분, Alert FIRING 확인")
        print(f"{'='*60}\n")

    # ── 3단계: 타이머 시작 (시나리오 실행 전 호출) ─────────────────────────
    def start_timer(self):
        """시나리오 실행 시작 시간 기록"""
        self._start_time = time.time()
        print(f"[3/5] 시나리오 실행 시작 (타이머 시작)")

    # ── 4단계: Alert 발화 확인 + MTTD 측정 ────────────────────────────────
    def verify(self, timeout: int = 120, poll_interval: int = 5) -> VerifyResult:
        """
        Prometheus를 반복 조회해서 Alert 발화 여부 확인.
        timeout 초 내에 FIRING되면 성공, 아니면 실패.

        Parameters:
            timeout: 최대 대기 시간 (초)
            poll_interval: 조회 간격 (초)

        Returns:
            VerifyResult 객체
        """
        if self._start_time == 0:
            self._start_time = time.time()

        print(f"\n{'='*60}")
        print(f"[4/5] Alert 발화 확인 (최대 {timeout}초 대기)")
        print(f"{'='*60}")

        deadline = self._start_time + timeout
        check_count = 0

        while time.time() < deadline:
            check_count += 1
            remaining = int(deadline - time.time())
            print(f"  → 확인 #{check_count} (남은 시간: {remaining}초)", end="")

            fired = self._check_alert_firing()
            if fired:
                mttd = time.time() - self._start_time
                print(f" → FIRING 확인! ✅")
                print(f"\n  ┌─────────────────────────────────┐")
                print(f"  │  [SUCCESS] {self.alert_name}")
                print(f"  │  MTTD: {mttd:.1f}초")
                print(f"  └─────────────────────────────────┘")
                return VerifyResult(
                    success=True,
                    alert_name=self.alert_name,
                    scenario_name=self.scenario_name,
                    mttd_seconds=round(mttd, 1),
                )

            print(f" → 대기 중...")
            time.sleep(poll_interval)

        # 타임아웃 — 실패
        print(f"\n  ┌─────────────────────────────────┐")
        print(f"  │  [FAIL] {timeout}초 내 Alert 미발화")
        print(f"  └─────────────────────────────────┘")

        # 실패 원인 자동 진단
        failure_reason, actual_value = self._diagnose_failure()

        return VerifyResult(
            success=False,
            alert_name=self.alert_name,
            scenario_name=self.scenario_name,
            failure_reason=failure_reason,
            actual_value=actual_value,
        )

    # ── 5단계: 결과 기록 ──────────────────────────────────────────────────
    def log_result(self, result: VerifyResult):
        """검증 결과를 anomaly_log.json에 기록하고 터미널에 최종 요약 출력"""
        print(f"\n{'='*60}")
        print(f"[5/5] 결과 기록")
        print(f"{'='*60}")

        entry = {
            "scenario": result.scenario_name,
            "alert_name": result.alert_name,
            "success": result.success,
            "mttd_seconds": result.mttd_seconds,
            "mtta_seconds": result.mtta_seconds,
            "slack_notified": result.slack_notified,
            "failure_reason": result.failure_reason,
            "timestamp": result.timestamp,
            "category": "verification",
        }

        # anomaly_log.json에 추가
        try:
            records = []
            if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > 0:
                with open(LOG_PATH, "r", encoding="utf-8") as f:
                    records = json.load(f)
            records.append(entry)
            os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
            with open(LOG_PATH, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2, ensure_ascii=False)
            print(f"  → anomaly_log.json 기록 완료")
        except Exception as e:
            print(f"  → 로그 기록 실패: {e}")

        # 최종 요약
        print(f"\n{'='*60}")
        print(f"  최종 결과 요약")
        print(f"{'='*60}")
        print(f"  시나리오:    {result.scenario_name}")
        print(f"  목표 Alert:  {result.alert_name}")
        if result.success:
            print(f"  결과:        SUCCESS ✅")
            print(f"  MTTD:        {result.mttd_seconds}초")
            if result.mtta_seconds is not None:
                print(f"  MTTA:        {result.mtta_seconds}초")
                print(f"  Slack:       {'전송 완료 ✅' if result.slack_notified else '미전송 ❌'}")
        else:
            print(f"  결과:        FAIL ❌")
            print(f"  실패 원인:   {result.failure_reason}")
            if result.actual_value is not None:
                print(f"  실제 값:     {result.actual_value}")
        print(f"{'='*60}\n")

    # ── repeat_interval 사전 체크 ─────────────────────────────────────────
    def check_repeat_interval(self) -> bool:
        """
        AlertManager에 동일 Alert이 이미 active인지 확인.
        이미 발화 중이면 repeat_interval 때문에 재전송이 안 될 수 있으므로 경고.
        """
        try:
            url = f"{ALERTMANAGER_URL}/api/v2/alerts"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            resp = urllib.request.urlopen(req, timeout=5)
            alerts = json.loads(resp.read().decode())
            active = [a for a in alerts
                      if a.get("labels", {}).get("alertname") == self.alert_name
                      and a.get("status", {}).get("state") == "active"]
            if active:
                print(f"  ⚠️  경고: {self.alert_name}이 이미 AlertManager에 active 상태")
                print(f"  → repeat_interval 때문에 Pipeline에 재전송이 안 될 수 있음")
                print(f"  → alertmanager를 재시작하거나 잠시 기다린 후 실행하세요")
                return False
            return True
        except Exception:
            return True  # 확인 실패해도 진행

    # ── 내부 유틸 ──────────────────────────────────────────────────────────
    def _check_alert_firing(self) -> bool:
        """Prometheus API로 특정 Alert이 FIRING 상태인지 확인"""
        try:
            url = f"{PROMETHEUS_URL}/api/v1/alerts"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            resp = urllib.request.urlopen(req, timeout=5)
            data = json.loads(resp.read().decode())
            alerts = data.get("data", {}).get("alerts", [])
            for alert in alerts:
                if (alert.get("labels", {}).get("alertname") == self.alert_name
                        and alert.get("state") == "firing"):
                    return True
            return False
        except Exception:
            return False

    def _query_prometheus_instant(self, query: str) -> float | None:
        """Prometheus instant query 실행 후 첫 번째 값 반환"""
        try:
            params = urllib.parse.urlencode({"query": query})
            url = f"{PROMETHEUS_URL}/api/v1/query?{params}"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            resp = urllib.request.urlopen(req, timeout=5)
            data = json.loads(resp.read().decode())
            results = data.get("data", {}).get("result", [])
            if results:
                return float(results[0]["value"][1])
            return None
        except Exception:
            return None

    def _diagnose_failure(self) -> tuple[str, float | None]:
        """Alert 미발화 시 자동 원인 진단"""
        # 1. AlertManager에 이미 active인지 확인
        try:
            url = f"{ALERTMANAGER_URL}/api/v2/alerts"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            resp = urllib.request.urlopen(req, timeout=5)
            alerts = json.loads(resp.read().decode())
            active = [a for a in alerts
                      if a.get("labels", {}).get("alertname") == self.alert_name]
            if active:
                return "Alert이 AlertManager에 존재하지만 Prometheus에서 FIRING 아님 (repeat_interval 문제 가능)", None
        except Exception:
            pass

        # 2. Prometheus에서 PENDING인지 확인
        try:
            url = f"{PROMETHEUS_URL}/api/v1/alerts"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            resp = urllib.request.urlopen(req, timeout=5)
            data = json.loads(resp.read().decode())
            alerts = data.get("data", {}).get("alerts", [])
            for alert in alerts:
                if alert.get("labels", {}).get("alertname") == self.alert_name:
                    state = alert.get("state", "")
                    if state == "pending":
                        return f"Alert이 PENDING 상태 (for 조건 미충족 — 지속 시간 부족)", None
        except Exception:
            pass

        # 3. 메트릭 자체가 임계값에 못 미치는지 확인
        if self.steady_state_query:
            value = self._query_prometheus_instant(self.steady_state_query)
            if value is not None:
                return f"메트릭 값({value:.4f})이 임계값({self.steady_state_threshold})에 미달", value

        return "원인 미상 — Prometheus 쿼리 확인 필요", None
    
    def check_l7_health(self, host: str, port: int, path: str = "/health") -> bool:
        """실제 서비스 엔드포인트가 HTTP 200을 반환하는지 확인"""
        try:
            conn = http.client.HTTPConnection(host, port, timeout=3)
            conn.request("GET", path)
            response = conn.getresponse()
            return response.status == 200
        except Exception:
            return False

    # [추가] 4단계-B: MTTR(복구) 검증 및 측정
    def verify_recovery(self, target_host: str, target_port: int, timeout: int = 300) -> float:
        """
        조치 실행 후 알람이 사라지고 L7이 정상화될 때까지 대기.
        Returns: mttr_seconds (복구 소요 시간)
        """
        recovery_start = time.time()
        deadline = recovery_start + timeout
        
        print(f"\n[4-B] 복구 확인 및 MTTR 측정 시작")
        
        while time.time() < deadline:
            # 1. Prometheus 알람 상태 확인 (FIRING이 아니어야 함)
            is_firing = self._check_alert_firing()
            # 2. L7 가용성 확인
            is_healthy = self.check_l7_health(target_host, target_port)
            
            if not is_firing and is_healthy:
                mttr = time.time() - self._start_time  # 시나리오 시작 시점부터의 총 복구 시간
                print(f"  → 복구 완료 확인! ✅ (MTTR: {mttr:.1f}초)")
                return round(mttr, 1)
            
            print(f"  → 복구 대기 중... (Alert Firing: {is_firing}, L7 Healthy: {is_healthy})")
            time.sleep(5)
            
        print(f"  → 복구 확인 타임아웃 ❌")
        return -1.0

    def verify_mtta(self, timeout: int = 180, poll_interval: int = 5) -> float | None:
        """Loki 폴링으로 Slack 전송 완료까지 걸린 시간 측정"""
        print(f"\n{'='*60}")
        print(f"[4-B] MTTA 측정 (Slack 알림까지, 최대 {timeout}초)")
        print(f"{'='*60}")
        deadline = time.time() + timeout
        check_count = 0
        while time.time() < deadline:
            check_count += 1
            remaining = int(deadline - time.time())
            print(f"  → 확인 #{check_count} (남은 시간: {remaining}초)", end="")
            ts = self._query_loki_slack_sent()
            if ts is not None:
                mtta = ts - self._start_time
                print(f" → Slack 알림 확인! ✅")
                print(f"\n  ┌─────────────────────────────────┐")
                print(f"  │  MTTA: {mtta:.1f}초")
                print(f"  └─────────────────────────────────┘")
                return round(mtta, 1)
            print(f" → 대기 중...")
            time.sleep(poll_interval)
        print(f"  → MTTA 측정 타임아웃 ❌")
        return None

    def _query_loki_slack_sent(self) -> float | None:
        """Loki에서 aiops-llm job 로그 폴링. _start_time 이후 alert_name 매칭 + confidence > 0 확인."""
        try:
            start_ns = int(self._start_time * 1_000_000_000)
            end_ns = int(time.time() * 1_000_000_000)
            query = '{job="aiops-llm"}'
            params = urllib.parse.urlencode({
                "query": query,
                "start": start_ns,
                "end": end_ns,
                "limit": 50,
                "direction": "forward",
            })
            url = f"{LOKI_URL}/loki/api/v1/query_range?{params}"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            resp = urllib.request.urlopen(req, timeout=5)
            data = json.loads(resp.read().decode())
            streams = data.get("data", {}).get("result", [])
            for stream in streams:
                labels = stream.get("stream", {})
                if labels.get("alert") != self.alert_name:
                    continue
                for ts_ns, line in stream.get("values", []):
                    entry = json.loads(line)
                    if entry.get("result", {}).get("confidence", 0) > 0:
                        return int(ts_ns) / 1_000_000_000
            return None
        except Exception:
            return None

    def verify_loki(self, log_query: str, keyword: str, timeout: int = 180, poll_interval: int = 5) -> float | None:
        """
        Loki 로그 폴링으로 특정 키워드가 포함된 로그가 나타날 때까지 대기.
        _start_time 이후 로그만 확인.
        반환: 로그 timestamp (epoch float) or None
        """
        print(f"\n{'='*60}")
        print(f"[4-B] Loki 탐지 대기 (키워드: '{keyword}', 최대 {timeout}초)")
        print(f"{'='*60}")

        deadline = time.time() + timeout
        check_count = 0

        while time.time() < deadline:
            check_count += 1
            remaining = int(deadline - time.time())
            print(f"  → 확인 #{check_count} (남은 시간: {remaining}초)", end="")

            ts = self._query_loki_keyword(log_query, keyword)
            if ts is not None:
                mttd = ts - self._start_time
                print(f" → 탐지! ✅")
                print(f"\n  ┌─────────────────────────────────┐")
                print(f"  │  MTTD (Loki): {mttd:.1f}초")
                print(f"  └─────────────────────────────────┘")
                return round(mttd, 1)

            print(f" → 대기 중...")
            time.sleep(poll_interval)

        print(f"  → Loki 탐지 타임아웃 ❌")
        return None

    def _query_loki_keyword(self, log_query: str, keyword: str) -> float | None:
        """
        Loki에서 log_query로 조회 후 keyword가 포함된 로그 확인.
        _start_time 이후 로그만 필터링.
        반환: 로그 timestamp (epoch float) or None
        """
        try:
            start_ns = int(self._start_time * 1_000_000_000)
            end_ns = int(time.time() * 1_000_000_000)
            params = urllib.parse.urlencode({
                "query": log_query,
                "start": start_ns,
                "end": end_ns,
                "limit": 100,
                "direction": "forward",
            })
            url = f"{LOKI_URL}/loki/api/v1/query_range?{params}"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            resp = urllib.request.urlopen(req, timeout=5)
            data = json.loads(resp.read().decode())

            streams = data.get("data", {}).get("result", [])
            for stream in streams:
                for ts_ns, line in stream.get("values", []):
                    if keyword.lower() in line.lower():
                        return int(ts_ns) / 1_000_000_000
            return None
        except Exception:
            return None
