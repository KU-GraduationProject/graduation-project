"""
수집된 메트릭·로그를 LLM이 읽을 수 있는 구조화된 프롬프트로 조립.
system 프롬프트는 JSON 출력 형식을 강제하고,
user 프롬프트는 실제 이상 데이터를 담는다.
"""
import json

SYSTEM_PROMPT = """You are an AIOps engineer. Analyze Docker container anomaly data and return JSON only. Always respond in English regardless of the input language.

SCHEMA (all fields required):
{
  "root_cause": "<2 sentences>",
  "action_type": "<RESTART|ISOLATE|PAUSE|THROTTLE|NOTIFY|NONE>",
  "action_targets": ["<container name from ALERT>"],
  "action_description": "<one sentence>",
  "threat_level": "<low|medium|high|critical>",
  "action_risk": "<low|medium|high>",
  "evidence": ["<metric observation>", ...],
  "confidence": <0.0-1.0>
}

RULES:
- action_type: RESTART=CPU spike/memory leak (service down), ISOLATE=active network attack/data exfil, PAUSE=container compromise requiring forensic preservation, THROTTLE=transient CPU/memory pressure with service still alive, NOTIFY=ambiguous/needs human review, NONE=false positive or already recovered
- action_risk: low=NOTIFY/NONE only, medium=THROTTLE/SCALE/config, high=RESTART/ISOLATE/PAUSE
- action_targets: MUST match Container field in ALERT. Always an array.
- evidence: 3-5 numeric values from metrics.

EXAMPLES (few-shot):

# Case 1 – Full CPU spike, service unresponsive → RESTART
INPUT: HighCpuUsage on leafy-backend, cpu_usage latest=4.93 peak=4.97, HTTP 503 errors in logs
OUTPUT: {"root_cause":"leafy-backend is consuming near-maximum CPU across all cores causing service failure. Stress load saturated the CPU leaving no capacity for request processing.","action_type":"RESTART","action_targets":["leafy-backend"],"action_description":"Restart container to clear runaway CPU process and restore service.","threat_level":"high","action_risk":"high","evidence":["cpu_usage: latest=4.93, peak=4.97","http_errors: 503 in logs","cpu_utilization sustained >95% for 5 min"],"confidence":0.88}

# Case 2 – Transient CPU spike, service still alive → THROTTLE
INPUT: HighCpuUsage on leafy-backend, cpu_usage latest=2.10 peak=2.45, HTTP 200 responses still present, spike duration <2 min
OUTPUT: {"root_cause":"leafy-backend experienced a transient CPU spike likely from a burst job, but the service remained responsive throughout. Full restart is unnecessary as the process is still functioning correctly.","action_type":"THROTTLE","action_targets":["leafy-backend"],"action_description":"Apply CPU quota limit to prevent recurrence while service stays alive.","threat_level":"medium","action_risk":"low","evidence":["cpu_usage: latest=2.10, peak=2.45","service still returning HTTP 200","spike duration under 2 minutes","no OOM or crash logs"],"confidence":0.82}

# Case 3 – Suspicious outbound C2 + credential access → PAUSE
INPUT: SuspiciousProcessExec on leafy-backend, logs contain suspicious_outbound curl to external IP, env variable accessed, /proc scanning detected
OUTPUT: {"root_cause":"leafy-backend shows active compromise indicators: outbound C2 connection attempt, environment variable harvesting, and internal process reconnaissance. This matches post-breach attacker behavior requiring forensic preservation.","action_type":"PAUSE","action_targets":["leafy-backend"],"action_description":"Pause container to freeze attacker activity and preserve forensic state for investigation.","threat_level":"critical","action_risk":"high","evidence":["suspicious_outbound keyword in logs","curl to external IP detected","env credential access logged","process /proc scanning observed"],"confidence":0.91}

# Case 4 – Alert fired but metrics already normalized → NONE
INPUT: HighCpuUsage on leafy-backend, cpu_usage latest=0.08 peak=2.31 (5 min ago), no errors in recent logs, alert startsAt is 8 minutes ago
OUTPUT: {"root_cause":"The CPU spike that triggered this alert has already resolved. Current CPU usage is normal and no error logs are present, indicating a transient spike that self-recovered without intervention.","action_type":"NONE","action_targets":[],"action_description":"No action required; the anomaly has already recovered.","threat_level":"low","action_risk":"low","evidence":["cpu_usage: current=0.08 (normalized)","peak was 2.31 over 5 min ago","no error or crash logs in recent window","service responding normally"],"confidence":0.90}
"""

MAX_PROMPT_CHARS = 6000  # ← 이 줄 추가

class PromptBuilder:
    def build(self, alert, metrics: dict, logs: list[dict], container_name: str | None = None) -> dict:
        """system + user 프롬프트 딕셔너리 반환"""
        user_content = self._build_user(alert, metrics, logs, container_name)
        return {
            "system": SYSTEM_PROMPT,
            "user":   user_content,
        }

    def _build_user(self, alert, metrics: dict, logs: list[dict], container_name: str | None = None) -> str:
        lines = []

        # 알람 정보
        display_container = container_name or alert.annotations.get("container") or "N/A"
        lines.append("=== ALERT ===")
        lines.append(f"Name     : {alert.labels.alertname}")
        lines.append(f"Severity : {alert.labels.severity or 'unknown'}")
        lines.append(f"Container: {display_container}")
        lines.append(f"Time     : {alert.startsAt}")
        if alert.annotations:
            lines.append(f"Summary  : {alert.annotations.get('summary', '')}")

        # 메트릭 요약 (최근 값 + 최대값)
        lines.append("\n=== METRICS (5-min window) ===")
        for metric_name, series_list in metrics.items():
            if not series_list:
                continue
            for series in series_list[:5]:  # ← 2개 → 5개로 확장
                values = [pt["v"] for pt in series.get("values", []) if pt["v"] is not None]
                if not values:
                    continue
                latest = values[-1]
                peak   = max(values)
                try:
                    lines.append(f"{metric_name}: latest={latest:.4f}, peak={peak:.4f}, samples={len(values)}")
                except (ValueError, OverflowError):
                    lines.append(f"{metric_name}: latest={latest}, peak={peak}, samples={len(values)}")

        # 로그 (최대 50줄, 에러/경고 우선)
        lines.append("\n=== LOGS (5-min window, up to 50 lines) ===")
        error_logs = [l for l in logs if any(kw in l["line"].lower() for kw in ["error", "exception", "fatal", "warn"])]
        error_set  = set(id(l) for l in error_logs)                    # ← O(n²) 성능 문제 수정
        other_logs = [l for l in logs if id(l) not in error_set]       # ← O(n²) 성능 문제 수정
        selected   = error_logs[:30] + other_logs[:20]
        selected.sort(key=lambda x: x["ts"])
        for entry in selected:
            lines.append(f"[{entry['labels'].get('container', '?')}] {entry['line'][:200]}")

        lines.append("\nAnalyze the above data and respond with JSON only.")

        # 프롬프트 길이 제한  ← 추가
        user_content = "\n".join(lines)
        if len(user_content) > MAX_PROMPT_CHARS:
            user_content = user_content[:MAX_PROMPT_CHARS] + "\n...(truncated)"
        return user_content