"""
수집된 메트릭·로그를 LLM이 읽을 수 있는 구조화된 프롬프트로 조립.
system 프롬프트는 JSON 출력 형식을 강제하고,
user 프롬프트는 실제 이상 데이터를 담는다.
"""
import json

SYSTEM_PROMPT = """You are an AIOps engineer. Analyze Docker container anomaly data and return JSON only.

SCHEMA (all fields required):
{
  "root_cause": "<2 sentences>",
  "action_type": "<RESTART|ISOLATE|SCALE|NOTIFY|NONE>",
  "action_targets": ["<container name from ALERT>"],
  "action_description": "<one sentence>",
  "threat_level": "<low|medium|high|critical>",
  "action_risk": "<low|medium|high>",
  "evidence": ["<metric observation>", ...],
  "confidence": <0.0-1.0>
}

RULES:
- action_type: RESTART=CPU spike/memory leak, ISOLATE=security breach, SCALE=sustained load, NOTIFY=ambiguous, NONE=false positive
- action_risk: low=NOTIFY only, medium=SCALE/config, high=RESTART/ISOLATE
- action_targets: MUST match Container field in ALERT. Always an array.
- evidence: 3-5 numeric values from metrics.

EXAMPLE OUTPUT:
{"root_cause":"CPU spike detected in leafy-backend due to stress load.","action_type":"RESTART","action_targets":["leafy-backend"],"action_description":"Restart to clear CPU spike.","threat_level":"high","action_risk":"high","evidence":["cpu_usage: 4.93"],"confidence":0.85}
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