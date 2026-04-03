"""
수집된 메트릭·로그를 LLM이 읽을 수 있는 구조화된 프롬프트로 조립.
system 프롬프트는 JSON 출력 형식을 강제하고,
user 프롬프트는 실제 이상 데이터를 담는다.
"""

import json


SYSTEM_PROMPT = """You are an expert AIOps engineer specializing in Docker container infrastructure analysis.

Your task is to analyze anomaly data from a containerized service and produce a structured Root Cause Analysis (RCA).

You MUST respond ONLY with a valid JSON object matching this exact schema:
{
  "root_cause": "<string: root cause summary in Korean, 2-3 sentences>",
  "action": "<string: recommended remediation command>",
  "threat_level": "<one of: low | medium | high | critical>",
  "action_risk": "<one of: low | high>",
  "evidence": ["<string>", ...],
  "confidence": <float 0.0-1.0>
}

Guidelines:
- threat_level: low=minor degradation, medium=service slowdown, high=service impact, critical=service down
- action_risk: low=no service disruption (e.g. log collection, config reload), high=may disrupt service (e.g. container restart, isolation)
- evidence: list 3-5 specific observations from the provided metrics and logs
- Be concise and precise. No explanation outside the JSON.
"""


class PromptBuilder:
    def build(self, alert, metrics: dict, logs: list[dict]) -> dict:
        """system + user 프롬프트 딕셔너리 반환"""
        user_content = self._build_user(alert, metrics, logs)
        return {
            "system": SYSTEM_PROMPT,
            "user":   user_content,
        }

    def _build_user(self, alert, metrics: dict, logs: list[dict]) -> str:
        lines = []

        # 알람 정보
        lines.append("=== ALERT ===")
        lines.append(f"Name     : {alert.labels.alertname}")
        lines.append(f"Severity : {alert.labels.severity or 'unknown'}")
        lines.append(f"Container: {alert.labels.container or 'N/A'}")
        lines.append(f"Time     : {alert.startsAt}")
        if alert.annotations:
            lines.append(f"Annotations: {json.dumps(alert.annotations, ensure_ascii=False)}")

        # 메트릭 요약 (최근 값 + 최대값)
        lines.append("\n=== METRICS (5-min window) ===")
        for metric_name, series_list in metrics.items():
            if not series_list:
                continue
            for series in series_list[:2]:  # 상위 2개 시리즈만
                values = [pt["v"] for pt in series.get("values", []) if pt["v"] is not None]
                if not values:
                    continue
                latest = values[-1]
                peak   = max(values)
                lines.append(f"{metric_name}: latest={latest:.4f}, peak={peak:.4f}, samples={len(values)}")

        # 로그 (최대 50줄, 에러/경고 우선)
        lines.append("\n=== LOGS (5-min window, up to 50 lines) ===")
        error_logs  = [l for l in logs if any(kw in l["line"].lower() for kw in ["error", "exception", "fatal", "warn"])]
        other_logs  = [l for l in logs if l not in error_logs]
        selected    = error_logs[:30] + other_logs[:20]
        selected.sort(key=lambda x: x["ts"])

        for entry in selected:
            lines.append(f"[{entry['labels'].get('container', '?')}] {entry['line'][:200]}")

        lines.append("\nAnalyze the above data and respond with JSON only.")
        return "\n".join(lines)
