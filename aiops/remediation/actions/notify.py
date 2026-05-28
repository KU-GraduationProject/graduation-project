"""
Notification — logs to stdout and sends messages to Slack via webhook.
SLACK_WEBHOOK_URL 환경변수가 없으면 로그만 출력하고 Slack 전송은 건너뜀.
"""

import json
import logging
import os
import time
import urllib.request
from datetime import datetime, timezone  # ← 추가

import httpx

logger = logging.getLogger(__name__)

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
LOKI_URL = os.getenv("LOKI_URL", "http://localhost:3100")


def _push_loki_slack_event(
    alert_name: str,
    status: str,
    response_code: int | None,
    response_text: str,
) -> None:
    ts_ns = str(int(time.time() * 1_000_000_000))
    body = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "slack_notification",
        "alert_name": alert_name,
        "slack_status": status,
        "slack_response_code": response_code,
        "slack_response_text": response_text,
    }
    payload = {
        "streams": [{
            "stream": {
                "job": "aiops-slack",
                "alert": alert_name,
                "status": status,
            },
            "values": [[ts_ns, json.dumps(body, ensure_ascii=False)]],
        }]
    }
    try:
        req = urllib.request.Request(
            f"{LOKI_URL}/loki/api/v1/push",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=3).read()
    except Exception:
        pass


class Notifier:
    def _extract_analysis(self, alert: dict, analysis: dict) -> dict:  # ← 공통 로직 분리
        return {
            "alertname":   alert.get("labels", {}).get("alertname", "unknown"),
            "threat_level": analysis.get("threat_level", "unknown"),
            "action": analysis.get("action_description", "N/A"),
            "root_cause":  analysis.get("root_cause", "N/A"),
            "confidence":  analysis.get("confidence", 0.0),
            "evidence":    analysis.get("evidence", []),
            "timestamp":   datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),  # ← timestamp 추가
        }

    async def send_approval_request(self, alert: dict, analysis: dict) -> dict:
        """Log a medium/high-risk action request that requires manual approval."""
        data = self._extract_analysis(alert, analysis)  # ← 공통 로직 사용

        logger.warning(
            "[APPROVAL REQUIRED] Remediation action pending manual review:\n"
            f"  Alert      : {data['alertname']}\n"
            f"  Threat     : {data['threat_level']}\n"
            f"  Root cause : {data['root_cause']}\n"
            f"  Action     : {data['action']}\n"
            f"  Confidence : {data['confidence']:.2f}\n"
            f"  Evidence   : {json.dumps(data['evidence'], ensure_ascii=False)}"
        )

        return await self._send_slack(data["alertname"], {
            "blocks": [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f":rotating_light: *[APPROVAL REQUIRED]* `{data['alertname']}`"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*발생 시각*\n{data['timestamp']}"},
                        {"type": "mrkdwn", "text": f"*Threat Level*\n{data['threat_level']}"},
                        {"type": "mrkdwn", "text": f"*Confidence*\n{data['confidence']:.2f}"},
                        {"type": "mrkdwn", "text": f"*Root Cause*\n{data['root_cause']}"},
                        {"type": "mrkdwn", "text": f"*Action*\n{data['action']}"},
                        {"type": "mrkdwn", "text": f"*Evidence*\n" + "\n".join(f"• {e}" for e in data['evidence'])},
                    ]
                }
            ]
        })

    async def send_alert_only(self, alert: dict, analysis: dict) -> dict:
        """Log a medium-risk action with low threat level — notify only, no action taken."""
        data = self._extract_analysis(alert, analysis)  # ← 공통 로직 사용

        logger.info(
            "[ALERT ONLY] Medium-risk action skipped due to low threat level:\n"
            f"  Alert      : {data['alertname']}\n"
            f"  Threat     : {data['threat_level']}\n"
            f"  Root cause : {data['root_cause']}\n"
            f"  Confidence : {data['confidence']:.2f}\n"
            f"  Evidence   : {json.dumps(data['evidence'], ensure_ascii=False)}"
        )

        return await self._send_slack(data["alertname"], {
            "blocks": [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f":warning: *[ALERT ONLY]* `{data['alertname']}`"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*발생 시각*\n{data['timestamp']}"},
                        {"type": "mrkdwn", "text": f"*Threat Level*\n{data['threat_level']}"},
                        {"type": "mrkdwn", "text": f"*Confidence*\n{data['confidence']:.2f}"},
                        {"type": "mrkdwn", "text": f"*Root Cause*\n{data['root_cause']}"},
                        {"type": "mrkdwn", "text": f"*Evidence*\n" + "\n".join(f"• {e}" for e in data['evidence'])},
                    ]
                }
            ]
        })

    async def _send_slack(self, alert_name: str, payload: dict) -> dict:
        """SLACK_WEBHOOK_URL이 설정된 경우 Slack webhook dispatch 결과를 반환."""
        dispatched_at = datetime.utcnow().isoformat() + "Z"
        if not SLACK_WEBHOOK_URL:
            logger.debug("[Notifier] SLACK_WEBHOOK_URL not set, skipping Slack notification")
            return {
                "sent": False,
                "status": "SKIPPED",
                "response_code": None,
                "response_text": "SLACK_WEBHOOK_URL not set",
                "dispatched_at": dispatched_at,
            }

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(SLACK_WEBHOOK_URL, json=payload)
                response_text = response.text.strip()
                sent = response.status_code == 200 and response_text.lower() == "ok"
                if sent:
                    logger.info("[Notifier] Slack webhook delivered")
                    status = "SUCCESS"
                else:
                    logger.error(
                        "[Notifier] Slack webhook failed: "
                        f"code={response.status_code}, text={response_text!r}"
                    )
                    status = "FAILED"
                _push_loki_slack_event(alert_name, status, response.status_code, response_text)
                return {
                    "sent": sent,
                    "status": status,
                    "response_code": response.status_code,
                    "response_text": response_text,
                    "dispatched_at": dispatched_at,
                }
        except httpx.HTTPError as e:
            logger.error(f"[Notifier] Failed to send Slack notification: {e}")
            _push_loki_slack_event(alert_name, "FAILED", None, str(e))
            return {
                "sent": False,
                "status": "FAILED",
                "response_code": None,
                "response_text": str(e),
                "dispatched_at": dispatched_at,
            }
