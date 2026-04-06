"""
Notification — logs to stdout and sends messages to Slack via webhook.
SLACK_WEBHOOK_URL 환경변수가 없으면 로그만 출력하고 Slack 전송은 건너뜀.
"""

import json
import logging
import os

import httpx

logger = logging.getLogger(__name__)

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")


class Notifier:
    def send_approval_request(self, alert: dict, analysis: dict) -> None:
        """Log a medium/high-risk action request that requires manual approval."""
        alertname = alert.get("labels", {}).get("alertname", "unknown")
        threat_level = analysis.get("threat_level", "unknown")
        action = analysis.get("action", "N/A")
        root_cause = analysis.get("root_cause", "N/A")
        confidence = analysis.get("confidence", 0.0)
        evidence = analysis.get("evidence", [])

        logger.warning(
            "[APPROVAL REQUIRED] Remediation action pending manual review:\n"
            f"  Alert      : {alertname}\n"
            f"  Threat     : {threat_level}\n"
            f"  Root cause : {root_cause}\n"
            f"  Action     : {action}\n"
            f"  Confidence : {confidence:.2f}\n"
            f"  Evidence   : {json.dumps(evidence, ensure_ascii=False)}"
        )

        self._send_slack({
            "text": f":rotating_light: *[APPROVAL REQUIRED]* `{alertname}`",
            "attachments": [
                {
                    "color": "danger",
                    "fields": [
                        {"title": "Threat Level", "value": threat_level, "short": True},
                        {"title": "Confidence",   "value": f"{confidence:.2f}", "short": True},
                        {"title": "Root Cause",   "value": root_cause, "short": False},
                        {"title": "Action",       "value": action, "short": False},
                        {"title": "Evidence",     "value": "\n".join(f"• {e}" for e in evidence), "short": False},
                    ],
                }
            ],
        })

    def send_alert_only(self, alert: dict, analysis: dict) -> None:
        """Log a medium-risk action with low threat level — notify only, no action taken."""
        alertname = alert.get("labels", {}).get("alertname", "unknown")
        threat_level = analysis.get("threat_level", "unknown")
        root_cause = analysis.get("root_cause", "N/A")
        confidence = analysis.get("confidence", 0.0)
        evidence = analysis.get("evidence", [])

        logger.info(
            "[ALERT ONLY] Medium-risk action skipped due to low threat level:\n"
            f"  Alert      : {alertname}\n"
            f"  Threat     : {threat_level}\n"
            f"  Root cause : {root_cause}\n"
            f"  Confidence : {confidence:.2f}\n"
            f"  Evidence   : {json.dumps(evidence, ensure_ascii=False)}"
        )

        self._send_slack({
            "text": f":warning: *[ALERT ONLY]* `{alertname}`",
            "attachments": [
                {
                    "color": "warning",
                    "fields": [
                        {"title": "Threat Level", "value": threat_level, "short": True},
                        {"title": "Confidence",   "value": f"{confidence:.2f}", "short": True},
                        {"title": "Root Cause",   "value": root_cause, "short": False},
                        {"title": "Evidence",     "value": "\n".join(f"• {e}" for e in evidence), "short": False},
                    ],
                }
            ],
        })

    def _send_slack(self, payload: dict) -> None:
        """SLACK_WEBHOOK_URL이 설정된 경우 Slack으로 메시지 전송."""
        if not SLACK_WEBHOOK_URL:
            logger.debug("[Notifier] SLACK_WEBHOOK_URL not set, skipping Slack notification")
            return

        try:
            response = httpx.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
            response.raise_for_status()
            logger.info("[Notifier] Slack notification sent successfully")
        except httpx.HTTPError as e:
            logger.error(f"[Notifier] Failed to send Slack notification: {e}")
