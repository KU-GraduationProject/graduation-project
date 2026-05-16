"""
Notification — logs to stdout and sends messages to Slack via webhook.
SLACK_WEBHOOK_URL 환경변수가 없으면 로그만 출력하고 Slack 전송은 건너뜀.
"""

import json
import logging
import os
from datetime import datetime  # ← 추가

import httpx

logger = logging.getLogger(__name__)

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")


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

    async def send_approval_request(self, alert: dict, analysis: dict) -> None:
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

        await self._send_slack({
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

    async def send_alert_only(self, alert: dict, analysis: dict) -> None:
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

        await self._send_slack({
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

    async def _send_slack(self, payload: dict) -> None:  # ← 동기 → 비동기로 변경
        """SLACK_WEBHOOK_URL이 설정된 경우 Slack으로 메시지 전송."""
        if not SLACK_WEBHOOK_URL:
            logger.debug("[Notifier] SLACK_WEBHOOK_URL not set, skipping Slack notification")
            return

        try:
            async with httpx.AsyncClient(timeout=10) as client:  # ← 비동기로 변경
                response = await client.post(SLACK_WEBHOOK_URL, json=payload)
                response.raise_for_status()
                logger.info("[Notifier] Slack notification sent successfully")
        except httpx.HTTPError as e:
            logger.error(f"[Notifier] Failed to send Slack notification: {e}")