"""
Notification — logs to stdout and sends messages to Slack via webhook.
SLACK_WEBHOOK_URL 환경변수가 없으면 로그만 출력하고 Slack 전송은 건너뜀.

[수정] _extract_analysis()에 action_type, action_targets 추가
[수정] send_approval_request() blocks에 Approve / Reject 버튼 추가
"""

import json
import logging
import os
import time
import urllib.request
from datetime import datetime, timezone

import httpx

logger = logging.getLogger(__name__)

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
LOKI_URL = os.getenv("LOKI_URL", "http://loki:3100")
# main.py와 같은 값. disabled면 승인해도 실행되지 않는다는 것을 메시지에 밝힌다.
REMEDIATION_DISABLED = os.getenv("REMEDIATION_MODE", "disabled") == "disabled"
DISABLED_NOTE = "\n_자동 조치 비활성화(REMEDIATION_MODE=disabled): 승인해도 실행되지 않고 기록만 남습니다._"


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
    async def send_recovery_request(self, record):
        value = json.dumps({"remediation_id": record.remediation_id,
                            "alertname": record.alertname, "action_type": record.action_type,
                            "action_targets": record.targets})
        return await self._send_slack(record.alertname, {"blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text":
                f"복구 승인 필요: `{record.action_type}` / `{record.remediation_id}`"}},
            {"type": "actions", "elements": [{"type": "button",
                "text": {"type": "plain_text", "text": "복구 승인"},
                "action_id": "approve_recovery", "value": value}]}]})

    def _extract_analysis(self, alert: dict, analysis: dict) -> dict:
        return {
            "alertname":      alert.get("labels", {}).get("alertname", "unknown"),
            "threat_level":   analysis.get("threat_level", "unknown"),
            "action":         analysis.get("action_description", "N/A"),
            "action_type":    analysis.get("action_type", "NONE"),       # [추가]
            "action_targets": analysis.get("action_targets", []),        # [추가]
            "root_cause":     analysis.get("root_cause", "N/A"),
            "confidence":     analysis.get("confidence", 0.0),
            "evidence":       analysis.get("evidence", []),
            "timestamp":      datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        }

    async def send_approval_request(self, alert: dict, analysis: dict,
                                    remediation_id: str | None = None) -> dict:
        """
        Log a medium/high-risk action request that requires manual approval.

        remediation_id 를 버튼 value 에 실어 보낸다 — 같은 조치에 대한 승인이 여러 번
        도착해도 수신측이 한 건으로 합쳐 한 번만 실행한다 (멱등성, Phase 2).
        """
        data = self._extract_analysis(alert, analysis)

        logger.warning(
            "[APPROVAL REQUIRED] Remediation action pending manual review:\n"
            f"  Alert      : {data['alertname']}\n"
            f"  Threat     : {data['threat_level']}\n"
            f"  Root cause : {data['root_cause']}\n"
            f"  Action     : {data['action']}\n"
            f"  Confidence : {data['confidence']:.2f}\n"
            f"  Evidence   : {json.dumps(data['evidence'], ensure_ascii=False)}"
        )

        # [추가] 버튼 value에 직렬화 — 클릭 시 서버가 어떤 조치를 할지 알아야 함
        action_payload = json.dumps({
            "alertname":      data["alertname"],
            "action_type":    data["action_type"],
            "action_targets": data["action_targets"],
            "remediation_id": remediation_id,
        }, ensure_ascii=False)

        return await self._send_slack(data["alertname"], {
            "blocks": [
                # ── 헤더 ──────────────────────────────────────────
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f":rotating_light: *[APPROVAL REQUIRED]* `{data['alertname']}`"
                                + (DISABLED_NOTE if REMEDIATION_DISABLED else "")
                    }
                },
                # ── 상세 정보 ──────────────────────────────────────
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*발생 시각*\n{data['timestamp']}"},
                        {"type": "mrkdwn", "text": f"*Threat Level*\n{data['threat_level']}"},
                        {"type": "mrkdwn", "text": f"*Confidence*\n{data['confidence']:.2f}"},
                        {"type": "mrkdwn", "text": f"*Root Cause*\n{data['root_cause']}"},
                        {"type": "mrkdwn", "text": f"*Action*\n{data['action']}"},
                        {
                            "type": "mrkdwn",
                            "text": "*Evidence*\n" + (
                                "\n".join(f"• {e}" for e in data["evidence"])
                                if data["evidence"] else "N/A"
                            ),
                        },
                    ]
                },
                # ── 구분선 ────────────────────────────────────────
                {"type": "divider"},
                # ── [추가] Approve / Reject 버튼 ──────────────────
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "✅ Approve", "emoji": True},
                            "style": "primary",
                            "action_id": "approve_action",
                            "value": action_payload,
                            "confirm": {
                                "title": {"type": "plain_text", "text": "조치를 승인하시겠습니까?"},
                                "text": {
                                    "type": "mrkdwn",
                                    "text": (
                                        (f"*{data['action_type']}* 승인을 기록합니다 (실행되지 않음).\n"
                                         if REMEDIATION_DISABLED else
                                         f"*{data['action_type']}* 조치를 실행합니다.\n")
                                        + f"대상: `{'`, `'.join(data['action_targets']) if data['action_targets'] else 'N/A'}`"
                                    ),
                                },
                                "confirm": {"type": "plain_text", "text": "승인"},
                                "deny":    {"type": "plain_text", "text": "취소"},
                            },
                        },
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "❌ Reject", "emoji": True},
                            "style": "danger",
                            "action_id": "reject_action",
                            "value": action_payload,
                        },
                    ]
                },
            ]
        })

    async def send_alert_only(self, alert: dict, analysis: dict) -> dict:
        """Log a medium-risk action with low threat level — notify only, no action taken."""
        data = self._extract_analysis(alert, analysis)

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
                        {
                            "type": "mrkdwn",
                            "text": "*Evidence*\n" + (
                                "\n".join(f"• {e}" for e in data["evidence"])
                                if data["evidence"] else "N/A"
                            ),
                        },
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
                status = "SUCCESS" if sent else "FAILED"
                if sent:
                    logger.info("[Notifier] Slack webhook delivered")
                else:
                    logger.error(
                        "[Notifier] Slack webhook failed: "
                        f"code={response.status_code}, text={response_text!r}"
                    )
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
