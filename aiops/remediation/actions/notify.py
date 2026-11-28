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
        confidence = analysis.get("confidence", 0.0)
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.0
        identity = alert.get("identity")
        if not isinstance(identity, dict) or not identity:
            identity = alert.get("labels", {})
        if not isinstance(identity, dict):
            identity = {}
        targets = analysis.get("action_targets")
        if isinstance(targets, str):
            targets = [targets]
        if not isinstance(targets, (list, tuple)):
            targets = []
        # Match the policy engine's supported legacy single-target input. Button
        # values must contain the normalized list that the durable record stores.
        targets = [str(t).strip() for t in targets if str(t).strip()]
        observation = " | ".join(f"{k}: {identity.get(k) or 'UNKNOWN'}"
                                 for k in ("site", "service", "source", "runtime", "target"))
        return {
            "alertname":      alert.get("labels", {}).get("alertname", "unknown"),
            "threat_level":   analysis.get("threat_level", "unknown"),
            # action_description 은 출력 형식에서 빠졌다 (root_cause 로 흡수). 과거 결과에만 있다.
            "action":         analysis.get("action_description") or (
                f"{analysis.get('action_type', 'NONE')} → "
                + (", ".join(analysis.get("action_targets") or []) or "대상 없음")),
            "analysis_invalid": str(analysis.get("analysis_status", "")).lower() == "invalid",
            "invalid_reasons":  analysis.get("invalid_reasons") or [],
            "action_type":    analysis.get("action_type", "NONE"),       # [추가]
            "action_targets": targets,
            "root_cause":     analysis.get("root_cause", "N/A"),
            "confidence":     confidence,
            "evidence":       analysis.get("evidence", []),
            "timestamp":      alert.get("startsAt") or datetime.now(timezone.utc).isoformat(),
            "observation":    observation,
            "identity_status": alert.get("identity_status", "not_verified"),
        }

    async def send_approval_request(self, alert: dict, analysis: dict,
                                    remediation_id: str | None = None) -> dict:
        """
        Log a medium/high-risk action request that requires manual approval.

        remediation_id 를 버튼 value 에 실어 보낸다 — 같은 조치에 대한 승인이 여러 번
        도착해도 수신측이 한 건으로 합쳐 한 번만 실행한다 (멱등성, Phase 2).
        """
        if not remediation_id:
            # Legacy callers have no durable approval record. They can inform people,
            # but must not manufacture executable buttons from an alert/action name.
            return await self.send_alert_only(alert, analysis)
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

        message = {
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
                        {"type": "mrkdwn", "text": f"*관측 대상*\n{data['observation']}"},
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
                            "action_id": "approve_recovery" if analysis.get("app_recovery") is True else "approve_action",
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
        }
        plan = analysis.get("approval_plan")
        parameters = analysis.get("approval_parameters")
        stage = analysis.get("approval_stage")
        if stage:
            message["blocks"].insert(1, {"type": "section", "text": {
                "type": "plain_text", "text": "승인 범위 (각 단계 별도 승인)\n" + json.dumps(stage, ensure_ascii=False)[:2900]}})
        if plan:
            # Server-generated summary of the exact approved resource/operation.
            # Connection credentials and full operator configuration never enter Slack.
            summary = json.dumps({"parameters": parameters or {}, "plan": plan}, ensure_ascii=False)
            message["blocks"].insert(2, {"type": "section", "text": {
                "type": "plain_text", "text": "승인 대상과 실행 계획\n" + summary[:2900]}})
        return await self._send_slack(data["alertname"], message)

    async def send_alert_only(self, alert: dict, analysis: dict) -> dict:
        """RCA 정보와 권고 조치를 알린다. 승인 버튼·실행 경로는 만들지 않는다."""
        data = self._extract_analysis(alert, analysis)

        logger.info(
            "[ALERT ONLY] RCA notification, manual investigation or action review:\n"
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
                    "text": {"type": "mrkdwn", "text": (
                        f":x: *[분석 실패 — 수동 확인 필요]* `{data['alertname']}`\n"
                        f"사유: {', '.join(data['invalid_reasons']) or 'unknown'} (자동 조치 없음)"
                        if data["analysis_invalid"] else
                        f":warning: *[ALERT ONLY]* `{data['alertname']}`")}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*발생 시각*\n{data['timestamp']}"},
                        {"type": "mrkdwn", "text": f"*Threat Level*\n{data['threat_level']}"},
                        {"type": "mrkdwn", "text": f"*Confidence*\n{data['confidence']:.2f}"},
                        {"type": "mrkdwn", "text": f"*Root Cause*\n{data['root_cause']}"},
                        {"type": "mrkdwn", "text": f"*관측 대상*\n{data['observation']}"},
                        {"type": "mrkdwn", "text": f"*대상 확인*\n{data['identity_status']}"},
                        {"type": "mrkdwn", "text": f"*권고 조치 (수동 검토)*\n{data['action_type']}: {data['action']}"},
                        {"type": "mrkdwn", "text": "*권고 대상*\n" + ", ".join(str(t) for t in data['action_targets'])},
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
        if os.getenv("SLACK_BOT_TOKEN"):
            return await self._send_bot(payload, dispatched_at)
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
            error_type = type(e).__name__
            logger.error("[Notifier] Failed to send Slack notification (%s)", error_type)
            _push_loki_slack_event(alert_name, "FAILED", None, error_type)
            return {
                "sent": False,
                "status": "FAILED",
                "response_code": None,
                "response_text": error_type,
                "dispatched_at": dispatched_at,
            }

    async def _send_bot(self, payload, dispatched_at):
        """Same HITL buttons, Web API transport so a real message permalink exists.

        Never retry posting after an uncertain response: that could duplicate an
        approval message. The durable remediation ID remains the approval gate.
        """
        result = {"sent": False, "status": "FAILED", "response_code": None,
                  "response_text": "slack_bot_dispatch_failed", "dispatched_at": dispatched_at}
        try:
            async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
                headers = {"Authorization": "Bearer " + os.environ["SLACK_BOT_TOKEN"]}
                response = await client.post("https://slack.com/api/chat.postMessage", headers=headers,
                    json={**payload, "channel": os.getenv("SLACK_CHANNEL_ID", ""),
                          "text": "Leafy AIOps · 승인 요청 / 분석 결과"})
                body = response.json()
                if response.status_code != 200 or body.get("ok") is not True:
                    return result
                result.update(sent=True, status="SUCCESS", response_code=200, response_text="ok")
                link = await client.get("https://slack.com/api/chat.getPermalink", headers=headers,
                                        params={"channel": body["channel"], "message_ts": body["ts"]})
                data = link.json()
                url = data.get("permalink", "")
                from urllib.parse import urlsplit
                parsed = urlsplit(url)
                if (data.get("ok") is True and parsed.scheme == "https"
                        and (parsed.hostname or "").endswith(".slack.com")
                        and not parsed.username and not parsed.password and not parsed.query):
                    result["message_url"] = url
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            pass
        return result
