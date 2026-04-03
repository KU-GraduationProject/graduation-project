"""
Notification stub — prints approval requests to stdout/logger only.
No external integrations (Slack, email, etc.).
"""

import logging
import json

logger = logging.getLogger(__name__)


class Notifier:
    def send_approval_request(self, alert: dict, analysis: dict) -> None:
        """Log a high-risk action request that requires manual approval."""
        alertname = alert.get("labels", {}).get("alertname", "unknown")
        threat_level = analysis.get("threat_level", "unknown")
        action = analysis.get("action", "N/A")
        root_cause = analysis.get("root_cause", "N/A")
        confidence = analysis.get("confidence", 0.0)

        logger.warning(
            "[APPROVAL REQUIRED] High-risk remediation action pending manual review:\n"
            f"  Alert      : {alertname}\n"
            f"  Threat     : {threat_level}\n"
            f"  Root cause : {root_cause}\n"
            f"  Action     : {action}\n"
            f"  Confidence : {confidence:.2f}\n"
            f"  Evidence   : {json.dumps(analysis.get('evidence', []), ensure_ascii=False)}"
        )
