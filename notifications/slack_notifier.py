# notifications/slack_notifier.py
# Slack mein scan results bhejta hai

import json
import httpx
import os
from datetime import datetime
from loguru import logger


class SlackNotifier:
    """
    Slack Incoming Webhook use karta hai.
    
    Setup kaise karein:
    1. api.slack.com/apps → Create New App
    2. Incoming Webhooks → Activate
    3. Add to Workspace → Channel select karo
    4. Webhook URL copy karo → .env mein daalo
    """

    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL", "")
        
        if not self.webhook_url:
            logger.warning("SLACK_WEBHOOK_URL set nahi hai — notifications nahi jayengi")

    def send_scan_result(self, scan_result: dict) -> bool:
        """
        Scan result Slack pe bhejta hai.
        Rich formatting use karta hai — blocks API.
        """
        if not self.webhook_url:
            return False

        risk_level = scan_result.get("risk_level", "UNKNOWN")
        counts     = scan_result.get("counts", {})
        
        # Risk level ke hisaab se color aur emoji
        if risk_level == "PASS":
            color = "#00CC44"
            emoji = "✅"
        elif risk_level == "FAIL":
            color = "#FF4B4B"
            emoji = "🚨"
        else:
            color = "#FFD700"
            emoji = "⚠️"

        # Slack Block Kit format — rich formatted messages
        payload = {
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"{emoji} Security Scan: {risk_level}",
                            }
                        },
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Branch:*\n`{scan_result.get('branch', 'N/A')}`"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Commit:*\n`{str(scan_result.get('commit_sha', 'N/A'))[:8]}`"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*🔴 Critical:* {counts.get('critical', 0)}"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*🟠 High:* {counts.get('high', 0)}"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*🟡 Medium:* {counts.get('medium', 0)}"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*🟢 Low:* {counts.get('low', 0)}"
                                },
                            ]
                        },
                        {
                            "type": "context",
                            "elements": [
                                {
                                    "type": "mrkdwn",
                                    "text": (
                                        f"Scan ID: `{scan_result.get('scan_id', 'N/A')}` | "
                                        f"Duration: {scan_result.get('duration_ms', 0)}ms | "
                                        f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
                                    )
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        try:
            # httpx use karte hain HTTP POST ke liye
            with httpx.Client() as client:
                response = client.post(
                    self.webhook_url,
                    json=payload,
                    timeout=10,
                )
                
                if response.status_code == 200:
                    logger.info("Slack notification sent!")
                    return True
                else:
                    logger.error(f"Slack error: {response.status_code} — {response.text}")
                    return False

        except Exception as e:
            logger.error(f"Slack send error: {e}")
            return False

    def send_critical_alert(self, finding: dict, scan_id: str) -> bool:
        """
        Critical finding milne pe turant alert bhejta hai.
        Ye normal scan result se alag aur zyada urgent hota hai.
        """
        if not self.webhook_url:
            return False

        payload = {
            "attachments": [
                {
                    "color": "#FF0000",
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": "🚨 CRITICAL SECURITY FINDING DETECTED",
                            }
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": (
                                    f"*Type:* {finding.get('vuln_type', 'N/A')}\n"
                                    f"*File:* `{finding.get('file_path', 'N/A')}` "
                                    f"line {finding.get('line_number', 'N/A')}\n"
                                    f"*CVSS:* {finding.get('cvss_score', 0):.1f}\n"
                                    f"*Description:* {finding.get('description', '')[:300]}\n\n"
                                    f"*Fix:* {finding.get('remediation', '')[:200]}"
                                )
                            }
                        },
                        {
                            "type": "actions",
                            "elements": [
                                {
                                    "type": "button",
                                    "text": {"type": "plain_text", "text": "📋 View Full Report"},
                                    "url": f"http://localhost:8501?scan_id={scan_id}",
                                    "style": "danger",
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        try:
            with httpx.Client() as client:
                resp = client.post(self.webhook_url, json=payload, timeout=10)
                return resp.status_code == 200
        except Exception as e:
            logger.error(f"Critical alert error: {e}")
            return False