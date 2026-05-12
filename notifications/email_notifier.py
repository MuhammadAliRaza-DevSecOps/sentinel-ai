# notifications/email_notifier.py
# Email notifications bhejta hai SMTP ke through
# notifications/email_notifier.py ke top pe yeh add karo
from dotenv import load_dotenv
load_dotenv()  # .env file load karo
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from loguru import logger


class EmailNotifier:
    """
    Gmail ya kisi bhi SMTP server se email bhejta hai.
    
    Gmail setup:
    1. Google Account → Security → 2-Step Verification → App Passwords
    2. "Mail" app → Generate password
    3. Woh password SMTP_PASSWORD mein daalo (normal password kaam nahi karta)
    """

    def __init__(self):
        self.smtp_host     = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port     = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user     = os.getenv("SMTP_USER", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.from_email    = self.smtp_user
        self.to_emails     = os.getenv("NOTIFY_EMAILS", self.smtp_user).split(",")

    def _build_html_email(self, scan_result: dict) -> str:
        """HTML email body banata hai."""
        risk_level = scan_result.get("risk_level", "UNKNOWN")
        counts     = scan_result.get("counts", {})
        
        color = {"PASS": "#00CC44", "FAIL": "#FF4B4B", "WARN": "#FFD700"}.get(risk_level, "#888")
        
        findings_html = ""
        for f in (scan_result.get("findings", []) or [])[:10]:  # Top 10 findings
            sev = f.get("severity", "info")
            sev_colors = {
                "critical": "#FF4B4B", "high": "#FF8C00",
                "medium": "#FFD700", "low": "#00CC44"
            }
            fc = sev_colors.get(sev, "#888")
            findings_html += f"""
            <tr>
              <td style="color:{fc};padding:6px 10px;border-bottom:1px solid #eee">{sev.upper()}</td>
              <td style="padding:6px 10px;border-bottom:1px solid #eee;font-family:monospace;font-size:12px">{f.get('file_path','')[:60]}</td>
              <td style="padding:6px 10px;border-bottom:1px solid #eee;font-size:13px">{f.get('description','')[:150]}</td>
            </tr>
            """

        return f"""
        <html><body style="font-family:Arial,sans-serif;max-width:800px;margin:0 auto">
          <h2 style="color:{color}">🛡️ Security Scan: {risk_level}</h2>
          <table style="background:#f5f5f5;padding:1rem;border-radius:8px;width:100%">
            <tr><td><strong>Branch:</strong></td><td>{scan_result.get('branch','N/A')}</td></tr>
            <tr><td><strong>Commit:</strong></td><td>{str(scan_result.get('commit_sha','N/A'))[:8]}</td></tr>
            <tr><td><strong>Time:</strong></td><td>{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</td></tr>
          </table>
          <h3>Summary</h3>
          <table style="width:100%">
            <tr>
              <td style="text-align:center;background:#FF4B4B;color:white;padding:12px;border-radius:8px;margin:4px">
                <div style="font-size:2em;font-weight:bold">{counts.get('critical',0)}</div>Critical
              </td>
              <td style="text-align:center;background:#FF8C00;color:white;padding:12px;border-radius:8px">
                <div style="font-size:2em;font-weight:bold">{counts.get('high',0)}</div>High
              </td>
              <td style="text-align:center;background:#FFD700;color:black;padding:12px;border-radius:8px">
                <div style="font-size:2em;font-weight:bold">{counts.get('medium',0)}</div>Medium
              </td>
            </tr>
          </table>
          <h3>Top Findings</h3>
          <table style="width:100%;border-collapse:collapse">
            <thead style="background:#333;color:white">
              <tr><th style="padding:8px">Severity</th><th style="padding:8px">File</th><th style="padding:8px">Description</th></tr>
            </thead>
            <tbody>{findings_html}</tbody>
          </table>
          <p style="color:#888;font-size:12px;margin-top:2rem">
            DevSecOps Pipeline Orchestrator — automated security notification
          </p>
        </body></html>
        """

    def send_scan_result(self, scan_result: dict) -> bool:
        """Scan result email karo."""
        if not self.smtp_user or not self.smtp_password:
            logger.warning("Email credentials set nahi hain")
            return False

        risk_level = scan_result.get("risk_level", "UNKNOWN")
        subject = f"[DevSecOps] Security Scan {risk_level} — {scan_result.get('branch', 'main')}"

        # MIME = Multipurpose Internet Mail Extensions
        # MIMEMultipart allows both plain text AND HTML versions
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = self.from_email
        msg["To"]      = ", ".join(self.to_emails)

        # Plain text fallback (email clients jo HTML nahi dikhate)
        text_part = MIMEText(
            f"Security Scan Result: {risk_level}\n"
            f"Branch: {scan_result.get('branch')}\n"
            f"Critical: {scan_result.get('counts',{}).get('critical',0)}\n"
            f"High: {scan_result.get('counts',{}).get('high',0)}",
            "plain"
        )
        html_part = MIMEText(self._build_html_email(scan_result), "html")

        # Dono parts attach karo — client best supported version use karega
        msg.attach(text_part)
        msg.attach(html_part)

        try:
            # SMTP connection banao
            # starttls() = TLS encryption enable karo (SMTP port 587 ke liye)
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.ehlo()            # Server ko hello kaho
                server.starttls()        # Encryption enable karo
                server.login(self.smtp_user, self.smtp_password)
                server.sendmail(
                    self.from_email,
                    self.to_emails,
                    msg.as_string()
                )
            
            logger.info(f"Email sent to: {self.to_emails}")
            return True

        except smtplib.SMTPAuthenticationError:
            logger.error("Email auth fail — App Password use karo, normal password nahi")
            return False
        except Exception as e:
            logger.error(f"Email send error: {e}")
            return False