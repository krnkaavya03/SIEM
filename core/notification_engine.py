"""
core/notification_engine.py  —  SIEMSecure Pro v3.0
Severity-routed email notifications.

Routing:
  CRITICAL / HIGH  → immediate email per alert
  MEDIUM           → hourly digest (call flush_digest("hourly") on schedule)
  LOW              → daily digest  (call flush_digest("daily")  on schedule)

Credential priority:  .env  >  notification_config.json
No .env?  Works fine — reads straight from notification_config.json.
"""

import os
import json
import smtplib
import logging
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

logging.basicConfig(level=logging.INFO, format="[NotificationEngine] %(message)s")
log = logging.getLogger("NotificationEngine")

NOTIFICATION_CONFIG = "notification_config.json"

ROUTING = {
    "CRITICAL": "immediate",
    "HIGH":     "immediate",
    "MEDIUM":   "hourly",
    "LOW":      "daily",
}

SEVERITY_COLORS_HEX = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f39c12",
    "LOW":      "#27ae60",
}


def load_smtp_config() -> dict:
    cfg = {
        "enabled":       False,
        "smtp_server":   "smtp.gmail.com",
        "smtp_port":     587,
        "smtp_user":     "",
        "smtp_password": "",
        "recipient":     "",
    }

    if os.path.exists(NOTIFICATION_CONFIG):
        try:
            with open(NOTIFICATION_CONFIG) as f:
                raw = json.load(f)
            entry = raw[0] if isinstance(raw, list) and raw else raw
            if isinstance(entry, dict):
                cfg["enabled"]       = bool(entry.get("email_enabled", False))
                cfg["smtp_server"]   = entry.get("smtp_server",   cfg["smtp_server"])
                cfg["smtp_port"]     = int(entry.get("smtp_port", cfg["smtp_port"]))
                cfg["smtp_user"]     = entry.get("smtp_user",     cfg["smtp_user"])
                cfg["smtp_password"] = entry.get("smtp_password", cfg["smtp_password"])
                cfg["recipient"]     = entry.get("recipient",
                                       entry.get("smtp_user", cfg["recipient"]))
        except Exception as e:
            log.warning(f"Could not parse {NOTIFICATION_CONFIG}: {e}")

    # .env overrides
    if os.getenv("SMTP_USER"):
        cfg["smtp_user"]   = os.getenv("SMTP_USER")
        cfg["smtp_server"] = os.getenv("SMTP_SERVER", cfg["smtp_server"])
        cfg["smtp_port"]   = int(os.getenv("SMTP_PORT", cfg["smtp_port"]))
        cfg["enabled"]     = True
    if os.getenv("SMTP_PASSWORD"):
        cfg["smtp_password"] = os.getenv("SMTP_PASSWORD")
    if os.getenv("ALERT_RECIPIENT"):
        cfg["recipient"] = os.getenv("ALERT_RECIPIENT")

    if not cfg["recipient"] and cfg["smtp_user"]:
        cfg["recipient"] = cfg["smtp_user"]

    return cfg


def _immediate_html(alert: dict) -> str:
    sev    = alert.get("severity", "HIGH")
    color  = SEVERITY_COLORS_HEX.get(sev, "#7f8c8d")
    enrich = alert.get("ip_enrichment", {})
    enrich_row = ""
    if enrich and not enrich.get("skipped"):
        enrich_row = (
            f"<tr><td colspan='2' style='padding:10px 20px;background:#1a252f;"
            f"font-size:12px;color:#bdc3c7;'>"
            f"<b>Threat Intel</b> — Abuse: {enrich.get('abuse_confidence','?')}% | "
            f"Country: {enrich.get('country','?')} | ISP: {enrich.get('isp','?')} | "
            f"Level: {enrich.get('threat_level','?')}</td></tr>"
        )

    def row(label, value, stripe=False):
        bg = "background:#223040;" if stripe else ""
        return (f"<tr><td style='padding:12px 20px;color:#ecf0f1;{bg}width:35%;'>"
                f"<b>{label}</b></td>"
                f"<td style='padding:12px 20px;color:#bdc3c7;{bg}'>{value}</td></tr>")

    return f"""<html><body style="font-family:Arial,sans-serif;background:#0f1923;margin:0;padding:20px;">
<div style="max-width:600px;margin:auto;background:#1a252f;border-radius:10px;overflow:hidden;">
  <div style="background:{color};padding:20px 25px;">
    <h2 style="margin:0;color:#fff;">🚨 SIEM Alert — {sev}</h2>
    <p style="margin:5px 0 0;color:rgba(255,255,255,0.85);font-size:13px;">
      {alert.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}
    </p>
  </div>
  <table style="width:100%;border-collapse:collapse;">
    {row('Alert ID',    alert.get('alert_id','N/A'))}
    {row('Rule',        alert.get('rule','N/A'),       stripe=True)}
    {row('User',        alert.get('username','N/A'))}
    {row('IP Address',  alert.get('ip_address','N/A'), stripe=True)}
    {row('Description', alert.get('description','N/A'))}
    {enrich_row}
  </table>
  <div style="padding:15px 20px;background:#0f1923;font-size:11px;color:#7f8c8d;">
    SIEMSecure Pro — Automated Alert. Do not reply.
  </div>
</div></body></html>"""


def _digest_html(alerts: list, label: str) -> str:
    rows = ""
    for a in alerts:
        sev = a.get("severity", "LOW")
        c   = SEVERITY_COLORS_HEX.get(sev, "#888")
        rows += (
            f"<tr>"
            f"<td style='padding:8px 12px;color:#bdc3c7;font-size:12px;'>{a.get('alert_id','?')}</td>"
            f"<td style='padding:8px 12px;'><span style='background:{c};color:#fff;"
            f"padding:2px 8px;border-radius:4px;font-size:11px;'>{sev}</span></td>"
            f"<td style='padding:8px 12px;color:#bdc3c7;font-size:12px;'>{a.get('rule','?')}</td>"
            f"<td style='padding:8px 12px;color:#bdc3c7;font-size:12px;'>{a.get('username','?')}</td>"
            f"<td style='padding:8px 12px;color:#bdc3c7;font-size:12px;'>{a.get('ip_address','?')}</td>"
            f"</tr>"
        )
    return f"""<html><body style="font-family:Arial,sans-serif;background:#0f1923;margin:0;padding:20px;">
<div style="max-width:700px;margin:auto;background:#1a252f;border-radius:10px;overflow:hidden;">
  <div style="background:#2c3e50;padding:20px 25px;">
    <h2 style="margin:0;color:#ecf0f1;">📋 SIEM {label} Digest</h2>
    <p style="margin:5px 0 0;color:#bdc3c7;font-size:13px;">
      {len(alerts)} alert(s) | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    </p>
  </div>
  <table style="width:100%;border-collapse:collapse;">
    <tr style="background:#0f1923;">
      <th style="padding:10px 12px;color:#7f8c8d;text-align:left;font-size:11px;">ID</th>
      <th style="padding:10px 12px;color:#7f8c8d;text-align:left;font-size:11px;">SEV</th>
      <th style="padding:10px 12px;color:#7f8c8d;text-align:left;font-size:11px;">RULE</th>
      <th style="padding:10px 12px;color:#7f8c8d;text-align:left;font-size:11px;">USER</th>
      <th style="padding:10px 12px;color:#7f8c8d;text-align:left;font-size:11px;">IP</th>
    </tr>
    {rows}
  </table>
  <div style="padding:15px 20px;background:#0f1923;font-size:11px;color:#7f8c8d;">
    SIEMSecure Pro — {label} Digest. Do not reply.
  </div>
</div></body></html>"""


def _send(cfg: dict, subject: str, html: str) -> tuple:
    if not cfg.get("smtp_user") or not cfg.get("smtp_password"):
        return False, ("SMTP credentials missing. Set SMTP_USER + SMTP_PASSWORD in .env "
                       "OR enter your Gmail App Password in notification_config.json.")
    if not cfg.get("recipient"):
        return False, "No recipient. Set ALERT_RECIPIENT in .env."

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = cfg["smtp_user"]
    msg["To"]      = cfg["recipient"]
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(cfg["smtp_server"], cfg["smtp_port"], timeout=15) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(cfg["smtp_user"], cfg["smtp_password"])
            srv.sendmail(cfg["smtp_user"], cfg["recipient"], msg.as_string())
        log.info(f"Sent: {subject} → {cfg['recipient']}")
        return True, f"✅ Email sent to {cfg['recipient']}"
    except smtplib.SMTPAuthenticationError:
        return False, (
            "❌ Gmail authentication failed.\n"
            "You need a Gmail App Password (not your regular password).\n"
            "Steps: Google Account → Security → 2-Step Verification → App passwords → Generate one → paste it in .env as SMTP_PASSWORD"
        )
    except Exception as e:
        return False, f"❌ Send failed: {e}"


class NotificationEngine:

    def __init__(self):
        self._hourly_queue: list = []
        self._daily_queue:  list = []
        self._sent_ids:     set  = set()

    def process_alerts(self, alerts: list) -> list:
        cfg     = load_smtp_config()
        results = []
        if not cfg["enabled"]:
            log.info("Email notifications disabled (email_enabled=false in config).")
            return results
        new = [a for a in alerts if a.get("alert_id") not in self._sent_ids]
        for alert in new:
            sev    = alert.get("severity", "LOW").upper()
            bucket = ROUTING.get(sev, "daily")
            if bucket == "immediate":
                ok, msg = self._send_immediate(cfg, alert)
                results.append((alert.get("alert_id"), ok, msg))
            elif bucket == "hourly":
                self._hourly_queue.append(alert)
            else:
                self._daily_queue.append(alert)
            self._sent_ids.add(alert.get("alert_id"))
        return results

    def flush_digest(self, digest_type: str = "hourly") -> tuple:
        cfg   = load_smtp_config()
        queue = self._hourly_queue if digest_type == "hourly" else self._daily_queue
        if not queue:
            return True, f"No alerts in {digest_type} queue."
        label   = "Hourly" if digest_type == "hourly" else "Daily"
        subject = f"[SIEMSecure] {label} Digest — {len(queue)} alerts"
        ok, msg = _send(cfg, subject, _digest_html(queue, label))
        if ok:
            (self._hourly_queue if digest_type == "hourly" else self._daily_queue).clear()
        return ok, msg

    def send_test_email(self) -> tuple:
        cfg = load_smtp_config()
        dummy = {
            "alert_id":   "TEST-001",
            "severity":   "HIGH",
            "rule":       "TEST_RULE",
            "username":   "test_user",
            "ip_address": "127.0.0.1",
            "timestamp":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "description": "This is a test alert from SIEMSecure Pro.",
        }
        return _send(cfg, "[SIEMSecure] Test Email — Config OK", _immediate_html(dummy))

    def get_config_status(self) -> dict:
        cfg = load_smtp_config()
        pw  = cfg.get("smtp_password", "")
        cfg["smtp_password"] = ("*" * max(len(pw)-4, 0) + pw[-4:]) if pw else "NOT SET"
        return cfg

    def _send_immediate(self, cfg, alert):
        sev     = alert.get("severity", "HIGH")
        subject = f"[SIEMSecure] 🚨 {sev}: {alert.get('rule','UNKNOWN')}"
        return _send(cfg, subject, _immediate_html(alert))
    