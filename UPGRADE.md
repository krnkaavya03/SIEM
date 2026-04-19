# SIEMSecure Pro v3.0 — Upgrade & Setup Guide

## What's New

| Feature | File | Status |
|---|---|---|
| Severity-routed email alerts | `core/notification_engine.py` | ✅ New |
| IP reputation enrichment (AbuseIPDB + VT) | `core/ip_enrichment.py` | ✅ New |
| Per-user risk scoring + anomaly detection | `core/risk_engine.py` | ✅ New |
| TOTP 2FA for admin accounts | `core/totp_manager.py` | ✅ New |
| Syslog UDP/TCP listener | `core/syslog_collector.py` | ✅ New |
| Windows Event Log collection | `core/windows_event_collector.py` | ✅ New |
| Secure `.env` credential loading | `.env` | ✅ New |
| Alert export (CSV / JSON) | `app_advanced.py` | ✅ New |
| Auto-refresh live dashboard | `app_advanced.py` | ✅ New |

---

## Step 1 — URGENT: Secure your credentials

Your `notification_config.json` currently contains a **plaintext Gmail app password**.
Remove it immediately:

```bash
# 1. Copy the template
cp .env.example .env

# 2. Edit .env and fill in:
#    SMTP_USER=krnkaavya03@gmail.com
#    SMTP_PASSWORD=vxtnrgdbfbdjwlaf     ← move it here
#    ALERT_RECIPIENT=krnkaavya03@gmail.com
#    ABUSEIPDB_API_KEY=your_key_here    ← get free at abuseipdb.com

# 3. Clear the password from notification_config.json
# (Leave email_enabled, smtp_server, smtp_port, smtp_user — just remove smtp_password)

# 4. Add .env to .gitignore
echo ".env" >> .gitignore
echo "totp_secrets.json" >> .gitignore
echo "ip_cache.json" >> .gitignore
echo "qr_codes/" >> .gitignore
```

---

## Step 2 — Install new dependencies

```bash
pip install python-dotenv pyotp "qrcode[pil]" scikit-learn numpy
# All others (streamlit, pandas, plotly, paramiko) should already be installed
```

---

## Step 3 — Copy new core modules

Copy these files into your `core/` folder:

```
core/
  notification_engine.py    ← email routing
  ip_enrichment.py          ← AbuseIPDB / VirusTotal
  risk_engine.py            ← user risk scoring + anomaly detection
  totp_manager.py           ← 2FA
  syslog_collector.py       ← syslog UDP/TCP listener
  windows_event_collector.py ← Windows Event Log
```

Then replace `app_advanced.py` with the new version.

---

## Step 4 — Get your free API keys

### AbuseIPDB (IP enrichment)
1. Go to https://www.abuseipdb.com/register
2. Sign up (free) → My Account → API
3. Copy your key → paste into `.env` as `ABUSEIPDB_API_KEY`

### VirusTotal (optional extra enrichment)
1. Go to https://www.virustotal.com/gui/join-us
2. Sign up (free) → API key in your profile
3. Paste into `.env` as `VIRUSTOTAL_API_KEY`

---

## Step 5 — Run

```bash
streamlit run app_advanced.py
```

---

## Step 6 — Enable 2FA (optional but recommended for admins)

1. Log in as an Admin
2. Go to **Settings → 2FA Setup**
3. Click **Enable 2FA**
4. Scan the QR code with Google Authenticator or Authy
5. Log out and log back in — you'll be prompted for your 6-digit code

---

## Step 7 — Start Syslog listener (optional)

To receive logs from routers, firewalls, and Linux hosts:

1. Go to **Settings → System → Syslog Listener**
2. Set port (default 514) and protocol (UDP recommended)
3. Click **Start Syslog Listener**
4. On your router/Linux host, configure rsyslog to forward to this machine:
   ```
   # /etc/rsyslog.conf
   *.* @YOUR_SIEM_IP:514    # UDP
   *.* @@YOUR_SIEM_IP:514   # TCP
   ```
5. Run analysis with mode = **Syslog** to process buffered messages

---

## Step 8 — Windows Event Log (Windows only)

For local collection:
```bash
pip install pywin32
python -m pywin32_postinstall -install
```

For remote collection, Paramiko (already installed) + SSH access to the Windows machine is used.

---

## Email Routing Reference

| Severity | Delivery |
|---|---|
| CRITICAL | Immediate email per alert |
| HIGH | Immediate email per alert |
| MEDIUM | Hourly digest batch |
| LOW | Daily digest batch |

To flush digests manually (or set up a cron job):
```python
from core.notification_engine import NotificationEngine
n = NotificationEngine()
n.flush_digest("hourly")
n.flush_digest("daily")
```

---

## File Structure After Upgrade

```
SIEM_Hybrid_Framework/
├── .env                         ← credentials (never commit)
├── .env.example                 ← template (safe to commit)
├── .gitignore
├── app_advanced.py              ← v3.0 dashboard (replace old one)
├── app.py                       ← original v1 (keep as backup)
├── main.py
├── config.py
├── requirements.txt             ← updated
├── users.json
├── alert_history.json
├── audit_log.json
├── ip_cache.json                ← auto-created (IP enrichment cache)
├── risk_scores.json             ← auto-created (risk score cache)
├── totp_secrets.json            ← auto-created (encrypted 2FA secrets)
├── qr_codes/                    ← auto-created (QR PNG per user)
├── core/
│   ├── __init__.py
│   ├── log_collector.py
│   ├── log_parser.py
│   ├── detection_engine.py
│   ├── correlation_engine.py
│   ├── alert_manager.py
│   ├── statistics_engine.py
│   ├── notification_engine.py   ← NEW
│   ├── ip_enrichment.py         ← NEW
│   ├── risk_engine.py           ← NEW
│   ├── totp_manager.py          ← NEW
│   ├── syslog_collector.py      ← NEW
│   └── windows_event_collector.py ← NEW
└── logs/
    └── logs.txt
```
