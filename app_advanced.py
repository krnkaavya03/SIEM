# app_advanced.py — SIEMSecure Pro v3.1

import streamlit as st
import pandas as pd
import os, sys, json, hashlib, re, time, io, csv
import plotly.express as px
from datetime import datetime, timedelta


# ------------------------
# Initialize session_state
# ------------------------
if 'alerts_data' not in st.session_state:
    st.session_state['alerts_data'] = []

if 'analysis_mode' not in st.session_state:
    st.session_state['analysis_mode'] = None

if 'log_file' not in st.session_state:
    st.session_state['log_file'] = None

if 'dashboard_data' not in st.session_state:
    st.session_state['dashboard_data'] = pd.DataFrame()

# ── Load environment variables ─────────────────────────
from dotenv import load_dotenv
load_dotenv()

# (Optional Debug - REMOVE after testing)
# st.write("API KEY:", os.getenv("ABUSEIPDB_API_KEY"))

# ── Path setup ─────────────────────────────────────────
ROOT = os.path.abspath(os.path.dirname(__file__) if "__file__" in dir() else ".")
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# ── SIEM Framework import ──────────────────────────────
_SIEM_OK = False
try:
    from main import SIEMFramework
    _SIEM_OK = True
except ImportError:
    try:
        from SIEM_Hybrid_Framework.main import SIEMFramework
        _SIEM_OK = True
    except ImportError:
        pass

# ── Optional Modules (Safe Imports) ────────────────────
_NOTIF_OK = _ENRICH_OK = _RISK_OK = _TOTP_OK = _SYSLOG_OK = _WINEVENT_OK = False

try:
    from core.notification_engine import NotificationEngine, load_smtp_config
    _NOTIF_OK = True
except Exception:
    pass

try:
    # ✅ FIXED CLASS NAME HERE
    from core.ip_enrichment import IPEnrichment
    _ENRICH_OK = True
except Exception:
    pass

try:
    from core.risk_engine import RiskEngine
    _RISK_OK = True
except Exception:
    pass

try:
    from core.totp_manager import TOTPManager
    _TOTP_OK = True
except Exception:
    pass

try:
    from core.syslog_collector import SyslogCollector
    _SYSLOG_OK = True
except Exception:
    pass

try:
    from core.windows_event_collector import WindowsEventCollector
    _WINEVENT_OK = True
except Exception:
    pass

# ──────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ──────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SIEMSecure Pro",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────
USER_DB          = "users.json"
ALERT_HISTORY_DB = "alert_history.json"
NOTIFICATION_CFG = "notification_config.json"
AUDIT_LOG_FILE   = "audit_log.json"
MAX_ATTEMPTS     = int(os.getenv("MAX_LOGIN_ATTEMPTS", 3))
LOCK_TIME        = int(os.getenv("LOCK_TIME_SECONDS", 60))

SEVERITY_COLORS = {
    "CRITICAL": "#e74c3c",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#2ecc71",
}

# ──────────────────────────────────────────────────────────────────────────────
# THEME
# ──────────────────────────────────────────────────────────────────────────────
def apply_theme(theme):
    p = {
        "Dark Pro":   dict(grad="linear-gradient(135deg,#0F2027,#203A43,#2C5364)", card="rgba(31,41,55,0.85)", accent="#00D9FF"),
        "Cyber Blue": dict(grad="linear-gradient(135deg,#667eea,#764ba2)",         card="rgba(30,30,63,0.85)",  accent="#00FFFF"),
        "Matrix":     dict(grad="linear-gradient(135deg,#000000,#0a0e27)",          card="rgba(10,10,10,0.9)",   accent="#00FF41"),
        "Light Pro":  dict(grad="linear-gradient(135deg,#f5f7fa,#c3cfe2)",          card="rgba(255,255,255,0.92)", accent="#4299e1"),
    }.get(theme, {})
    if not p:
        return
    st.markdown(f"""<style>
    .stApp{{background:{p['grad']};}}
    section[data-testid="stSidebar"]{{background:{p['card']};backdrop-filter:blur(10px);}}
    div[data-testid="metric-container"]{{background:{p['card']};border-radius:15px;
        padding:20px;border:1px solid rgba(255,255,255,0.1);
        box-shadow:0 8px 32px rgba(31,38,135,0.37);transition:transform .3s;}}
    div[data-testid="metric-container"]:hover{{transform:translateY(-4px);}}
    .stButton>button{{background:linear-gradient(45deg,{p['accent']},{p['accent']}AA);
        color:white;border:none;border-radius:25px;padding:10px 28px;font-weight:bold;
        transition:all .3s;}}
    .stButton>button:hover{{transform:scale(1.04);}}
    </style>""", unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────────────────────
# DB HELPERS
# ──────────────────────────────────────────────────────────────────────────────
def load_json(path, default=None):
    if default is None:
        default = []
    if not os.path.exists(path):
        return default
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        st.error(f"Save failed: {e}")

def load_users() -> dict:
    d = load_json(USER_DB, {})
    return d if isinstance(d, dict) else {}

def save_users(u: dict):
    save_json(USER_DB, u)

def hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def is_strong(pw: str) -> bool:
    return (len(pw) >= 8
            and re.search(r"[A-Z]", pw)
            and re.search(r"[0-9]", pw)
            and re.search(r'[!@#$%^&*(),.?":{}|<>]', pw))

def log_audit(username: str, action: str, details: str = ""):
    data = load_json(AUDIT_LOG_FILE, [])
    if not isinstance(data, list):
        data = []
    data.append({
        "timestamp":  datetime.now().isoformat(),
        "username":   username,
        "action":     action,
        "details":    str(details),
        "ip_address": "127.0.0.1",
    })
    save_json(AUDIT_LOG_FILE, data)

def save_alert_history(new_alerts: list):
    history = load_json(ALERT_HISTORY_DB, [])
    if not isinstance(history, list):
        history = []
    existing = {a.get("alert_id") for a in history}
    added = [a for a in new_alerts if a.get("alert_id") not in existing]
    history.extend(added)
    save_json(ALERT_HISTORY_DB, history)
    return added


# ──────────────────────────────────────────────────────────────────────────────
# AUTH
# ──────────────────────────────────────────────────────────────────────────────
def authenticate(username: str, password: str) -> str:
    users = load_users()
    if username not in users:
        return "no_user"
    u = users[username]
    if u.get("locked_until", 0) > time.time():
        return "locked"
    if u["password"] != hash_pw(password):
        u["failed_attempts"] = u.get("failed_attempts", 0) + 1
        if u["failed_attempts"] >= MAX_ATTEMPTS:
            u["locked_until"] = time.time() + LOCK_TIME
            save_users(users)
            log_audit(username, "ACCOUNT_LOCKED")
            return "locked"
        save_users(users)
        log_audit(username, "LOGIN_FAILED", f"Attempt {u['failed_attempts']}")
        return "wrong_password"
    u["failed_attempts"] = 0
    u["locked_until"]    = 0
    u["last_login"]      = datetime.now().isoformat()
    save_users(users)
    log_audit(username, "LOGIN_SUCCESS", "Successful login")
    return "success"

def register_user(username: str, password: str, role: str, email: str = "") -> str:
    users = load_users()
    if username in users:
        return "exists"
    if not is_strong(password):
        return "weak"
    users[username] = {
        "password":        hash_pw(password),
        "role":            role,
        "email":           email,
        "failed_attempts": 0,
        "locked_until":    0,
        "created_at":      datetime.now().isoformat(),
        "two_fa_enabled":  False,
    }
    save_users(users)
    log_audit(username, "USER_REGISTERED", f"New {role}")
    return "success"


# ──────────────────────────────────────────────────────────────────────────────
# SESSION STATE
# ──────────────────────────────────────────────────────────────────────────────
for k, v in [
    ("authenticated", False), ("username", None), ("role", None),
    ("awaiting_2fa", False), ("syslog_collector", None),
    ("live_refresh", False), ("last_refresh", 0.0),
    ("last_alerts", []),     ("last_stats", {}),
]:
    if k not in st.session_state:
        st.session_state[k] = v

# ──────────────────────────────────────────────────────────────────────────────
# SIDEBAR THEME (always visible)
# ──────────────────────────────────────────────────────────────────────────────
st.sidebar.title("⚙️ Controls")
theme = st.sidebar.selectbox("Theme", ["Dark Pro", "Cyber Blue", "Matrix", "Light Pro"])
apply_theme(theme)


# ══════════════════════════════════════════════════════════════════════════════
# LOGIN / REGISTER PAGE
# ══════════════════════════════════════════════════════════════════════════════
if not st.session_state.authenticated:
    st.title("🔐 SIEMSecure Pro")

    menu = st.radio("", ["Login", "Register"], horizontal=True)
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if menu == "Login":
        if st.button("Login", use_container_width=True):
            result = authenticate(username, password)
            if result == "success":
                users = load_users()
                user  = users.get(username, {})
                if user.get("two_fa_enabled") and _TOTP_OK:
                    st.session_state.awaiting_2fa = True
                    st.session_state.username     = username
                    st.session_state.role         = user["role"]
                    st.rerun()
                else:
                    st.session_state.authenticated = True
                    st.session_state.username      = username
                    st.session_state.role          = user["role"]
                    st.rerun()
            elif result == "no_user":      st.error("User does not exist.")
            elif result == "wrong_password": st.error("Incorrect password.")
            elif result == "locked":       st.error("Account locked. Try again later.")

    else:  # Register
        role  = st.selectbox("Role", ["Analyst", "Admin"])
        email = st.text_input("Email (used for alert notifications)")
        if st.button("Register", use_container_width=True):
            result = register_user(username, password, role, email)
            if result == "success":    st.success("Registered! You can now log in.")
            elif result == "exists":   st.error("Username already exists.")
            elif result == "weak":     st.error("Password needs 8+ chars, 1 uppercase, 1 digit, 1 special character.")

    # 2FA verification step
    if st.session_state.awaiting_2fa:
        st.divider()
        st.subheader("🔐 Two-Factor Authentication")
        code = st.text_input("Enter 6-digit code from your authenticator app", max_chars=6)
        if st.button("Verify"):
            totp = TOTPManager()
            if totp.verify(st.session_state.username, code.strip()):
                st.session_state.authenticated = True
                st.session_state.awaiting_2fa  = False
                log_audit(st.session_state.username, "2FA_SUCCESS")
                st.rerun()
            else:
                st.error("Invalid code. Try again.")

    st.stop()


# ══════════════════════════════════════════════════════════════════════════════
# MAIN DASHBOARD  (only reached when authenticated)
# ══════════════════════════════════════════════════════════════════════════════
st.title("🔒 SIEMSecure Pro")
st.subheader(f"Welcome, **{st.session_state.username}**  ({st.session_state.role})")

hdr1, hdr2 = st.columns([1, 1])
with hdr1:
    if st.button("Logout"):
        log_audit(st.session_state.username, "LOGOUT")
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.rerun()
with hdr2:
    live = st.toggle("⚡ Auto-refresh every 30 s", value=st.session_state.live_refresh)
    st.session_state.live_refresh = live

if st.session_state.live_refresh:
    if time.time() - st.session_state.last_refresh > 30:
        st.session_state.last_refresh = time.time()
        st.rerun()

# ── Sidebar: analysis options ──────────────────────────────────────────────────
st.sidebar.header("Analysis Mode")
mode = st.sidebar.radio("Mode", ["Test", "Live (SSH)", "Syslog Listener", "Windows Event Log"])

log_file_path = remote_server = remote_user = remote_pass = None

if mode == "Test":
    log_file_path = st.sidebar.text_input("Log file path", value="logs/logs.txt")

elif mode == "Live (SSH)":
    remote_server = st.sidebar.text_input("Remote Server IP/hostname")
    remote_user   = st.sidebar.text_input("SSH Username")
    remote_pass   = st.sidebar.text_input("SSH Password", type="password")
    remote_logpath = st.sidebar.text_input("Remote log path", value="/var/log/auth.log")
    if remote_server:
        st.sidebar.caption(f"Will connect to {remote_user}@{remote_server}")

elif mode == "Syslog Listener":
    sl_port  = st.sidebar.number_input("Listen Port", value=514, min_value=1, max_value=65535)
    sl_proto = st.sidebar.selectbox("Protocol", ["UDP", "TCP"])
    sc = st.session_state.syslog_collector
    if sc and sc.get_status()["running"]:
        st.sidebar.success(f"Listener active on {sl_proto}:{int(sl_port)}")
    else:
        st.sidebar.warning("Listener not started — see Settings → System")

elif mode == "Windows Event Log":
    if st.session_state.role == "Admin":
        remote_server = st.sidebar.text_input("Remote Server (blank = local)")
        remote_user   = st.sidebar.text_input("Remote Username")
        remote_pass   = st.sidebar.text_input("Remote Password", type="password")
    else:
        st.sidebar.info("Admin required for Windows Event Log mode.")

enrich_ips  = st.sidebar.checkbox("🌐 Enrich IPs via AbuseIPDB", value=_ENRICH_OK)
send_emails = st.sidebar.checkbox("📧 Send email alerts", value=_NOTIF_OK)
run_button  = st.sidebar.button("▶  Run Analysis", use_container_width=True)

# ──────────────────────────────────────────────────────────────────────────────
# TABS
# ──────────────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "🏠 Dashboard",
    "🚨 Alerts",
    "📊 Analytics",
    "🛡️ Risk & Anomalies",
    "📜 Audit Log",
    "⚙️ Settings",
    "📡 Live Monitor",
])


# ══════════════════════════════════════════════════════════════════════════════
# RUN ANALYSIS PIPELINE
# ══════════════════════════════════════════════════════════════════════════════
if run_button:
    if not _SIEM_OK:
        st.error("SIEMFramework not available. Cannot run analysis.")
    elif mode == "Live (SSH)" and st.session_state.role != "Admin":
        st.error("Only Admins can run Live SSH mode.")
    else:
        with st.spinner("Running SIEM analysis..."):
            try:
                # ── Build and run framework ────────────────────────────────
                if mode == "Windows Event Log" and _WINEVENT_OK:
                    wc  = WindowsEventCollector()
                    raw = (wc.collect_remote(remote_server, remote_user, remote_pass)
                           if remote_server else wc.collect())
                    siem = SIEMFramework(test_mode=True)
                    siem.raw_logs = raw
                    siem.run_analysis()

                elif mode == "Syslog Listener" and _SYSLOG_OK:
                    sc  = st.session_state.syslog_collector
                    raw = sc.drain() if sc else []
                    siem = SIEMFramework(test_mode=True)
                    siem.raw_logs = raw
                    siem.run_analysis()

                elif mode == "Live (SSH)":
                    siem = SIEMFramework(
                        log_file_path=log_file_path,
                        live_mode=True,
                        test_mode=False,
                        remote_server=remote_server,
                        remote_user=remote_user,
                        remote_password=remote_pass,
                    )
                    siem.run_analysis()

                else:  # Test
                    siem = SIEMFramework(
                        log_file_path=log_file_path,
                        test_mode=True,
                    )
                    siem.run_analysis()

                alerts = siem.alerts or []
                stats  = siem.statistics or {}

                # ── IP Enrichment ──────────────────────────────────────────
                if enrich_ips and _ENRICH_OK and alerts:
                    with st.spinner("Enriching IPs with AbuseIPDB..."):
                        enricher = IPEnrichment()
                        alerts   = enricher.enrich_alerts(alerts)

                # ── Save to history ────────────────────────────────────────
                new_alerts = save_alert_history(alerts)

                # ── Email notifications ────────────────────────────────────
                notif_results = []
                if send_emails and _NOTIF_OK and new_alerts:
                    notifier = NotificationEngine()
                    notif_results = notifier.process_alerts(new_alerts)

                # ── Risk scoring ───────────────────────────────────────────
                if _RISK_OK and new_alerts:
                    risk = RiskEngine()
                    alerts = risk.calculate_risk(alerts)

                # ── Audit ──────────────────────────────────────────────────
                mode_labels = {
                    "Test":               "🧪 Test",
                    "Live (SSH)":         "🔴 Live SSH",
                    "Syslog Listener":    "📡 Syslog",
                    "Windows Event Log":  "🪟 WinEvent",
                }
                log_audit(st.session_state.username, "ANALYSIS_RUN",
                          f"Mode: {mode_labels.get(mode, mode)}, Alerts: {len(alerts)}")

                st.session_state.last_alerts = alerts
                alerts = st.session_state.alerts_data
                st.session_state.last_stats  = stats

                # ── Result summary ─────────────────────────────────────────
                st.success(
                    f"✅ Analysis complete — **{len(alerts)}** alert(s) | "
                    f"**{len(new_alerts)}** new"
                )
                if notif_results:
                    for aid, ok, msg in notif_results:
                        if ok:
                            st.success(f"📧 Email sent for {aid}")
                        else:
                            st.warning(f"📧 Email failed for {aid}: {msg}")

            except Exception as e:
                st.error(f"Pipeline error: {e}")
                import traceback; traceback.print_exc()


# ══════════════════════════════════════════════════════════════════════════════
# TAB 1  —  DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
with tab1:
    history = load_json(ALERT_HISTORY_DB, [])
    alerts  = st.session_state.last_alerts

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total (history)",  len(history))
    c2.metric("Critical",  sum(1 for a in history if a.get("severity") == "CRITICAL"))
    c3.metric("High",      sum(1 for a in history if a.get("severity") == "HIGH"))
    c4.metric("Unreviewed",sum(1 for a in history if not a.get("acknowledged")))
    c5.metric("Session alerts", len(alerts))

    if history:
        df = pd.DataFrame(history)
        r1, r2 = st.columns(2)
        with r1:
            if "severity" in df.columns:
                sev = df["severity"].value_counts().reset_index()
                sev.columns = ["Severity","Count"]
                fig = px.pie(sev, names="Severity", values="Count", hole=0.4,
                             color="Severity", color_discrete_map=SEVERITY_COLORS,
                             title="Severity Distribution")
                st.plotly_chart(fig, use_container_width=True)
        with r2:
            if "rule" in df.columns:
                rules = df["rule"].value_counts().head(8).reset_index()
                rules.columns = ["Rule","Count"]
                fig2 = px.bar(rules, x="Count", y="Rule", orientation="h",
                              title="Top Alert Rules", color="Count",
                              color_continuous_scale="Reds")
                st.plotly_chart(fig2, use_container_width=True)

        if "timestamp" in df.columns:
            df["ts"] = pd.to_datetime(df["timestamp"], errors="coerce")
            df_s = df.dropna(subset=["ts"]).sort_values("ts")
            fig3 = px.scatter(df_s, x="ts", y="severity", color="severity",
                              color_discrete_map=SEVERITY_COLORS,
                              hover_data=["rule","username","ip_address"],
                              title="Alert Timeline")
            st.plotly_chart(fig3, use_container_width=True)
    else:
        st.info("Run an analysis to populate the dashboard.")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2  —  ALERTS
# ══════════════════════════════════════════════════════════════════════════════
with tab2:
    st.header("🚨 Alert Management")
    history = load_json(ALERT_HISTORY_DB, [])

    if not isinstance(history, list):
        history = []

    if history:
        fc1, fc2, fc3 = st.columns(3)
        with fc1:
            f_sev = st.multiselect("Severity", ["CRITICAL","HIGH","MEDIUM","LOW"],
                                   default=["CRITICAL","HIGH","MEDIUM","LOW"])
        with fc2:
            f_status = st.selectbox("Status", ["All","Acknowledged","Unacknowledged"])
        with fc3:
            all_rules = list(set(a.get("rule","") for a in history if a.get("rule")))
            f_rule = st.multiselect("Rule", all_rules)

        # Export
        ec1, ec2 = st.columns(2)
        with ec1:
            buf = io.StringIO()
            w   = csv.DictWriter(buf, fieldnames=["alert_id","severity","rule","username","ip_address","timestamp","description"])
            w.writeheader()
            [w.writerow({k: a.get(k,"") for k in ["alert_id","severity","rule","username","ip_address","timestamp","description"]}) for a in history]
            st.download_button("📥 Export CSV", buf.getvalue(),
                               file_name=f"alerts_{datetime.now().strftime('%Y%m%d')}.csv",
                               mime="text/csv")
        with ec2:
            st.download_button("📥 Export JSON", json.dumps(history, indent=2),
                               file_name=f"alerts_{datetime.now().strftime('%Y%m%d')}.json",
                               mime="application/json")

        # Filter
        filtered = [a for a in history if a.get("severity","") in f_sev]
        if f_status == "Acknowledged":
            filtered = [a for a in filtered if a.get("acknowledged")]
        elif f_status == "Unacknowledged":
            filtered = [a for a in filtered if not a.get("acknowledged")]
        if f_rule:
            filtered = [a for a in filtered if a.get("rule","") in f_rule]

        st.markdown(f"**Showing {len(filtered)} of {len(history)} alerts**")

        for idx, alert in enumerate(filtered):
            sev   = alert.get("severity","LOW")
            color = SEVERITY_COLORS.get(sev,"#888")
            badge = {"CRITICAL":"🔴 CRITICAL","HIGH":"🟠 HIGH",
                     "MEDIUM":"🟡 MEDIUM","LOW":"🟢 LOW"}.get(sev, sev)

            enrich = alert.get("ip_enrichment",{})
            enrich_html = ""
            if enrich and not enrich.get("skipped") and not enrich.get("error"):
                enrich_html = (
                    f"<p style='font-size:12px;color:#aaa;margin:4px 0 0;'>"
                    f"🌐 <b>Threat Intel:</b> "
                    f"Abuse {enrich.get('abuse_confidence','?')}% | "
                    f"Level: {enrich.get('threat_level','?')} | "
                    f"Country: {enrich.get('country','?')} | "
                    f"ISP: {enrich.get('isp','?')}"
                    f"</p>"
                )

            escalated = ""
            if alert.get("severity_escalated"):
                escalated = f"<span style='color:{color};font-size:11px;'> ⬆ Escalated from {alert.get('severity_original','?')}</span>"

            st.markdown(
                f"""<div style="border-left:6px solid {color};padding:14px 18px;
                margin-bottom:10px;background:rgba(255,255,255,0.04);border-radius:10px;">
                <h4 style="margin:0 0 6px;">{badge} — {alert.get('rule','?')}{escalated}</h4>
                <p style="margin:2px 0;"><b>ID:</b> {alert.get('alert_id','?')} &nbsp;|&nbsp;
                   <b>Time:</b> {alert.get('timestamp','?')[:19]} &nbsp;|&nbsp;
                   <b>User:</b> {alert.get('username','N/A')} &nbsp;|&nbsp;
                   <b>IP:</b> {alert.get('ip_address','N/A')}</p>
                <p style="margin:4px 0;">{alert.get('description','N/A')}</p>
                {enrich_html}
                </div>""",
                unsafe_allow_html=True,
            )

            if alert.get("acknowledged"):
                st.success(f"✅ Acked by {alert.get('acknowledged_by','?')} at {alert.get('acknowledged_at','?')}")
            else:
                if st.button("✅ Acknowledge", key=f"ack_{alert.get('alert_id')}_{idx}"):
                    for i, a in enumerate(history):
                        if a.get("alert_id") == alert.get("alert_id"):
                            history[i].update({
                                "acknowledged":    True,
                                "acknowledged_by": st.session_state.username,
                                "acknowledged_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            })
                            break
                    save_json(ALERT_HISTORY_DB, history)
                    log_audit(st.session_state.username, "ALERT_ACKNOWLEDGED", alert.get("alert_id"))
                    st.rerun()
    else:
        st.info("No alerts yet. Run an analysis to generate alerts.")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3  —  ANALYTICS
# ══════════════════════════════════════════════════════════════════════════════
with tab3:
    st.header("📊 Security Analytics")
    
    # Use dashboard_data if available, else fall back to alert history
    df = st.session_state.get('dashboard_data', pd.DataFrame())
    history = load_json(ALERT_HISTORY_DB, [])

    if not df.empty:
        st.subheader("Log File Overview")
        st.dataframe(df.head(10))

        # Example: Log Type Distribution (if 'type' column exists)
        if 'type' in df.columns:
            type_count = df['type'].value_counts().reset_index()
            type_count.columns = ['Type', 'Count']
            fig1 = px.bar(type_count, x='Type', y='Count', title="Log Type Distribution", color='Count', color_continuous_scale='Blues')
            st.plotly_chart(fig1, use_container_width=True)

        # Example: Logs Over Time (if 'timestamp' column exists)
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            df_sorted = df.dropna(subset=['timestamp']).sort_values('timestamp')
            fig2 = px.line(df_sorted, x='timestamp', y='type' if 'type' in df_sorted.columns else df_sorted.columns[0],
                           title="Logs Over Time")
            st.plotly_chart(fig2, use_container_width=True)

    elif history:
        st.info("No uploaded log file, using alert history for analytics.")

        df_hist = pd.DataFrame(history)
        if 'severity' in df_hist.columns:
            sev_count = df_hist['severity'].value_counts().reset_index()
            sev_count.columns = ['Severity', 'Count']
            fig3 = px.pie(sev_count, names='Severity', values='Count', title="Severity Distribution", hole=0.3)
            st.plotly_chart(fig3, use_container_width=True)

    else:
        st.info("Run an analysis or upload a log file to see analytics.")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 4  —  RISK & ANOMALIES
# ══════════════════════════════════════════════════════════════════════════════
with tab4:
    st.header("🛡️ Risk & Anomalies")
    
    alerts = st.session_state.get('alerts_data', st.session_state.get('last_alerts', []))

    if alerts:
        df_alerts = pd.DataFrame(alerts)

        if 'risk_score' in df_alerts.columns:
            st.subheader("Risk Scores Distribution")
            fig_risk = px.histogram(df_alerts, x='risk_score', nbins=20, title="Risk Score Histogram")
            st.plotly_chart(fig_risk, use_container_width=True)

        if 'anomaly' in df_alerts.columns:
            anomaly_count = df_alerts['anomaly'].value_counts().reset_index()
            anomaly_count.columns = ['Anomaly', 'Count']
            st.subheader("Anomaly Types")
            fig_anom = px.bar(anomaly_count, x='Anomaly', y='Count', title="Detected Anomalies", color='Count', color_continuous_scale='Reds')
            st.plotly_chart(fig_anom, use_container_width=True)

        st.dataframe(df_alerts[['alert_id','severity','rule','risk_score','anomaly']].head(10))
    else:
        st.info("No alerts found — run an analysis to see Risk & Anomalies.")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 5  —  AUDIT LOG
# ══════════════════════════════════════════════════════════════════════════════
with tab5:
    st.header("📜 Security Audit Log")
    audit = load_json(AUDIT_LOG_FILE, [])

    if isinstance(audit, list) and audit:
        ac1, ac2 = st.columns(2)
        with ac1:
            f_user = st.multiselect("Filter by user",
                                    list(set(a.get("username","") for a in audit)))
        with ac2:
            f_action = st.multiselect("Filter by action",
                                      list(set(a.get("action","") for a in audit)))

        filtered_audit = audit
        if f_user:
            filtered_audit = [a for a in filtered_audit if a.get("username","") in f_user]
        if f_action:
            filtered_audit = [a for a in filtered_audit if a.get("action","") in f_action]

        st.markdown(f"**{len(filtered_audit)} entries**")
        audit_df = pd.DataFrame(filtered_audit)
        st.dataframe(audit_df, use_container_width=True)

        st.download_button("📥 Download CSV", audit_df.to_csv(index=False),
                           file_name=f"audit_{datetime.now().strftime('%Y%m%d')}.csv",
                           mime="text/csv")
    else:
        st.info("No audit entries yet.")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 6  —  SETTINGS
# ══════════════════════════════════════════════════════════════════════════════
with tab6:
    st.header("⚙️ System Settings")
    s1, s2, s3, s4 = st.tabs(["📧 Email Alerts", "👥 Users", "🔐 2FA", "🔧 System"])

    # ── Email ──────────────────────────────────────────────────────────────────
    with s1:
        st.subheader("Email Notification Configuration")

        if _NOTIF_OK:
            cur_cfg = load_smtp_config()

            # Show current credential source
            has_env_pw = bool(os.getenv("SMTP_PASSWORD"))
            has_json_pw = False
            try:
                raw = load_json(NOTIFICATION_CFG, [])
                entry = raw[0] if isinstance(raw, list) and raw else raw
                has_json_pw = bool(entry.get("smtp_password","")) if isinstance(entry, dict) else False
            except Exception:
                pass

            if has_env_pw:
                st.success("🔒 Password loaded from .env (secure)")
            elif has_json_pw:
                st.warning("⚠️ Password stored in notification_config.json — move to .env for security")
            else:
                st.error("❌ No SMTP password found. Enter one below.")

            st.markdown("**Routing:** CRITICAL & HIGH = immediate email | MEDIUM = hourly digest | LOW = daily digest")
            st.divider()

            email_on  = st.checkbox("Enable Email Notifications",
                                    value=cur_cfg.get("email_enabled", False))
            smtp_host = st.text_input("SMTP Server", value=cur_cfg.get("smtp_server","smtp.gmail.com"))
            smtp_port = st.number_input("SMTP Port", value=int(cur_cfg.get("smtp_port", 587)), step=1)
            smtp_user = st.text_input("SMTP Username (your Gmail)",
                                      value=cur_cfg.get("smtp_user",""))
            smtp_pass = st.text_input(
                "SMTP Password (Gmail App Password)",
                type="password",
                value="",
                help="For Gmail: Google Account → Security → 2-Step Verification → App passwords"
            )
            recipient = st.text_input("Alert Recipient Email",
                                      value=cur_cfg.get("recipient", cur_cfg.get("smtp_user","")))

            c_save, c_test, c_hourly, c_daily = st.columns(4)

            with c_save:
                if st.button("💾 Save Config"):
                    new_entry = {
                        "email_enabled": email_on,
                        "smtp_server":   smtp_host,
                        "smtp_port":     int(smtp_port),
                        "smtp_user":     smtp_user,
                        "recipient":     recipient,
                    }
                    if smtp_pass:
                        new_entry["smtp_password"] = smtp_pass
                    save_json(NOTIFICATION_CFG, [new_entry])
                    log_audit(st.session_state.username, "CONFIG_UPDATED", "Email notifications")
                    st.success("Saved!")

            with c_test:
                if st.button("📨 Test Email"):
                    # If user just typed a password, apply it temporarily
                    if smtp_pass:
                        os.environ["SMTP_PASSWORD"] = smtp_pass
                    if smtp_user:
                        os.environ["SMTP_USER"]     = smtp_user
                    if recipient:
                        os.environ["ALERT_RECIPIENT"] = recipient
                    notifier = NotificationEngine()
                    ok, msg = notifier.send_test_email()
                    if ok:
                        st.success(msg)
                    else:
                        st.error(msg)

            with c_hourly:
                if st.button("📤 Send Hourly Digest"):
                    notifier = NotificationEngine()
                    ok, msg = notifier.flush_digest("hourly")
                    st.success(msg) if ok else st.warning(msg)

            with c_daily:
                if st.button("📤 Send Daily Digest"):
                    notifier = NotificationEngine()
                    ok, msg = notifier.flush_digest("daily")
                    st.success(msg) if ok else st.warning(msg)

            # Gmail App Password help
            with st.expander("ℹ️ How to create a Gmail App Password"):
                st.markdown("""
1. Go to **myaccount.google.com**
2. Click **Security** in the left sidebar
3. Enable **2-Step Verification** if not already on
4. Search for **App passwords** or go to: myaccount.google.com/apppasswords
5. App name: `SIEMSecure` → click **Create**
6. Copy the 16-character password → paste above as SMTP Password
7. Click **Save Config** then **Test Email**
                """)
        else:
            st.error("NotificationEngine not available. Check that `core/notification_engine.py` exists.")
            st.code("Expected: <project_root>/core/notification_engine.py")

    # ── Users ──────────────────────────────────────────────────────────────────
    with s2:
        if st.session_state.role == "Admin":
            st.subheader("User Management")
            users = load_users()
            if users:
                u_df = pd.DataFrame([{
                    "Username":   u,
                    "Role":       d["role"],
                    "Email":      d.get("email","—"),
                    "2FA":        "✅" if d.get("two_fa_enabled") else "—",
                    "Last Login": (d.get("last_login","Never")[:19] if d.get("last_login") else "Never"),
                    "Status":     "🔒 Locked" if d.get("locked_until",0) > time.time() else "✅ Active",
                } for u, d in users.items()])
                st.dataframe(u_df, use_container_width=True)

                du1, du2 = st.columns(2)
                with du1:
                    del_user = st.selectbox("Delete user", list(users.keys()))
                    if st.button("🗑️ Delete"):
                        if del_user == st.session_state.username:
                            st.error("Cannot delete your own account.")
                        else:
                            del users[del_user]
                            save_users(users)
                            if _TOTP_OK:
                                TOTPManager().remove_user(del_user)
                            log_audit(st.session_state.username, "USER_DELETED", del_user)
                            st.success(f"Deleted {del_user}")
                            st.rerun()
                with du2:
                    locked = [u for u, d in users.items() if d.get("locked_until",0) > time.time()]
                    if locked:
                        unlock_user = st.selectbox("Unlock account", locked)
                        if st.button("🔓 Unlock"):
                            users[unlock_user]["locked_until"]    = 0
                            users[unlock_user]["failed_attempts"] = 0
                            save_users(users)
                            log_audit(st.session_state.username, "ACCOUNT_UNLOCKED", unlock_user)
                            st.success(f"Unlocked {unlock_user}")
                            st.rerun()
        else:
            st.warning("Admin access required.")

    # ── 2FA ────────────────────────────────────────────────────────────────────
    with s3:
        st.subheader("Two-Factor Authentication")
        if not _TOTP_OK:
            st.error("pyotp not installed. Run: `pip install pyotp qrcode[pil]`")
        else:
            totp_mgr = TOTPManager()
            cur      = st.session_state.username
            users    = load_users()
            has_2fa  = totp_mgr.has_2fa(cur)

            if has_2fa:
                st.success(f"✅ 2FA enabled for **{cur}**")
                fa1, fa2 = st.columns(2)
                with fa1:
                    if st.button("♻️ Regenerate"):
                        secret, _ = totp_mgr.setup_user(cur, users.get(cur,{}).get("email",""))
                        users[cur]["two_fa_enabled"] = True
                        save_users(users)
                        qr = totp_mgr.get_qr_as_base64(cur)
                        if qr:
                            st.image(f"data:image/png;base64,{qr}", caption="Scan with authenticator app")
                        st.code(f"Manual key: {secret}")
                with fa2:
                    if st.button("🗑️ Disable 2FA"):
                        totp_mgr.remove_user(cur)
                        users[cur]["two_fa_enabled"] = False
                        save_users(users)
                        st.success("2FA disabled.")
                        st.rerun()
            else:
                st.info("2FA is not enabled for your account.")
                if st.button("🔐 Enable 2FA"):
                    secret, _ = totp_mgr.setup_user(cur, users.get(cur,{}).get("email",""))
                    if secret:
                        users[cur]["two_fa_enabled"] = True
                        save_users(users)
                        qr = totp_mgr.get_qr_as_base64(cur)
                        if qr:
                            st.image(f"data:image/png;base64,{qr}", caption="Scan with Google Authenticator / Authy")
                        st.code(f"Manual key: {secret}")
                        st.success("2FA enabled! Scan the QR, log out, and log back in to test.")
                        log_audit(cur, "2FA_ENABLED")

    # ── System ─────────────────────────────────────────────────────────────────
    with s4:
        st.subheader("Module Status")
        status_rows = [
            ("SIEMFramework",          _SIEM_OK,    "main.py in project root"),
            ("NotificationEngine",     _NOTIF_OK,   "core/notification_engine.py"),
            ("IPEnrichmentEngine",     _ENRICH_OK,  "core/ip_enrichment.py + ABUSEIPDB_API_KEY in .env"),
            ("RiskEngine",             _RISK_OK,    "core/risk_engine.py"),
            ("TOTPManager",            _TOTP_OK,    "core/totp_manager.py + pip install pyotp qrcode[pil]"),
            ("SyslogCollector",        _SYSLOG_OK,  "core/syslog_collector.py"),
            ("WindowsEventCollector",  _WINEVENT_OK,"core/windows_event_collector.py"),
        ]
        for name, ok, note in status_rows:
            icon = "✅" if ok else "❌"
            st.markdown(f"{icon} **{name}** {'— ' + note if not ok else ''}")

        st.divider()
        st.subheader("Syslog Listener")
        if _SYSLOG_OK:
            sc = st.session_state.syslog_collector
            if sc and sc.get_status()["running"]:
                status = sc.get_status()
                st.success(f"Running on {status['protocol']}:{status['port']} | {status['buffered']} buffered messages")
                if st.button("⏹ Stop Listener"):
                    sc.stop()
                    st.session_state.syslog_collector = None
                    st.rerun()
            else:
                sys_port  = st.number_input("Port", value=514, key="sys_sl_port")
                sys_proto = st.selectbox("Protocol", ["UDP","TCP"], key="sys_sl_proto")
                if st.button("▶ Start Syslog Listener"):
                    new_sc = SyslogCollector(port=int(sys_port), protocol=sys_proto.lower())
                    new_sc.start_background()
                    st.session_state.syslog_collector = new_sc
                    log_audit(st.session_state.username, "SYSLOG_STARTED", f"{sys_proto}:{sys_port}")
                    st.success(f"Started on {sys_proto}:{int(sys_port)}")
                    st.rerun()
        else:
            st.warning("core/syslog_collector.py not found.")

        st.divider()
        st.subheader("Windows Event Log")
        if _WINEVENT_OK:
            wc = WindowsEventCollector()
            ws = wc.get_status()
            st.write(f"Local (pywin32): {'✅' if ws['local_available'] else '❌ — run on Windows + pip install pywin32'}")
            st.write(f"Remote (SSH):    {'✅' if ws['remote_available'] else '❌ — pip install paramiko'}")
        else:
            st.warning("core/windows_event_collector.py not found.")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 7  —  LIVE MONITOR
# ══════════════════════════════════════════════════════════════════════════════
with tab7:
    st.header("📡 Live Monitor")
    history = load_json(ALERT_HISTORY_DB, [])

    if isinstance(history, list) and history:
        recent = sorted(history, key=lambda a: a.get("timestamp",""), reverse=True)[:15]
        st.markdown("**Latest 15 alerts** (newest first):")
        for a in recent:
            sev   = a.get("severity","LOW")
            color = SEVERITY_COLORS.get(sev,"#888")
            ack   = "✅" if a.get("acknowledged") else "🔔"
            st.markdown(
                f'<div style="display:flex;align-items:center;gap:12px;padding:8px 14px;'
                f'margin-bottom:5px;background:rgba(255,255,255,0.04);border-radius:8px;'
                f'border-left:4px solid {color};">'
                f'<span style="font-size:16px;">{ack}</span>'
                f'<span style="color:{color};font-weight:bold;min-width:90px;">{sev}</span>'
                f'<span style="min-width:220px;">{a.get("rule","?")}</span>'
                f'<span style="color:#aaa;font-size:12px;min-width:140px;">{a.get("timestamp","?")[:19]}</span>'
                f'<span style="color:#aaa;font-size:12px;margin-left:auto;">{a.get("ip_address","?")}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )

        sc = st.session_state.syslog_collector
        if sc:
            st.divider()
            status = sc.get_status()
            st.info(f"📡 Syslog listener active on {status['protocol']}:{status['port']} "
                    f"— {status['buffered']} messages buffered. "
                    f"Switch to **Syslog Listener** mode and click **Run Analysis** to process them.")
    else:
        st.info("No alert history. Run an analysis to start monitoring.")

# Footer
st.markdown("<br>", unsafe_allow_html=True)
st.markdown(
    "<div style='text-align:center;opacity:0.45;font-size:11px;padding:12px;'>"
    "SIEMSecure Pro v3.1 &nbsp;·&nbsp; Advanced SIEM &nbsp;·&nbsp; AI-Driven Threat Intelligence"
    "</div>",
    unsafe_allow_html=True,
)