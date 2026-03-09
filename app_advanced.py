# app.py - Advanced SIEM Dashboard (FIXED VERSION)
import streamlit as st
import pandas as pd
import os
import sys
import paramiko
import json
import hashlib
import re
import time
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests

# Add SIEM project path
sys.path.append(os.path.abspath("."))

# Import SIEM Framework - FIXED
try:
    from SIEM_Hybrid_Framework.main import SIEMFramework
except ImportError:
    try:
        from main import SIEMFramework
    except ImportError:
        st.error("⚠️ Could not import SIEMFramework. Make sure SIEM_Hybrid_Framework folder is in the same directory as this app.")
        st.stop()

# -----------------------------
# ADVANCED CONFIG
# -----------------------------
st.set_page_config(
    page_title="SIEMSecure", 
    page_icon="🔐", 
    layout="wide",
    initial_sidebar_state="expanded"
)

USER_DB = "users.json"
ALERT_HISTORY_DB = "alert_history.json"
NOTIFICATION_CONFIG = "notification_config.json"
AUDIT_LOG = "audit_log.json"
MAX_ATTEMPTS = 3
LOCK_TIME = 60

# Severity color mapping
SEVERITY_COLORS = {
    "CRITICAL": "#FF0000",
    "HIGH": "#FF6B00",
    "MEDIUM": "#FFA500",
    "LOW": "#00FF00"
}

# -----------------------------
# CUSTOM CSS - ADVANCED THEMES
# -----------------------------
def apply_advanced_theme(theme):
    """Apply advanced glassmorphism and modern UI themes"""
    
    if theme == "Dark Pro":
        bg = "linear-gradient(135deg, #0F2027 0%, #203A43 50%, #2C5364 100%)"
        sidebar = "#1a1a2e"
        text = "#FFFFFF"
        card = "rgba(31, 41, 55, 0.8)"
        accent = "#00D9FF"
    elif theme == "Cyber Blue":
        bg = "linear-gradient(135deg, #667eea 0%, #764ba2 100%)"
        sidebar = "#1e1e3f"
        text = "#FFFFFF"
        card = "rgba(30, 30, 63, 0.8)"
        accent = "#00FFFF"
    elif theme == "Matrix":
        bg = "linear-gradient(135deg, #000000 0%, #0a0e27 100%)"
        sidebar = "#0a0a0a"
        text = "#00FF41"
        card = "rgba(10, 10, 10, 0.9)"
        accent = "#00FF41"
    elif theme == "Sunset":
        bg = "linear-gradient(135deg, #FF512F 0%, #DD2476 50%, #F46B45 100%)"
        sidebar = "#2d132c"
        text = "#FFFFFF"
        card = "rgba(45, 19, 44, 0.8)"
        accent = "#FFD700"
    else:  # Light Pro
        bg = "linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%)"
        sidebar = "#ffffff"
        text = "#2d3748"
        card = "rgba(255, 255, 255, 0.9)"
        accent = "#4299e1"

    st.markdown(
        f"""
        <style>
        /* Main background with gradient */
        .stApp {{
            background: {bg};
            color: {text};
        }}

        /* Glassmorphism sidebar */
        section[data-testid="stSidebar"] {{
            background: {card};
            backdrop-filter: blur(10px);
            border-right: 1px solid rgba(255, 255, 255, 0.1);
        }}

        /* Modern cards with glassmorphism */
        div[data-testid="metric-container"] {{
            background: {card};
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
            transition: transform 0.3s ease;
        }}

        div[data-testid="metric-container"]:hover {{
            transform: translateY(-5px);
            box-shadow: 0 12px 40px 0 rgba(31, 38, 135, 0.5);
        }}

        /* Animated buttons */
        .stButton > button {{
            background: linear-gradient(45deg, {accent}, {accent}AA);
            color: white;
            border: none;
            border-radius: 25px;
            padding: 10px 30px;
            font-weight: bold;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px 0 rgba(0, 0, 0, 0.2);
        }}

        .stButton > button:hover {{
            transform: scale(1.05);
            box-shadow: 0 6px 20px 0 rgba(0, 0, 0, 0.3);
        }}

        /* Input fields */
        input, textarea, select {{
            background: rgba(255, 255, 255, 0.1) !important;
            border: 1px solid rgba(255, 255, 255, 0.2) !important;
            border-radius: 10px !important;
            color: {text} !important;
        }}

        /* Headers with gradient text */
        h1, h2, h3 {{
            background: linear-gradient(45deg, {accent}, {accent}AA);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: bold;
        }}

        /* DataFrames */
        .stDataFrame {{
            background: {card};
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 10px;
        }}

        /* Tabs */
        .stTabs [data-baseweb="tab-list"] {{
            gap: 10px;
        }}

        .stTabs [data-baseweb="tab"] {{
            background: {card};
            border-radius: 10px;
            padding: 10px 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}

        /* Progress bars */
        .stProgress > div > div > div > div {{
            background: linear-gradient(45deg, {accent}, {accent}AA);
        }}

        /* Animated loading */
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.5; }}
        }}

        .stSpinner > div {{
            border-color: {accent} !important;
            animation: pulse 1.5s ease-in-out infinite;
        }}

        </style>
        """,
        unsafe_allow_html=True
    )


# -----------------------------
# UTILITY FUNCTIONS
# -----------------------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def load_users():
    if not os.path.exists(USER_DB):
        return {}
    try:
        with open(USER_DB, "r") as f:
            return json.load(f)
    except:
        return {}


def save_users(users):
    with open(USER_DB, "w") as f:
        json.dump(users, f, indent=4)


def log_audit(username, action, details=""):
    """Log user actions for audit trail"""
    audit_data = load_json_db(AUDIT_LOG)
    
    audit_data.append({
        "timestamp": datetime.now().isoformat(),
        "username": username,
        "action": action,
        "details": details,
        "ip_address": "127.0.0.1"
    })
    
    save_json_db(AUDIT_LOG, audit_data)


def load_json_db(filepath):
    """Generic JSON database loader"""
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except:
        return []


def save_json_db(filepath, data):
    """Generic JSON database saver"""
    with open(filepath, "w") as f:
        json.dump(data, f, indent=4)


def is_strong_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain lowercase letter"
    if not re.search(r"[0-9]", password):
        return False, "Password must contain digit"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain special character"
    return True, "Strong password"


def authenticate(username, password):
    users = load_users()

    if username not in users:
        log_audit(username, "LOGIN_FAILED", "User does not exist")
        return "no_user"

    user = users[username]

    if user["locked_until"] > time.time():
        log_audit(username, "LOGIN_BLOCKED", "Account locked")
        return "locked"

    if user["password"] != hash_password(password):
        user["failed_attempts"] += 1

        if user["failed_attempts"] >= MAX_ATTEMPTS:
            user["locked_until"] = time.time() + LOCK_TIME
            save_users(users)
            log_audit(username, "ACCOUNT_LOCKED", f"{MAX_ATTEMPTS} failed attempts")
            return "locked"

        save_users(users)
        log_audit(username, "LOGIN_FAILED", f"Wrong password (attempt {user['failed_attempts']})")
        return "wrong_password"

    user["failed_attempts"] = 0
    user["locked_until"] = 0
    user["last_login"] = datetime.now().isoformat()
    save_users(users)
    log_audit(username, "LOGIN_SUCCESS", "Successful login")
    return "success"


def register_user(username, password, role, email=""):
    users = load_users()

    if username in users:
        return "exists", "Username already exists"

    is_strong, message = is_strong_password(password)
    if not is_strong:
        return "weak", message

    users[username] = {
        "password": hash_password(password),
        "role": role,
        "email": email,
        "failed_attempts": 0,
        "locked_until": 0,
        "created_at": datetime.now().isoformat(),
        "last_login": None
    }

    save_users(users)
    log_audit(username, "USER_REGISTERED", f"New {role} registered")
    return "success", "Registration successful"


def send_email_alert(to_email, subject, body):
    """Send email notification for critical alerts"""
    try:
        config = load_json_db(NOTIFICATION_CONFIG)
        if not config or not config[0].get("email_enabled"):
            return False
        
        smtp_config = config[0]
        
        msg = MIMEMultipart()
        msg['From'] = smtp_config.get("smtp_user")
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP(smtp_config.get("smtp_server"), smtp_config.get("smtp_port"))
        server.starttls()
        server.login(smtp_config.get("smtp_user"), smtp_config.get("smtp_password"))
        server.send_message(msg)
        server.quit()
        
        return True
    except Exception as e:
        st.warning(f"Email notification failed: {e}")
        return False


def save_alert_to_history(alert):
    """Save alert to historical database"""
    history = load_json_db(ALERT_HISTORY_DB)
    alert["saved_at"] = datetime.now().isoformat()
    alert["acknowledged"] = False
    alert["acknowledged_by"] = None
    history.append(alert)
    save_json_db(ALERT_HISTORY_DB, history)


# -----------------------------
# SESSION STATE INITIALIZATION
# -----------------------------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "username" not in st.session_state:
    st.session_state.username = None
if "role" not in st.session_state:
    st.session_state.role = None
if "alerts_data" not in st.session_state:
    st.session_state.alerts_data = []
if "stats_data" not in st.session_state:
    st.session_state.stats_data = {}
if "last_analysis_time" not in st.session_state:
    st.session_state.last_analysis_time = None


# -----------------------------
# SIDEBAR THEME SELECTOR
# -----------------------------
st.sidebar.title("🎨 UI Control")
theme = st.sidebar.selectbox(
    "Choose Theme",
    ["Light Pro", "Dark Pro", "Cyber Blue", "Matrix", "Sunset"]
)
apply_advanced_theme(theme)


# -----------------------------
# LOGIN PAGE WITH ENHANCED UI
# -----------------------------
if not st.session_state.authenticated:
    
    # Center login form with custom styling
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("<h1 style='text-align: center;'>🔐 SIEMSecure</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; opacity: 0.8;'>Advanced Security Information & Event Management</p>", unsafe_allow_html=True)
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        menu = st.radio("", ["🔑 Login", "📝 Register"], horizontal=True)

        username = st.text_input("👤 Username", placeholder="Enter your username")
        password = st.text_input("🔒 Password", type="password", placeholder="Enter your password")

        if menu == "🔑 Login":
            col_a, col_b, col_c = st.columns([1, 2, 1])
            with col_b:
                if st.button("Login", use_container_width=True):
                    if not username or not password:
                        st.error("Please enter both username and password")
                    else:
                        result = authenticate(username, password)

                        if result == "success":
                            users = load_users()
                            st.session_state.authenticated = True
                            st.session_state.username = username
                            st.session_state.role = users[username]["role"]
                            st.success("✅ Login successful!")
                            time.sleep(0.5)
                            st.rerun()
                        elif result == "no_user":
                            st.error("❌ User does not exist.")
                        elif result == "wrong_password":
                            st.error("❌ Incorrect password.")
                        elif result == "locked":
                            st.error(f"🔒 Account locked for {LOCK_TIME} seconds. Too many failed attempts.")

        else:  # Register
            email = st.text_input("📧 Email", placeholder="your@email.com")
            role = st.selectbox("👥 Role", ["Analyst", "Admin"])

            col_a, col_b, col_c = st.columns([1, 2, 1])
            with col_b:
                if st.button("Register", use_container_width=True):
                    if not username or not password:
                        st.error("Please fill in all fields")
                    else:
                        result, message = register_user(username, password, role, email)

                        if result == "success":
                            st.success(f"✅ {message}. Please login now.")
                        else:
                            st.error(f"❌ {message}")

    st.stop()


# -----------------------------
# MAIN DASHBOARD - ENHANCED
# -----------------------------
st.markdown(f"""
    <div style='background: rgba(255,255,255,0.1); padding: 20px; border-radius: 15px; margin-bottom: 20px; backdrop-filter: blur(10px);'>
        <h1 style='margin: 0;'>🔒 SIEM Command Center</h1>
        <p style='margin: 5px 0 0 0; opacity: 0.8;'>Welcome, <strong>{st.session_state.username}</strong> ({st.session_state.role})</p>
    </div>
""", unsafe_allow_html=True)

# Logout button in sidebar
if st.sidebar.button("🚪 Logout", use_container_width=True):
    log_audit(st.session_state.username, "LOGOUT", "User logged out")
    st.session_state.authenticated = False
    st.rerun()

if "alerts_data" not in st.session_state:
    st.session_state.alerts_data = []

if "stats_data" not in st.session_state:
    st.session_state.stats_data = {}

if "last_analysis_time" not in st.session_state:
    st.session_state.last_analysis_time = None

# -----------------------------
# MAIN TABS
# -----------------------------
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📊 Dashboard", 
    "🔍 Analysis", 
    "📈 Statistics", 
    "🚨 Alerts",
    "⚙️ Settings",
    "📜 Audit Log"
])

# TAB 1: DASHBOARD OVERVIEW
with tab1:
    st.header("Real-Time Security Overview")
    
    # Top metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_alerts = len(st.session_state.alerts_data)
        critical_alerts = len([a for a in st.session_state.alerts_data if a.get('severity') == 'CRITICAL'])
        st.metric(
            "Total Alerts",
            total_alerts,
            delta=f"+{critical_alerts} Critical" if critical_alerts > 0 else "0 Critical"
        )
    
    with col2:
        st.metric("Critical Threats", critical_alerts)
    
    with col3:
        status = "🟢 Active" if st.session_state.alerts_data else "⚪ Idle"
        st.metric("System Status", status)
    
    with col4:
        last_scan = st.session_state.last_analysis_time if st.session_state.last_analysis_time else "Never"
        st.metric("Last Scan", last_scan)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Quick stats visualization
    if st.session_state.alerts_data:
        col_a, col_b = st.columns(2)
        
        with col_a:
            # Severity distribution pie chart
            df_alerts = pd.DataFrame(st.session_state.alerts_data)
            if "severity" in df_alerts.columns:
                severity_counts = df_alerts["severity"].value_counts()
                
                fig = go.Figure(data=[go.Pie(
                    labels=severity_counts.index,
                    values=severity_counts.values,
                    hole=.3,
                    marker=dict(colors=[SEVERITY_COLORS.get(s, "#888888") for s in severity_counts.index])
                )])
                fig.update_layout(
                    title="Alert Severity Distribution",
                    template="plotly_dark" if "Dark" in theme or "Matrix" in theme else "plotly_white"
                )
                st.plotly_chart(fig, use_container_width=True)
        
        with col_b:
            # Rule distribution
            if "rule" in df_alerts.columns:
                rule_counts = df_alerts["rule"].value_counts().head(10)
                
                fig2 = go.Figure(data=[go.Bar(
                    x=rule_counts.values,
                    y=rule_counts.index,
                    orientation='h',
                    marker=dict(color='#00D9FF')
                )])
                fig2.update_layout(
                    title="Top Alert Rules",
                    xaxis_title="Count",
                    yaxis_title="Rule",
                    template="plotly_dark" if "Dark" in theme or "Matrix" in theme else "plotly_white"
                )
                st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("📊 Run an analysis in the 'Analysis' tab to see dashboard metrics.")

def fetch_remote_logs(server, username, password, remote_path="/var/log/auth.log"):
    """
    Connects to remote server via SSH and fetch log file.
    """
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(server, username=username, password=password, timeout=10)

        stdin, stdout, stderr = ssh.exec_command(f"cat {remote_path}")
        logs = stdout.read().decode()
        ssh.close()

        if not logs:
            raise Exception("No logs returned from remote server.")

        return logs.splitlines()

    except Exception as e:
        raise Exception(f"Remote connection failed: {e}")

# =========================
# TAB 2: ANALYSIS (UPDATED & STABLE)
# =========================
with tab2:
    st.header("🔍 Security Analysis Engine")

    # -----------------------
    # INITIALIZE SESSION STATE
    # -----------------------
    if "analysis_triggered" not in st.session_state:
        st.session_state.analysis_triggered = False
    if "alerts_data" not in st.session_state:
        st.session_state.alerts_data = []
    if "stats_data" not in st.session_state:
        st.session_state.stats_data = {}
    if "last_analysis_time" not in st.session_state:
        st.session_state.last_analysis_time = None

    # -----------------------
    # MODE SELECTION
    # -----------------------
    col1, col2 = st.columns([2, 1])
    with col1:
        mode = st.radio(
            "Analysis Mode",
            ["🧪 Test Mode (Local Logs)", "🔴 Live Mode (Remote)"],
            horizontal=True
        )
    st.markdown("<br>", unsafe_allow_html=True)

    # -----------------------
    # TEST MODE (LOCAL FILE)
    # -----------------------
    if "Test" in mode:
        siem_folder_exists = os.path.exists("SIEM_Hybrid_Framework")
        default_path = "SIEM_Hybrid_Framework/logs/logs.txt" if siem_folder_exists else "logs/logs1.txt"

        log_file_path = st.text_input(
            "📁 Log File Path",
            value=default_path,
            help="Path to your log file"
        )

        if log_file_path:
            if os.path.exists(log_file_path):
                st.success(f"✅ File found: {log_file_path}")
                with st.expander("👁️ Preview Log File (first 10 lines)"):
                    try:
                        with open(log_file_path, "r") as f:
                            lines = f.readlines()[:10]
                            st.code("".join(lines))
                    except Exception as e:
                        st.error(f"Error reading file: {e}")
            else:
                st.error(f"❌ File not found: {log_file_path}")

        remote_server = remote_user = remote_pass = None

    # -----------------------
    # LIVE MODE (REMOTE SERVER DEMO)
    # -----------------------
    else:
        log_file_path = None
        col_a, col_b, col_c = st.columns(3)
        with col_a:
            remote_server = st.text_input("🌐 Remote Server (IP Address)")
        with col_b:
            remote_user = st.text_input("👤 Username")
        with col_c:
            remote_pass = st.text_input("🔒 Password", type="password")

    st.markdown("<br>", unsafe_allow_html=True)

    # -----------------------
    # RUN BUTTON
    # -----------------------
    run_col1, run_col2, run_col3 = st.columns([1, 2, 1])
    with run_col2:
        if st.button("▶️ Run Analysis", use_container_width=True, type="primary"):
            st.session_state.analysis_triggered = True

    # -----------------------
    # RUN ANALYSIS
    # -----------------------
    if st.session_state.analysis_triggered:
        try:
            with st.spinner("🔄 Running SIEM Analysis..."):
                progress_bar = st.progress(0)
                status_text = st.empty()

                # -----------------------
                # INITIALIZE SIEM
                # -----------------------
                status_text.text("🔧 Initializing SIEM Framework...")
                progress_bar.progress(15)
                time.sleep(0.3)

                if "Test" in mode:
                    if not os.path.exists(log_file_path):
                        st.error(f"❌ Log file not found: {log_file_path}")
                        st.stop()
                    siem = SIEMFramework(log_file_path=log_file_path)
                else:
                    # -----------------------
                    # LIVE MODE DEMO (NO SERVER)
                    # -----------------------
                    status_text.text("🌐 Simulating Live Mode (Demo)...")
                    progress_bar.progress(25)
                    time.sleep(0.5)

                    temp_demo_file = "live_demo_empty.txt"
                    with open(temp_demo_file, "w") as f:
                        f.write("")  # zero logs

                    siem = SIEMFramework(log_file_path=temp_demo_file)
                    siem.parsed_logs = []
                    siem.alerts = []
                    siem.statistics = {
                        'general_stats': {
                            'total_events': 0,
                            'unique_ips': 0,
                            'unique_users': 0,
                            'failed_logins': 0,
                            'successful_logins': 0,
                            'event_type_breakdown': {}
                        },
                        'attack_breakdown': {},
                        'top_attackers': []
                    }

                # -----------------------
                # RUN ANALYSIS
                # -----------------------
                status_text.text("📊 Analyzing logs...")
                progress_bar.progress(40)
                time.sleep(0.3)
                siem.run_analysis()
                progress_bar.progress(70)
                status_text.text("🔍 Processing detections...")
                time.sleep(0.3)

                # -----------------------
                # STORE RESULTS
                # -----------------------
                st.session_state.alerts_data = siem.alerts.copy()
                st.session_state.stats_data = siem.statistics.copy()
                st.session_state.last_analysis_time = datetime.now().strftime("%H:%M:%S")

                progress_bar.progress(85)

                # Save to history (empty in demo)
                for alert in siem.alerts:
                    save_alert_to_history(alert)

                # Email critical alerts (empty in demo)
                critical_alerts = [a for a in siem.alerts if a.get("severity") == "CRITICAL"]
                if critical_alerts:
                    users = load_users()
                    user_email = users.get(st.session_state.username, {}).get("email")
                    if user_email:
                        send_email_alert(
                            user_email,
                            f"🚨 {len(critical_alerts)} Critical Alerts",
                            f"<h2>{len(critical_alerts)} Critical Alerts Detected</h2>"
                        )

                progress_bar.progress(100)
                status_text.text("✅ Analysis complete!")

                log_audit(
                    st.session_state.username,
                    "ANALYSIS_RUN",
                    f"Mode: {mode}, Alerts: {len(siem.alerts)}"
                )

                # -----------------------
                # SUCCESS SUMMARY
                # -----------------------
                st.success(
                    f"✅ Analysis complete! "
                    f"**{len(siem.alerts)} alerts** generated from "
                    f"**{len(siem.parsed_logs)} logs**."
                )

                st.markdown("### 📊 Quick Summary")
                c1, c2, c3, c4 = st.columns(4)
                with c1:
                    st.metric("Total Logs", len(st.session_state.alerts_data) if st.session_state.stats_data=={} else len(siem.parsed_logs))
                with c2:
                    st.metric("Total Alerts", len(st.session_state.alerts_data))
                with c3:
                    st.metric(
                        "Critical",
                        len([a for a in st.session_state.alerts_data if a.get("severity") == "CRITICAL"])
                    )
                with c4:
                    st.metric(
                        "High",
                        len([a for a in st.session_state.alerts_data if a.get("severity") == "HIGH"])
                    )

                # Preview
                if st.session_state.alerts_data:
                    st.markdown("### 🚨 Alert Preview")
                    preview_df = pd.DataFrame(st.session_state.alerts_data[:5])
                    st.dataframe(
                        preview_df[["alert_id", "severity", "rule", "description"]],
                        use_container_width=True
                    )

                st.info("💡 View complete results in the **Dashboard** and **Statistics** tabs!")

        except FileNotFoundError as e:
            st.error(f"❌ File not found: {e}")

        except Exception as e:
            st.error(f"❌ Analysis failed: {e}")
            log_audit(
                st.session_state.username,
                "ANALYSIS_FAILED",
                str(e)
            )
            with st.expander("🔍 View Error Details"):
                import traceback
                st.code(traceback.format_exc())

# TAB 3: STATISTICS (Enhanced)
with tab3:
    st.header("📈 Advanced Security Statistics")
    
    if st.session_state.stats_data and 'general_stats' in st.session_state.stats_data:
        stats = st.session_state.stats_data
        
        # Multi-column metrics
        st.subheader("📊 General Statistics")
        col1, col2, col3, col4, col5 = st.columns(5)
        
        general_stats = stats.get('general_stats', {})
        
        with col1:
            st.metric("Total Events", general_stats.get('total_events', 0))
        with col2:
            st.metric("Unique IPs", general_stats.get('unique_ips', 0))
        with col3:
            st.metric("Unique Users", general_stats.get('unique_users', 0))
        with col4:
            st.metric("Failed Logins", general_stats.get('failed_logins', 0))
        with col5:
            st.metric("Successful Logins", general_stats.get('successful_logins', 0))
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Attack breakdown
        if 'attack_breakdown' in stats and stats['attack_breakdown']:
            st.subheader("🎯 Attack Type Breakdown")
            attack_df = pd.DataFrame(list(stats['attack_breakdown'].items()), columns=['Attack Type', 'Count'])
            attack_df = attack_df.sort_values('Count', ascending=False)
            
            fig = px.bar(
                attack_df,
                x='Attack Type',
                y='Count',
                title="Attack Types Detected",
                color='Count',
                color_continuous_scale='Reds'
            )
            fig.update_layout(
                template="plotly_dark" if "Dark" in theme or "Matrix" in theme else "plotly_white"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Top attackers
        if 'top_attackers' in stats and stats['top_attackers']:
            st.subheader("🎯 Top Attacking IPs")
            attackers_df = pd.DataFrame(stats['top_attackers'])
            st.dataframe(attackers_df, use_container_width=True)
        
        # Event type breakdown
        if 'event_type_breakdown' in general_stats:
            st.subheader("📋 Event Type Distribution")
            event_df = pd.DataFrame(list(general_stats['event_type_breakdown'].items()), 
                                   columns=['Event Type', 'Count'])
            
            fig2 = px.pie(
                event_df,
                values='Count',
                names='Event Type',
                title="Event Type Distribution"
            )
            fig2.update_layout(
                template="plotly_dark" if "Dark" in theme or "Matrix" in theme else "plotly_white"
            )
            st.plotly_chart(fig2, use_container_width=True)
        
    else:
        st.info("📊 Run an analysis in the 'Analysis' tab to view statistics.")

# =========================
# TAB 4: ALERTS MANAGEMENT (FIXED VERSION)
# =========================
with tab4:
    st.header("🚨 Alert Management Center")

    # -----------------------
    # FILTERS
    # -----------------------
    col1, col2, col3 = st.columns(3)

    with col1:
        filter_severity = st.multiselect(
            "Severity",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        )

    with col2:
        filter_status = st.selectbox(
            "Status",
            ["All", "Acknowledged", "Unacknowledged"]
        )

    with col3:
        filter_timerange = st.selectbox(
            "Time Range",
            ["Last Hour", "Last 24 Hours", "Last 7 Days", "All Time"]
        )

    # -----------------------
    # LOAD ALERT HISTORY
    # -----------------------
    alert_history = load_json_db(ALERT_HISTORY_DB)

    if alert_history:

        filtered_alerts = alert_history.copy()

        # -----------------------
        # APPLY FILTERS
        # -----------------------

        # Severity filter
        filtered_alerts = [
            a for a in filtered_alerts
            if a.get("severity") in filter_severity
        ]

        # Status filter
        if filter_status == "Acknowledged":
            filtered_alerts = [
                a for a in filtered_alerts
                if a.get("acknowledged")
            ]

        elif filter_status == "Unacknowledged":
            filtered_alerts = [
                a for a in filtered_alerts
                if not a.get("acknowledged")
            ]

        st.markdown(f"**Showing {len(filtered_alerts)} alerts**")

        # -----------------------
        # DISPLAY ALERTS
        # -----------------------
        for idx, alert in enumerate(filtered_alerts):

            severity = alert.get("severity", "LOW")

            if severity == "CRITICAL":
                badge = "🔴 CRITICAL"
                color = "#FF0000"
            elif severity == "HIGH":
                badge = "🟠 HIGH"
                color = "#FF6B00"
            elif severity == "MEDIUM":
                badge = "🟡 MEDIUM"
                color = "#FFA500"
            else:
                badge = "🟢 LOW"
                color = "#00C851"

            st.markdown(
                f"""
                <div style="
                    border-left: 6px solid {color};
                    padding: 15px;
                    margin-bottom: 12px;
                    background-color: rgba(255,255,255,0.05);
                    border-radius: 10px;
                ">
                    <h4 style="margin-bottom:5px;">{badge} - {alert.get('rule', 'Unknown')}</h4>
                    <p><strong>Time:</strong> {alert.get('timestamp', 'N/A')}</p>
                    <p><strong>User:</strong> {alert.get('username', 'N/A')} |
                       <strong>IP:</strong> {alert.get('ip_address', 'N/A')}</p>
                    <p><strong>Description:</strong> {alert.get('description', 'N/A')}</p>
                    <p><strong>Alert ID:</strong> {alert.get('alert_id', 'N/A')}</p>
                </div>
                """,
                unsafe_allow_html=True
            )

            # -----------------------
            # ACKNOWLEDGE SECTION (FIXED INDENTATION)
            # -----------------------
            if alert.get("acknowledged"):
                st.success(
                    f"✅ Acknowledged by {alert.get('acknowledged_by')} "
                    f"at {alert.get('acknowledged_at')}"
                )
            else:
                if st.button(
                    "✅ Acknowledge",
                    key=f"ack_{alert.get('alert_id')}_{idx}"
                ):
                    # Update correct alert in original history
                    for i, a in enumerate(alert_history):
                        if a.get("alert_id") == alert.get("alert_id"):
                            alert_history[i]["acknowledged"] = True
                            alert_history[i]["acknowledged_by"] = st.session_state.username
                            alert_history[i]["acknowledged_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            break

                    save_json_db(ALERT_HISTORY_DB, alert_history)

                    log_audit(
                        st.session_state.username,
                        "ALERT_ACKNOWLEDGED",
                        alert.get("alert_id")
                    )

                    st.success("✅ Alert acknowledged successfully!")
                    st.rerun()

    else:
        st.info("📭 No alerts yet. Run an analysis to generate alerts.")

# TAB 5: SETTINGS
with tab5:
    st.header("⚙️ System Settings")
    
    settings_tab1, settings_tab2, settings_tab3 = st.tabs(["📧 Notifications", "👥 User Management", "🔧 System Config"])
    
    # Notifications settings
    with settings_tab1:
        st.subheader("Email Notification Configuration")
        
        config_data = load_json_db(NOTIFICATION_CONFIG)
        current_config = config_data[0] if config_data else {}
        
        email_enabled = st.checkbox("Enable Email Notifications", value=current_config.get('email_enabled', False))
        
        if email_enabled:
            smtp_server = st.text_input("SMTP Server", value=current_config.get('smtp_server', 'smtp.gmail.com'))
            smtp_port = st.number_input("SMTP Port", value=current_config.get('smtp_port', 587))
            smtp_user = st.text_input("SMTP Username", value=current_config.get('smtp_user', ''))
            smtp_password = st.text_input("SMTP Password", type="password")
            
            if st.button("💾 Save Email Config"):
                save_json_db(NOTIFICATION_CONFIG, [{
                    'email_enabled': email_enabled,
                    'smtp_server': smtp_server,
                    'smtp_port': smtp_port,
                    'smtp_user': smtp_user,
                    'smtp_password': smtp_password
                }])
                st.success("✅ Email configuration saved!")
                log_audit(st.session_state.username, "CONFIG_UPDATED", "Email notifications")
    
    # User management
    with settings_tab2:
        if st.session_state.role == "Admin":
            st.subheader("👥 Manage Users")
            
            users = load_users()
            
            if users:
                users_df = pd.DataFrame([
                    {
                        'Username': username,
                        'Role': user['role'],
                        'Email': user.get('email', 'N/A'),
                        'Last Login': user.get('last_login', 'Never')[:19] if user.get('last_login') else 'Never',
                        'Status': '🔒 Locked' if user['locked_until'] > time.time() else '✅ Active'
                    }
                    for username, user in users.items()
                ])
                
                st.dataframe(users_df, use_container_width=True)
                
                # Delete user
                user_to_delete = st.selectbox("Select user to delete", list(users.keys()))
                
                if st.button("🗑️ Delete User"):
                    if user_to_delete == st.session_state.username:
                        st.error("❌ Cannot delete your own account!")
                    else:
                        del users[user_to_delete]
                        save_users(users)
                        log_audit(st.session_state.username, "USER_DELETED", user_to_delete)
                        st.success(f"✅ User {user_to_delete} deleted.")
                        st.rerun()
            else:
                st.info("No users found.")
        else:
            st.warning("🔒 Admin access required for user management.")
    
    # System config
    with settings_tab3:
        st.subheader("🔧 System Configuration")
        
        st.number_input("Max Login Attempts", value=MAX_ATTEMPTS, min_value=1, max_value=10)
        st.number_input("Account Lock Time (seconds)", value=LOCK_TIME, min_value=30, max_value=3600)
        
        if st.button("💾 Save System Config"):
            st.success("✅ System configuration saved!")


# TAB 6: AUDIT LOG
with tab6:
    st.header("📜 Security Audit Log")
    
    audit_data = load_json_db(AUDIT_LOG)
    
    if audit_data:
        # Filter options
        col1, col2 = st.columns(2)
        
        with col1:
            filter_user = st.multiselect("Filter by User", list(set([a['username'] for a in audit_data])))
        
        with col2:
            filter_action = st.multiselect("Filter by Action", list(set([a['action'] for a in audit_data])))
        
        # Apply filters
        filtered_audit = audit_data
        if filter_user:
            filtered_audit = [a for a in filtered_audit if a['username'] in filter_user]
        if filter_action:
            filtered_audit = [a for a in filtered_audit if a['action'] in filter_action]
        
        # Display as DataFrame
        audit_df = pd.DataFrame(filtered_audit)
        st.dataframe(audit_df, use_container_width=True)
        
        # Download audit log
        if st.button("📥 Download Audit Log"):
            csv = audit_df.to_csv(index=False)
            st.download_button(
                label="Download CSV",
                data=csv,
                file_name=f"audit_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    else:
        st.info("📭 No audit log entries yet.")


# -----------------------------
# FOOTER
# -----------------------------
st.markdown("<br><br>", unsafe_allow_html=True)
st.markdown("""
    <div style='text-align: center; opacity: 0.6; padding: 20px;'>
        <p>SIEMSecure Pro v2.0 | Advanced Security Information & Event Management</p>
        <p>Powered by AI-Driven Threat Intelligence | © 2024</p>
    </div>
""", unsafe_allow_html=True)
