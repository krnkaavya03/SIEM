# app.py
import streamlit as st
import pandas as pd
import os
import sys
import json
import hashlib
import re
import time
import plotly.express as px

# Add SIEM project path
sys.path.append(os.path.abspath("."))
from main import SIEMFramework

# -----------------------------
# CONFIG
# -----------------------------
st.set_page_config(page_title="SIEMSecure", page_icon="🔐", layout="wide")

USER_DB = "users.json"
MAX_ATTEMPTS = 3
LOCK_TIME = 60


# -----------------------------
# THEME SELECTOR
# -----------------------------
st.sidebar.title("")
st.sidebar.title("⚙️Controls")
theme = st.sidebar.selectbox(
    "Choose Theme",
    ["Light", "Dark", "Blue", "Cyber"]
)


def apply_theme(theme):
    if theme == "Dark":
        bg = "#0E1117"
        sidebar = "#161B22"
        text = "#FFFFFF"
        card = "#1F2933"
    elif theme == "Blue":
        bg = "#EAF2FF"
        sidebar = "#D6E6FF"
        text = "#003366"
        card = "#FFFFFF"
    elif theme == "Cyber":
        bg = "#000000"
        sidebar = "#111111"
        text = "#00FF99"
        card = "#0D0D0D"
    else:  # Light
        bg = "#FFFFFF"
        sidebar = "#F5F5F5"
        text = "#000000"
        card = "#FFFFFF"

    st.markdown(
        f"""
        <style>

        /* Main background */
        .stApp {{
            background-color: {bg};
            color: {text};
        }}

        /* Sidebar */
        section[data-testid="stSidebar"] {{
            background-color: {sidebar};
            color: {text};
        }}

        /* Text everywhere */
        h1, h2, h3, h4, h5, h6, p, div, span, label {{
            color: {text} !important;
        }}

        /* Input fields */
        input, textarea {{
            color: black !important;
            background-color: white !important;
        }}

        /* Selectbox & Radio */
        .stSelectbox div, .stRadio div {{
            color: {text} !important;
        }}

        /* Metrics */
        div[data-testid="metric-container"] {{
            background-color: {card};
            border-radius: 10px;
            padding: 15px;
        }}

        /* DataFrame */
        .stDataFrame {{
            background-color: {card};
        }}

        </style>
        """,
        unsafe_allow_html=True
    )


apply_theme(theme)


# -----------------------------
# Utility Functions
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


def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True


def authenticate(username, password):
    users = load_users()

    if username not in users:
        return "no_user"

    user = users[username]

    if user["locked_until"] > time.time():
        return "locked"

    if user["password"] != hash_password(password):
        user["failed_attempts"] += 1

        if user["failed_attempts"] >= MAX_ATTEMPTS:
            user["locked_until"] = time.time() + LOCK_TIME
            save_users(users)
            return "locked"

        save_users(users)
        return "wrong_password"

    user["failed_attempts"] = 0
    user["locked_until"] = 0
    save_users(users)
    return "success"


def register_user(username, password, role):
    users = load_users()

    if username in users:
        return "exists"

    if not is_strong_password(password):
        return "weak"

    users[username] = {
        "password": hash_password(password),
        "role": role,
        "failed_attempts": 0,
        "locked_until": 0
    }

    save_users(users)
    return "success"


# -----------------------------
# SESSION STATE
# -----------------------------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "username" not in st.session_state:
    st.session_state.username = None
if "role" not in st.session_state:
    st.session_state.role = None


# -----------------------------
# LOGIN PAGE
# -----------------------------
if not st.session_state.authenticated:

    st.title("🔐 SIEMSecure Login")

    menu = st.radio("Select Option", ["Login", "Register"])

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if menu == "Login":
        if st.button("Login"):
            result = authenticate(username, password)

            if result == "success":
                users = load_users()
                st.session_state.authenticated = True
                st.session_state.username = username
                st.session_state.role = users[username]["role"]
                st.rerun()
            elif result == "no_user":
                st.error("User does not exist.")
            elif result == "wrong_password":
                st.error("Incorrect password.")
            elif result == "locked":
                st.error("Account locked. Try again later.")

    else:
        role = st.selectbox("Role", ["Analyst", "Admin"])

        if st.button("Register"):
            result = register_user(username, password, role)

            if result == "success":
                st.success("Registration successful.")
            elif result == "exists":
                st.error("Username already exists.")
            elif result == "weak":
                st.error("Password must contain 8 chars, 1 uppercase, 1 digit, 1 special character.")

    st.stop()


# -----------------------------
# DASHBOARD
# -----------------------------
st.title("🔒 SIEM Dashboard")
st.subheader(f"Welcome {st.session_state.username} ({st.session_state.role})")

if st.button("Logout"):
    st.session_state.authenticated = False
    st.rerun()

# -----------------------------
# Sidebar Mode Selection
# -----------------------------
st.sidebar.header("Analysis Mode")
mode = st.sidebar.radio("Mode", ["Test", "Live"])

if mode == "Test":
    log_file_path = st.sidebar.text_input("Local Log File Path", value="logs/logs.txt")
    remote_server = remote_user = remote_pass = None
else:
    log_file_path = None
    remote_server = st.sidebar.text_input("Remote Server")
    remote_user = st.sidebar.text_input("Device Name")
    remote_pass = st.sidebar.text_input("Password", type="password")

run_button = st.sidebar.button("Run Analysis")


# -----------------------------
# Run SIEM
# -----------------------------
if run_button:

    if mode == "Live" and st.session_state.role != "Admin":
        st.error("Only Admins can run Live mode.")
    else:
        with st.spinner("Running SIEM Analysis..."):
            try:
                siem = SIEMFramework(
                    log_file_path=log_file_path,
                    live_mode=(mode == "Live"),
                    test_mode=(mode == "Test"),
                    remote_server=remote_server,
                    remote_user=remote_user,
                    remote_password=remote_pass
                )

                siem.run_analysis()

                alerts = siem.alerts
                stats = siem.statistics

                col1, col2, col3 = st.columns(3)
                col1.metric("Total Alerts", len(alerts))
                col2.metric("Mode", mode)
                col3.metric("System Status", "Active")

                if alerts:
                    df = pd.DataFrame(alerts)
                    st.subheader("🚨 Alert Details")
                    st.dataframe(df)

                    if "severity" in df.columns:
                        severity_counts = df["severity"].value_counts().reset_index()
                        severity_counts.columns = ["Severity", "Count"]

                        fig = px.bar(
                            severity_counts,
                            x="Severity",
                            y="Count",
                            title="Alert Severity Distribution",
                            color="Severity"
                        )
                        st.plotly_chart(fig, use_container_width=True)

                if stats:
                    st.subheader("📊 Security Statistics")
                    stats_df = pd.DataFrame([stats])
                    st.dataframe(stats_df)

                    numeric_cols = stats_df.select_dtypes(include=['int64', 'float64']).columns

                    if len(numeric_cols) > 0:
                        fig2 = px.bar(stats_df.T, title="Statistics Overview")
                        st.plotly_chart(fig2, use_container_width=True)

            except Exception as e:
                st.error(f"Pipeline failed: {e}")
