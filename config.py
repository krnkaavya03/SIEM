"""
Configuration file for SIEM Hybrid Framework
Contains detection rules, thresholds, and system settings
"""

# -----------------------------
# System Configuration
# -----------------------------
LOG_FILE_PATH = r"C:\Users\krnka\OneDrive\Documents\SIEM\logs\logs.txt"
ALERT_OUTPUT_FILE = r"C:\Users\krnka\OneDrive\Documents\SIEM\alerts.txt"
STATISTICS_OUTPUT_FILE = r"C:\Users\krnka\OneDrive\Documents\SIEM\statistics_report.txt"

# Supported Log Formats
LOG_FORMATS_SUPPORTED = ["CUSTOM", "APACHE", "NGINX", "SYSLOG", "WINDOWS_EVENT"]

# -----------------------------
# Detection Thresholds
# -----------------------------
BRUTE_FORCE_THRESHOLD = 5              # Failed logins to trigger brute force alert
CORRELATION_WINDOW_MINUTES = 30        # Time window for correlation rules
SHARED_IP_THRESHOLD = 2                # Multiple users from same IP triggers alert
MULTIPLE_IPS_THRESHOLD = 2             # Single user from multiple IPs triggers alert
SEQUENTIAL_FAIL_THRESHOLD = 3          # Sequential failed logins for correlation detection
MULTIPLE_PRIV_ESC_THRESHOLD = 1        # Multiple privilege escalation attempts

# -----------------------------
# Threat Intelligence
# -----------------------------
BLACKLISTED_IPS = [
    "203.0.113.45",
    "198.51.100.88",
    "192.0.2.199"
]

SUSPICIOUS_TIME_START = 2   # Hour in 24h format
SUSPICIOUS_TIME_END = 4     # Hour in 24h format

# -----------------------------
# Alert Severity Levels
# -----------------------------
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

# -----------------------------
# Event Types (Parser & Detection Engine)
# -----------------------------
EVENT_LOGIN_SUCCESS = "LOGIN_SUCCESS"
EVENT_LOGIN_FAILED = "LOGIN_FAILED"
EVENT_FILE_ACCESS = "FILE_ACCESS"
EVENT_PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
EVENT_LOGOUT = "LOGOUT"
EVENT_OTHER = "OTHER"

# -----------------------------
# Alert Rules (Flexible)
# -----------------------------
ALERT_RULES = {
    "BRUTE_FORCE": {
        "threshold": BRUTE_FORCE_THRESHOLD,
        "severity": SEVERITY_HIGH,
        "description": "Multiple failed login attempts detected"
    },
    "BLACKLISTED_IP": {
        "severity": SEVERITY_CRITICAL,
        "description": "Access attempt from blacklisted IP"
    },
    "SUSPICIOUS_HOURS": {
        "severity": SEVERITY_MEDIUM,
        "description": f"Access during suspicious hours ({SUSPICIOUS_TIME_START}:00-{SUSPICIOUS_TIME_END}:00)"
    },
    "PRIVILEGE_ESCALATION": {
        "threshold": MULTIPLE_PRIV_ESC_THRESHOLD,
        "severity": SEVERITY_CRITICAL,
        "description": "Privilege escalation attempts detected"
    },
    "SHARED_IP": {
        "threshold": SHARED_IP_THRESHOLD,
        "severity": SEVERITY_MEDIUM,
        "description": "Multiple users detected from the same IP"
    },
    "MULTIPLE_IPS": {
        "threshold": MULTIPLE_IPS_THRESHOLD,
        "severity": SEVERITY_MEDIUM,
        "description": "User accessed from multiple IP addresses"
    },
    "SEQUENTIAL_FAILED_LOGINS": {
        "threshold": SEQUENTIAL_FAIL_THRESHOLD,
        "severity": SEVERITY_MEDIUM,
        "description": "Sequential failed logins detected"
    }
}

# -----------------------------
# Output Settings
# -----------------------------
ENABLE_DETAILED_REPORTS = True
ENABLE_CONSOLE_OUTPUT = True

# -----------------------------
# Live Log Analysis Settings
# -----------------------------
LIVE_MODE_ENABLED = True          # Enable continuous monitoring
LIVE_MODE_POLL_INTERVAL = 5      # Seconds between polling for new logs
LIVE_MODE_BATCH_SIZE = 10        # Number of logs per processing batch
LIVE_MODE_TIMEOUT = None         # None = run indefinitely

# -----------------------------
# Windows Event Log Settings
# -----------------------------
WINDOWS_EVENT_LOG_ENABLED = True
WINDOWS_EVENT_LOG_CHANNEL = "Security"  # Security, System, Application
WINDOWS_EVENT_LOG_POLL_INTERVAL = 5     # Seconds between log polling
WINDOWS_EVENT_LOG_MAX_EVENTS = 50       # Max events to fetch per poll

# -----------------------------
# Optional: Email Alert Settings
# -----------------------------
EMAIL_ALERT_SETTINGS = {
    "enabled": False,
    "smtp_server": "smtp.example.com",
    "smtp_port": 587,
    "username": "alert@example.com",
    "password": "password",
    "recipient_list": ["security_team@example.com"]
}
