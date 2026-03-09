"""
Detection Engine Module
Rule-based detection engine for SIEM Hybrid Framework
Analyzes parsed logs to detect security threats in real system logs
"""

from collections import defaultdict
from datetime import datetime
import config


class DetectionEngine:
    """Rule-based detection engine for real system logs"""

    def __init__(self, test_mode=False):
        self.test_mode = test_mode
        self._reset_state()

    # -----------------------------
    # Internal State Reset
    # -----------------------------
    def _reset_state(self):
        self.detections = []
        self.failed_login_tracker_ip = defaultdict(list)
        self.failed_login_tracker_user = defaultdict(list)
        self.ip_activity_tracker = defaultdict(list)
        self.user_activity_tracker = defaultdict(list)

    # -----------------------------
    # Helper: Get Severity from Config
    # -----------------------------
    def _get_severity(self, rule_name):
        return config.ALERT_RULES.get(rule_name, {}).get(
            "severity", config.SEVERITY_LOW
        )

    # -----------------------------
    # Helper: Add Detection (Prevents Duplicates)
    # -----------------------------
    def _add_detection(self, rule, ip, username, timestamp, description, extra=None):
        if any(d.get("rule") == rule and d.get("ip_address") == ip for d in self.detections):
            return

        detection = {
            "rule": rule,
            "severity": self._get_severity(rule),
            "ip_address": ip,
            "username": username,
            "timestamp": timestamp or datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "description": description,
        }

        if extra:
            detection.update(extra)

        self.detections.append(detection)

    # -----------------------------
    # Main Analysis
    # -----------------------------
    def analyze_logs(self, parsed_logs):

        self._reset_state()

        # Track activity first
        for log in parsed_logs:
            ip = log.get("ip_address", "N/A")
            username = log.get("username", "N/A")

            self.ip_activity_tracker[ip].append(log)
            self.user_activity_tracker[username].append(log)

            if log.get("event_type") == config.EVENT_LOGIN_FAILED:
                self.failed_login_tracker_ip[ip].append(log)
                self.failed_login_tracker_user[username].append(log)

        # -----------------------------
        # Test Mode (forces varied severity)
        # -----------------------------
        if self.test_mode:
            for log in parsed_logs:
                self.detections.append({
                    "rule": f"TEST_{log.get('event_type')}",
                    "severity": config.SEVERITY_HIGH,
                    "ip_address": log.get("ip_address", "N/A"),
                    "username": log.get("username", "N/A"),
                    "timestamp": log.get("timestamp_str"),
                    "description": f"Test detection for {log.get('event_type')}",
                })
            return self.detections

        # -----------------------------
        # Apply Detection Rules
        # -----------------------------
        for log in parsed_logs:
            self._detect_brute_force(log)
            self._detect_blacklisted_ip(log)
            self._detect_suspicious_time(log)
            self._detect_privilege_escalation(log)
            self._detect_admin_endpoint_access(log)
            self._detect_correlation_attack(log)

        return self.detections

    # -----------------------------
    # Detection Rules
    # -----------------------------

    def _detect_brute_force(self, log):
        ip = log.get("ip_address", "N/A")
        failed_count = len(self.failed_login_tracker_ip[ip])

        if failed_count >= config.BRUTE_FORCE_THRESHOLD:
            self._add_detection(
                rule="BRUTE_FORCE",
                ip=ip,
                username=log.get("username", "N/A"),
                timestamp=log.get("timestamp_str"),
                description=f"{failed_count} failed login attempts detected from {ip}",
                extra={"event_count": failed_count}
            )

    def _detect_blacklisted_ip(self, log):
        ip = log.get("ip_address", "N/A")

        if ip in config.BLACKLISTED_IPS:
            self._add_detection(
                rule="BLACKLISTED_IP",
                ip=ip,
                username=log.get("username", "N/A"),
                timestamp=log.get("timestamp_str"),
                description=f"Access attempt from blacklisted IP {ip}"
            )

    def _detect_suspicious_time(self, log):
        if log.get("event_type") == config.EVENT_LOGIN_SUCCESS:
            hour = log.get("hour")

            if hour is not None and config.SUSPICIOUS_TIME_START <= hour < config.SUSPICIOUS_TIME_END:
                self._add_detection(
                    rule="SUSPICIOUS_HOURS",
                    ip=log.get("ip_address", "N/A"),
                    username=log.get("username", "N/A"),
                    timestamp=log.get("timestamp_str"),
                    description=f"Login during suspicious hours ({hour}:00)"
                )

    def _detect_privilege_escalation(self, log):
        if log.get("event_type") == config.EVENT_PRIVILEGE_ESCALATION:
            self._add_detection(
                rule="PRIVILEGE_ESCALATION",
                ip=log.get("ip_address", "N/A"),
                username=log.get("username", "N/A"),
                timestamp=log.get("timestamp_str"),
                description=f"Privilege escalation attempt detected"
            )

    def _detect_admin_endpoint_access(self, log):
        http_path = log.get("http_path")

        if http_path and "/admin" in http_path:
            self._add_detection(
                rule="ADMIN_ENDPOINT_ACCESS",
                ip=log.get("ip_address", "N/A"),
                username=log.get("username", "N/A"),
                timestamp=log.get("timestamp_str"),
                description="Access to protected admin endpoint detected"
            )

    def _detect_correlation_attack(self, log):
        ip = log.get("ip_address", "N/A")

        failed_logins = [
            l for l in self.ip_activity_tracker[ip]
            if l.get("event_type") == config.EVENT_LOGIN_FAILED
        ]

        successful_logins = [
            l for l in self.ip_activity_tracker[ip]
            if l.get("event_type") == config.EVENT_LOGIN_SUCCESS
        ]

        if len(failed_logins) >= config.BRUTE_FORCE_THRESHOLD and successful_logins:
            self._add_detection(
                rule="CORRELATION_ATTACK",
                ip=ip,
                username=successful_logins[0].get("username", "N/A"),
                timestamp=successful_logins[0].get("timestamp_str"),
                description=f"Successful login after {len(failed_logins)} failed attempts",
                extra={
                    "failed_attempts": len(failed_logins),
                    "successful_logins": len(successful_logins)
                }
            )
