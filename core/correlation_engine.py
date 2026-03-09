"""
Correlation Engine Module
Performs advanced correlation between security events for real system logs
"""

from collections import defaultdict
from datetime import datetime
import config


class CorrelationEngine:
    """
    Correlates multiple security events to identify complex attack patterns.
    Works alongside detection engine for multi-stage attack detection.
    """

    def __init__(self):
        """Initialize correlation engine"""
        self.correlations = []
        self.user_activity = defaultdict(list)   # All events per user
        self.ip_user_mapping = defaultdict(set)  # All users per IP

    def correlate_events(self, parsed_logs, detections):
        """
        Correlate events to identify complex patterns

        Args:
            parsed_logs (list): List of parsed log entries (real system logs)
            detections (list): List of detected threats from detection engine

        Returns:
            list: List of correlated security events
        """
        self.correlations = []

        # Build activity profiles safely
        for log in parsed_logs:
            username = log.get('username') or 'N/A'
            ip = log.get('ip_address') or 'N/A'
            timestamp = log.get('timestamp') or datetime.now()
            log['timestamp'] = timestamp
            log['timestamp_str'] = log.get('timestamp_str') or timestamp.strftime("%Y-%m-%d %H:%M:%S")

            self.user_activity[username].append(log)
            self.ip_user_mapping[ip].add(username)

        # Apply correlation rules
        self._correlate_shared_ips()
        self._correlate_multiple_ips_per_user()
        self._correlate_privilege_escalation()
        self._correlate_sequential_failed_logins()

        print(f"[CORRELATION ENGINE] Found {len(self.correlations)} correlated events")
        return self.correlations

    # ------------------ CORRELATION RULES ------------------ #

    def _correlate_shared_ips(self):
        """Detect multiple users accessing from the same IP (possible credential sharing or proxy)"""
        for ip, users in self.ip_user_mapping.items():
            if len(users) >= config.SHARED_IP_THRESHOLD:
                if not any(c.get('correlation_type') == 'SHARED_IP' and c.get('ip_address') == ip
                           for c in self.correlations):
                    self.correlations.append({
                        'correlation_type': 'SHARED_IP',
                        'severity': config.SEVERITY_MEDIUM,
                        'ip_address': ip,
                        'users': list(users),
                        'user_count': len(users),
                        'description': (
                            f"Multiple users ({len(users)}) accessing from single IP: {ip}. "
                            "Possible credential sharing or compromised proxy."
                        )
                    })

    def _correlate_multiple_ips_per_user(self):
        """Detect single user accessing from multiple IPs (possible account compromise)"""
        for username, activities in self.user_activity.items():
            unique_ips = set(log.get('ip_address') or 'N/A' for log in activities)
            if len(unique_ips) >= config.MULTIPLE_IPS_THRESHOLD:
                if not any(c.get('correlation_type') == 'MULTIPLE_IPS' and c.get('username') == username
                           for c in self.correlations):
                    self.correlations.append({
                        'correlation_type': 'MULTIPLE_IPS',
                        'severity': config.SEVERITY_MEDIUM,
                        'username': username,
                        'ip_addresses': list(unique_ips),
                        'ip_count': len(unique_ips),
                        'description': (
                            f"User {username} accessed from {len(unique_ips)} different IPs. "
                            "Possible account compromise."
                        )
                    })

    def _correlate_privilege_escalation(self):
        """Detect privilege escalation following failed logins (lateral movement)"""
        for username, activities in self.user_activity.items():
            # Sort by timestamp safely
            sorted_activities = sorted(activities, key=lambda x: x.get('timestamp') or datetime.now())
            for i in range(len(sorted_activities) - 1):
                current = sorted_activities[i]
                next_event = sorted_activities[i + 1]

                if (current.get('event_type') == config.EVENT_LOGIN_FAILED and
                        next_event.get('event_type') == config.EVENT_PRIVILEGE_ESCALATION):

                    time_diff = (next_event.get('timestamp') - current.get('timestamp')).total_seconds() / 60
                    if time_diff <= config.CORRELATION_WINDOW_MINUTES:
                        if not any(c.get('correlation_type') == 'PRIVILEGE_ESCALATION_AFTER_FAILED_LOGIN' and
                                   c.get('username') == username and
                                   c.get('timestamp') == next_event.get('timestamp_str')
                                   for c in self.correlations):
                            self.correlations.append({
                                'correlation_type': 'PRIVILEGE_ESCALATION_AFTER_FAILED_LOGIN',
                                'severity': config.SEVERITY_HIGH,
                                'username': username,
                                'ip_address': current.get('ip_address') or 'N/A',
                                'timestamp': next_event.get('timestamp_str') or str(next_event.get('timestamp')),
                                'time_diff_minutes': round(time_diff, 2),
                                'description': (
                                    f"Privilege escalation detected {round(time_diff, 2)} minutes "
                                    f"after failed login for user {username}."
                                )
                            })

    def _correlate_sequential_failed_logins(self):
        """Detect rapid sequential failed logins from same IP or user (pre-brute force indication)"""
        ip_failed_count = defaultdict(list)
        user_failed_count = defaultdict(list)

        for username, activities in self.user_activity.items():
            for log in activities:
                if log.get('event_type') == config.EVENT_LOGIN_FAILED:
                    ip_failed_count[log.get('ip_address') or 'N/A'].append(log)
                    user_failed_count[username].append(log)

        # IP-based rapid failures
        for ip, logs in ip_failed_count.items():
            if len(logs) >= config.SEQUENTIAL_FAIL_THRESHOLD:
                if not any(c.get('correlation_type') == 'SEQUENTIAL_FAILED_LOGINS' and c.get('ip_address') == ip
                           for c in self.correlations):
                    self.correlations.append({
                        'correlation_type': 'SEQUENTIAL_FAILED_LOGINS',
                        'severity': config.SEVERITY_MEDIUM,
                        'ip_address': ip,
                        'event_count': len(logs),
                        'description': f"{len(logs)} sequential failed logins detected from IP {ip}"
                    })

        # User-based rapid failures
        for username, logs in user_failed_count.items():
            if len(logs) >= config.SEQUENTIAL_FAIL_THRESHOLD:
                if not any(c.get('correlation_type') == 'SEQUENTIAL_FAILED_LOGINS_USER' and
                           c.get('username') == username for c in self.correlations):
                    self.correlations.append({
                        'correlation_type': 'SEQUENTIAL_FAILED_LOGINS_USER',
                        'severity': config.SEVERITY_MEDIUM,
                        'username': username,
                        'event_count': len(logs),
                        'description': f"{len(logs)} sequential failed login attempts detected for user {username}"
                    })

    # ------------------ GETTERS ------------------ #

    def get_correlations(self):
        """Return all correlated events"""
        return self.correlations

    def get_high_risk_correlations(self):
        """Return only high-risk correlations"""
        return [
            c for c in self.correlations
            if c.get('severity') in [config.SEVERITY_HIGH, config.SEVERITY_CRITICAL]
        ]
