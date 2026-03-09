"""
Statistics Engine Module
Generates comprehensive security analysis statistics and reports
"""

from collections import Counter, defaultdict
from datetime import datetime
import config


class StatisticsEngine:
    """
    Generates detailed security analysis statistics from processed logs and alerts
    """

    def __init__(self):
        """Initialize statistics engine"""
        self.statistics: dict = {}

    def generate_statistics(self, parsed_logs: list, detections: list, correlations: list, alerts: list) -> dict:
        """
        Generate comprehensive security statistics

        Args:
            parsed_logs (list): Parsed log entries
            detections (list): Detected threats
            correlations (list): Correlated events
            alerts (list): Security alerts

        Returns:
            dict: Statistics data
        """
        self.statistics = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_events': len(parsed_logs),
            'total_detections': len(detections),
            'total_correlations': len(correlations),
            'total_alerts': len(alerts),
            'general_stats': self._compute_general_stats(parsed_logs),
            'attack_breakdown': self._compute_attack_breakdown(detections, correlations),
            'top_attackers': self._identify_top_attackers(parsed_logs),
            'user_activity': self._analyze_user_activity(parsed_logs),
            'alert_severity': self._analyze_alert_severity(alerts)
        }

        return self.statistics

    # -----------------------------
    # Internal statistics computations
    # -----------------------------
    def _compute_general_stats(self, parsed_logs: list) -> dict:
        """Compute general statistics from logs"""
        event_types = [log.get('event_type', 'OTHER') for log in parsed_logs]
        event_counter = Counter(event_types)

        unique_ips = {log.get('ip_address', 'N/A') for log in parsed_logs}
        unique_users = {log.get('username', 'N/A') for log in parsed_logs}

        return {
            'total_events': len(parsed_logs),
            'unique_ips': len(unique_ips),
            'unique_users': len(unique_users),
            'failed_logins': event_counter.get(config.EVENT_LOGIN_FAILED, 0),
            'successful_logins': event_counter.get(config.EVENT_LOGIN_SUCCESS, 0),
            'file_accesses': event_counter.get(config.EVENT_FILE_ACCESS, 0),
            'privilege_escalations': event_counter.get(config.EVENT_PRIVILEGE_ESCALATION, 0),
            'event_type_breakdown': dict(event_counter)
        }

    def _compute_attack_breakdown(self, detections: list, correlations: list) -> dict:
        """Compute breakdown of attack types"""
        all_attack_types = [d.get('rule', 'UNKNOWN') for d in detections] + \
                           [c.get('correlation_type', 'UNKNOWN') for c in correlations]
        return dict(Counter(all_attack_types))

    def _identify_top_attackers(self, parsed_logs: list, top_n: int = 5) -> list:
        """Identify top attacking IPs based on failed logins"""
        ip_failed_logins = Counter(
            log.get('ip_address', 'N/A') for log in parsed_logs if log.get('event_type') == config.EVENT_LOGIN_FAILED
        )
        return [{'ip': ip, 'failed_attempts': count} for ip, count in ip_failed_logins.most_common(top_n)]

    def _analyze_user_activity(self, parsed_logs: list) -> dict:
        """Analyze user activity patterns"""
        user_events = defaultdict(lambda: {
            'total_events': 0,
            'failed_logins': 0,
            'successful_logins': 0,
            'unique_ips': set()
        })

        for log in parsed_logs:
            username = log.get('username', 'N/A')
            user_events[username]['total_events'] += 1
            user_events[username]['unique_ips'].add(log.get('ip_address', 'N/A'))

            if log.get('event_type') == config.EVENT_LOGIN_FAILED:
                user_events[username]['failed_logins'] += 1
            elif log.get('event_type') == config.EVENT_LOGIN_SUCCESS:
                user_events[username]['successful_logins'] += 1

        # Convert sets to counts for serialization
        for username in user_events:
            user_events[username]['unique_ips'] = len(user_events[username]['unique_ips'])

        return dict(user_events)

    def _analyze_alert_severity(self, alerts: list) -> dict:
        """Analyze alert severity distribution"""
        severity_count = Counter(alert.get('severity', config.SEVERITY_LOW) for alert in alerts)
        return {
            'critical': severity_count.get(config.SEVERITY_CRITICAL, 0),
            'high': severity_count.get(config.SEVERITY_HIGH, 0),
            'medium': severity_count.get(config.SEVERITY_MEDIUM, 0),
            'low': severity_count.get(config.SEVERITY_LOW, 0)
        }

    # -----------------------------
    # Output methods
    # -----------------------------
    def display_statistics(self):
        """Display formatted statistics to console"""
        if not self.statistics:
            print("No statistics available. Generate statistics first.")
            return

        print("\n" + "="*80)
        print(f"{'SIEM HYBRID FRAMEWORK - SECURITY STATISTICS':^80}")
        print(f"{'Generated: ' + self.statistics['timestamp']:^80}")
        print("="*80)

        stats = self.statistics['general_stats']
        print(f"\n{'GENERAL STATISTICS':^80}")
        print("-" * 80)
        print(f"Total Events Processed:     {stats['total_events']}")
        print(f"Unique IP Addresses:        {stats['unique_ips']}")
        print(f"Unique Users:               {stats['unique_users']}")
        print(f"Failed Login Attempts:      {stats['failed_logins']}")
        print(f"Successful Logins:          {stats['successful_logins']}")
        print(f"File Access Events:         {stats['file_accesses']}")
        print(f"Privilege Escalations:      {stats['privilege_escalations']}")

        print(f"\n{'ALERT SUMMARY':^80}")
        print("-" * 80)
        print(f"Total Alerts Generated:     {self.statistics['total_alerts']}")
        print(f"Total Detections:           {self.statistics['total_detections']}")
        print(f"Total Correlations:         {self.statistics['total_correlations']}")

        severity = self.statistics['alert_severity']
        print(f"\nAlert Severity Breakdown:")
        print(f"  🔴 Critical:  {severity['critical']}")
        print(f"  🟠 High:      {severity['high']}")
        print(f"  🟡 Medium:    {severity['medium']}")
        print(f"  🟢 Low:       {severity['low']}")

        if self.statistics['attack_breakdown']:
            print(f"\n{'ATTACK TYPE BREAKDOWN':^80}")
            print("-" * 80)
            for attack_type, count in self.statistics['attack_breakdown'].items():
                print(f"{attack_type:40} {count:>5}")

        if self.statistics['top_attackers']:
            print(f"\n{'TOP ATTACKING IPs':^80}")
            print("-" * 80)
            for i, attacker in enumerate(self.statistics['top_attackers'], 1):
                print(f"{i}. {attacker['ip']:20} - {attacker['failed_attempts']} failed attempts")

        print("\n" + "="*80 + "\n")

    def save_statistics_to_file(self, filename: str = None):
        """Save statistics to a file"""
        if filename is None:
            filename = config.STATISTICS_OUTPUT_FILE

        try:
            with open(filename, 'w') as f:
                f.write("="*80 + "\n")
                f.write(f"{'SIEM HYBRID FRAMEWORK - SECURITY STATISTICS':^80}\n")
                f.write(f"{'Generated: ' + self.statistics['timestamp']:^80}\n")
                f.write("="*80 + "\n\n")

                # General Stats
                f.write("GENERAL STATISTICS\n")
                f.write("-" * 80 + "\n")
                stats = self.statistics['general_stats']
                for key in ['total_events', 'unique_ips', 'unique_users', 'failed_logins', 'successful_logins',
                            'file_accesses', 'privilege_escalations']:
                    f.write(f"{key.replace('_',' ').title():<30} {stats.get(key,0)}\n")

                # Alert Summary
                f.write("\nALERT SUMMARY\n")
                f.write("-" * 80 + "\n")
                for key in ['total_alerts', 'total_detections', 'total_correlations']:
                    f.write(f"{key.replace('_',' ').title():<30} {self.statistics.get(key,0)}\n")

                f.write("\nAlert Severity Breakdown:\n")
                severity = self.statistics['alert_severity']
                for level in ['critical','high','medium','low']:
                    f.write(f"  {level.title():<8} {severity.get(level,0)}\n")

                # Attack Breakdown
                if self.statistics['attack_breakdown']:
                    f.write("\nATTACK TYPE BREAKDOWN\n")
                    f.write("-"*80 + "\n")
                    for attack_type,count in self.statistics['attack_breakdown'].items():
                        f.write(f"{attack_type:40} {count:>5}\n")

                # Top Attackers
                if self.statistics['top_attackers']:
                    f.write("\nTOP ATTACKING IPs\n")
                    f.write("-"*80 + "\n")
                    for i, attacker in enumerate(self.statistics['top_attackers'],1):
                        f.write(f"{i}. {attacker['ip']:20} - {attacker['failed_attempts']} failed attempts\n")

                f.write("\n" + "="*80 + "\n")

            print(f"[STATISTICS ENGINE] Statistics saved to {filename}")

        except Exception as e:
            print(f"[STATISTICS ENGINE] Error saving statistics: {e}")

    def get_statistics(self) -> dict:
        """Return the generated statistics dictionary"""
        return self.statistics
