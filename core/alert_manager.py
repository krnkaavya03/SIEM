"""
Alert Manager Module
Manages, categorizes, and outputs security alerts from detection and correlation engines
Enhanced for real system SIEM usage
"""

import config
from datetime import datetime
import os
import json


class AlertManager:
    """
    Handles security alerts, organizes by severity, and manages output
    """

    def __init__(self):
        """Initialize alert manager"""
        self.alerts = []
        self._initialize_severity_counter()

    # ---------------------------------------------------------
    # Internal Utilities
    # ---------------------------------------------------------

    def _initialize_severity_counter(self):
        """Initialize severity counter dictionary"""
        self.alert_count_by_severity = {
            config.SEVERITY_LOW: 0,
            config.SEVERITY_MEDIUM: 0,
            config.SEVERITY_HIGH: 0,
            config.SEVERITY_CRITICAL: 0
        }

    def _normalize_severity(self, severity):
        """
        Normalize severity to uppercase and validate against config
        """
        if not severity:
            return config.SEVERITY_LOW

        severity = str(severity).upper()

        if severity not in self.alert_count_by_severity:
            return config.SEVERITY_LOW

        return severity

    # ---------------------------------------------------------
    # Main Processing
    # ---------------------------------------------------------

    def process_detections(self, detections, correlations):
        """
        Convert detections and correlations into alerts
        """

        self.alerts.clear()
        self._initialize_severity_counter()

        # Process detection-based alerts
        for detection in detections:
            severity = self._normalize_severity(
                detection.get('severity', config.SEVERITY_LOW)
            )
            detection['severity'] = severity

            alert = self._create_alert_from_detection(detection)
            self.alerts.append(alert)

            self.alert_count_by_severity[severity] += 1

        # Process correlation-based alerts
        for correlation in correlations:
            severity = self._normalize_severity(
                correlation.get('severity', config.SEVERITY_LOW)
            )
            correlation['severity'] = severity

            alert = self._create_alert_from_correlation(correlation)
            self.alerts.append(alert)

            self.alert_count_by_severity[severity] += 1

        # Sort alerts by severity: Critical > High > Medium > Low
        severity_order = {
            config.SEVERITY_CRITICAL: 0,
            config.SEVERITY_HIGH: 1,
            config.SEVERITY_MEDIUM: 2,
            config.SEVERITY_LOW: 3
        }

        self.alerts.sort(
            key=lambda x: severity_order.get(
                x.get('severity', config.SEVERITY_LOW), 3
            )
        )

        print(f"[ALERT MANAGER] Generated {len(self.alerts)} alerts")
        return self.alerts

    # ---------------------------------------------------------
    # Alert Creation
    # ---------------------------------------------------------

    def _create_alert_from_detection(self, detection):
       """Generate alert dictionary from detection"""
       import time
       alert_id = f"ALERT-{int(time.time() * 1000) % 1000000:06d}-{len(self.alerts):04d}"
       # Rest stays the same...

    def _create_alert_from_correlation(self, correlation):
       """Generate alert dictionary from correlation"""
       import time
       alert_id = f"ALERT-{int(time.time() * 1000) % 1000000:06d}-{len(self.alerts):04d}"
    
       return {
            'alert_id': alert_id,
            'type': 'CORRELATION',
            'rule': correlation.get('correlation_type', 'UNKNOWN'),
            'severity': self._normalize_severity(
                correlation.get('severity', config.SEVERITY_LOW)
            ),
            'timestamp': correlation.get(
                'timestamp',
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ),
            'ip_address': correlation.get('ip_address', 'N/A'),
            'username': correlation.get('username', 'N/A'),
            'description': correlation.get('description', 'No description'),
            'metadata': correlation
        }

    # ---------------------------------------------------------
    # Display Functions
    # ---------------------------------------------------------

    def display_alerts(self):
        """Display all alerts in console"""

        if not self.alerts:
            print("\n" + "=" * 80)
            print("NO ALERTS GENERATED")
            print("=" * 80)
            return

        print("\n" + "=" * 80)
        print(f"{'SECURITY ALERTS':^80}")
        print("=" * 80)

        for alert in self.alerts:
            self._print_alert(alert)

        print("=" * 80)
        self._print_alert_summary()
        print("=" * 80 + "\n")

    def _print_alert(self, alert):
        """Print formatted single alert"""

        severity_labels = {
            config.SEVERITY_CRITICAL: "🔴 CRITICAL",
            config.SEVERITY_HIGH: "🟠 HIGH",
            config.SEVERITY_MEDIUM: "🟡 MEDIUM",
            config.SEVERITY_LOW: "🟢 LOW"
        }

        severity = alert.get('severity', config.SEVERITY_LOW)

        print(f"\n[{alert.get('alert_id', 'N/A')}] "
              f"{severity_labels.get(severity, 'UNKNOWN')}")
        print(f"Rule: {alert.get('rule', 'N/A')}")
        print(f"Time: {alert.get('timestamp', 'N/A')}")
        print(f"User: {alert.get('username', 'N/A')} | "
              f"IP: {alert.get('ip_address', 'N/A')}")
        print(f"Description: {alert.get('description', 'No description')}")
        print("-" * 80)

    def _print_alert_summary(self):
        """Display summary counts by severity"""

        print(f"\n{'ALERT SUMMARY':^80}")
        print(f"Total Alerts: {len(self.alerts)}")

        for sev, emoji in [
            (config.SEVERITY_CRITICAL, "🔴"),
            (config.SEVERITY_HIGH, "🟠"),
            (config.SEVERITY_MEDIUM, "🟡"),
            (config.SEVERITY_LOW, "🟢")
        ]:
            print(f"  {emoji} {sev.capitalize():<8}: "
                  f"{self.alert_count_by_severity.get(sev, 0)}")

    # ---------------------------------------------------------
    # File Persistence
    # ---------------------------------------------------------

    def save_alerts_to_file(self, filename=None):
        """Persist alerts to file"""

        if filename is None:
            filename = config.ALERT_OUTPUT_FILE

        try:
            os.makedirs(os.path.dirname(filename), exist_ok=True)

            with open(filename, 'w') as f:
                f.write("=" * 80 + "\n")
                f.write(f"{'SIEM HYBRID FRAMEWORK - SECURITY ALERTS':^80}\n")
                f.write(f"{'Generated: ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S'):^80}\n")
                f.write("=" * 80 + "\n\n")

                for alert in self.alerts:
                    f.write(json.dumps(alert, default=str, indent=2))
                    f.write("\n" + "-" * 80 + "\n")

                f.write("=" * 80 + "\n")
                f.write(f"Total Alerts: {len(self.alerts)}\n")
                f.write(f"Critical: {self.alert_count_by_severity.get(config.SEVERITY_CRITICAL, 0)} | ")
                f.write(f"High: {self.alert_count_by_severity.get(config.SEVERITY_HIGH, 0)} | ")
                f.write(f"Medium: {self.alert_count_by_severity.get(config.SEVERITY_MEDIUM, 0)} | ")
                f.write(f"Low: {self.alert_count_by_severity.get(config.SEVERITY_LOW, 0)}\n")
                f.write("=" * 80 + "\n")

            print(f"[ALERT MANAGER] Alerts saved to {filename}")

        except Exception as e:
            print(f"[ALERT MANAGER] Error saving alerts: {e}")

    # ---------------------------------------------------------
    # Accessors
    # ---------------------------------------------------------

    def get_alerts(self):
        """Return all alerts"""
        return self.alerts

    def get_critical_alerts(self):
        """Return only critical alerts"""
        return [
            a for a in self.alerts
            if a.get('severity') == config.SEVERITY_CRITICAL
        ]
