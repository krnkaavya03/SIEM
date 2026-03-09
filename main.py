"""
Main Orchestration Script for SIEM Hybrid Framework
Coordinates all modules to perform end-to-end log analysis and threat detection
Handles real system logs safely, test-mode logs, and remote Windows servers
"""

import sys
import os
import config
from datetime import datetime

# Direct imports from core modules
from core.log_collector import LogCollector
from core.log_parser import LogParser
from core.detection_engine import DetectionEngine
from core.correlation_engine import CorrelationEngine
from core.alert_manager import AlertManager
from core.statistics_engine import StatisticsEngine


# -----------------------------
# Test log injection
# -----------------------------
def inject_test_logs():
    """Return a set of test logs to generate alerts"""
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return [
        {'event_type': 'LOGIN_FAILED', 'ip_address': '10.0.0.101', 'username': 'attacker1', 'timestamp_str': now_str},
        {'event_type': 'PRIVILEGE_ESCALATION', 'ip_address': '10.0.0.102', 'username': 'attacker2', 'timestamp_str': now_str},
        {'event_type': 'LOGIN_SUCCESS', 'ip_address': '10.0.0.101', 'username': 'attacker1', 'timestamp_str': now_str, 'hour': 2},
        {'event_type': 'FILE_ACCESS', 'ip_address': '10.0.0.103', 'username': 'attacker3', 'timestamp_str': now_str}
    ]


# -----------------------------
# SIEM Framework
# -----------------------------
class SIEMFramework:
    """Main SIEM Framework orchestrator for system logs"""

    def __init__(self, log_file_path=None, live_mode=False, test_mode=False,
                 remote_server=None, remote_user=None, remote_password=None):
        self.log_file_path = log_file_path or config.LOG_FILE_PATH
        self.live_mode = live_mode
        self.test_mode = test_mode
        self.remote_server = remote_server
        self.remote_user = remote_user
        self.remote_password = remote_password

        # Initialize log collector with remote support
        self.collector = LogCollector(
            log_file_path=self.log_file_path,
            remote_server=self.remote_server,
            username=self.remote_user,
            password=self.remote_password
        )

        self.parser = LogParser()
        self.detection_engine = DetectionEngine(test_mode=self.test_mode)
        self.correlation_engine = CorrelationEngine()
        self.alert_manager = AlertManager()
        self.statistics_engine = StatisticsEngine()

        # Data storage
        self.raw_logs = []
        self.parsed_logs = []
        self.detections = []
        self.correlations = []
        self.alerts = []
        self.statistics = {}

        # Live mode tracking
        self.log_position = 0
        self.analysis_cycle = 0

    # -----------------------------
    # Standard log analysis
    # -----------------------------
    def run_analysis(self):
        print("\n" + "="*80)
        print(f"{'SIEM HYBRID FRAMEWORK - STARTING LOG ANALYSIS':^80}")
        print("="*80 + "\n")

        try:
            # Step 1: Collect logs
            print("[PIPELINE] Step 1/6: Collecting logs from system...")
            if self.test_mode:
                self.raw_logs = inject_test_logs()
                print(f"[LOG COLLECTOR] Injected {len(self.raw_logs)} test log entries")
            else:
                self.raw_logs = self.collector.collect_logs()
                source = "remote server" if self.remote_server else "local file"
                print(f"[LOG COLLECTOR] Collected {len(self.raw_logs)} log entries from {source}")

            if not self.raw_logs:
                print("[ERROR] No logs collected. Exiting.")
                return

            # Step 2: Parse logs
            print("[PIPELINE] Step 2/6: Parsing system logs...")
            self.parsed_logs = self.parser.parse_logs(self.raw_logs)
            print(f"[PARSER] Successfully parsed {len(self.parsed_logs)} out of {len(self.raw_logs)} log entries")
            if not self.parsed_logs:
                print("[ERROR] No logs parsed successfully. Exiting.")
                return

            # Step 3: Detect threats
            print("[PIPELINE] Step 3/6: Running detection engine...")
            self.detections = self.detection_engine.analyze_logs(self.parsed_logs)
            print(f"[DETECTION ENGINE] Generated {len(self.detections)} detection(s)")

            # Step 4: Correlate events
            print("[PIPELINE] Step 4/6: Running correlation engine...")
            self.correlations = self.correlation_engine.correlate_events(self.parsed_logs, self.detections)
            print(f"[CORRELATION ENGINE] Found {len(self.correlations)} correlated events")

            # Step 5: Manage alerts
            print("[PIPELINE] Step 5/6: Processing alerts...")
            self.alerts = self.alert_manager.process_detections(self.detections, self.correlations)
            print(f"[ALERT MANAGER] Generated {len(self.alerts)} alerts")

            # Step 6: Generate statistics
            print("[PIPELINE] Step 6/6: Generating security statistics...")
            self.statistics = self.statistics_engine.generate_statistics(
                self.parsed_logs, self.detections, self.correlations, self.alerts
            )

            print("\n[PIPELINE] ✓ Log analysis completed successfully!\n")
            self._display_results()
            self._save_outputs()

        except Exception as e:
            print(f"[ERROR] Pipeline failed: {e}")
            import traceback
            traceback.print_exc()

    # -----------------------------
    # Helper methods
    # -----------------------------
    def _display_results(self):
        if config.ENABLE_CONSOLE_OUTPUT:
            self.alert_manager.display_alerts()
            if config.ENABLE_DETAILED_REPORTS:
                self.statistics_engine.display_statistics()

    def _save_outputs(self):
        self.alert_manager.save_alerts_to_file()
        self.statistics_engine.save_statistics_to_file()

    def get_summary(self):
        return {
            'total_logs': len(self.raw_logs),
            'parsed_logs': len(self.parsed_logs),
            'total_detections': len(self.detections),
            'total_correlations': len(self.correlations),
            'total_alerts': len(self.alerts),
            'critical_alerts': len(self.alert_manager.get_critical_alerts())
        }


# -----------------------------
# Entry Point
# -----------------------------
def main():
    print("""
    ╔════════════════════════════════════════════════════════════════════════════╗
    ║                                                                            ║
    ║                      SIEM HYBRID FRAMEWORK v1.1                            ║
    ║          Real-Time System Log Security Monitoring                          ║
    ║                                                                            ║
    ╚════════════════════════════════════════════════════════════════════════════╝
    """)

    # Flags
    live_mode = '--live' in sys.argv
    test_mode = '--test' in sys.argv

    # Log file option
    log_file_path = None
    if '--log' in sys.argv:
        idx = sys.argv.index('--log')
        try:
            log_file_path = sys.argv[idx + 1]
            if not os.path.exists(log_file_path):
                print(f"[ERROR] Log file '{log_file_path}' not found.")
                return
        except IndexError:
            print("[ERROR] Missing log filename after --log")
            return

    # Remote server options
    remote_server = None
    remote_user = None
    remote_password = None
    if '--remote' in sys.argv:
        idx = sys.argv.index('--remote')
        try:
            remote_server = sys.argv[idx + 1]
            remote_user = sys.argv[idx + 2]
            remote_password = sys.argv[idx + 3]
        except IndexError:
            print("[ERROR] Remote server parameters missing. Usage: --remote <host> <user> <password>")
            return

    siem = SIEMFramework(
        log_file_path=log_file_path,
        live_mode=live_mode,
        test_mode=test_mode,
        remote_server=remote_server,
        remote_user=remote_user,
        remote_password=remote_password
    )

    siem.run_analysis()

    if not live_mode:
        summary = siem.get_summary()
        print("\n" + "="*80)
        print(f"{'EXECUTION SUMMARY':^80}")
        print("="*80)
        for k, v in summary.items():
            print(f"{k.replace('_',' ').title():<30}: {v}")
        print("="*80)
        print("\n✓ SIEM Framework execution completed.\n")


if __name__ == "__main__":
    main()
