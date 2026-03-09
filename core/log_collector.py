"""
Log Collector Module
Responsible for ingesting real system logs from Linux or Windows
Supports local and remote servers
"""

import os
import re
import platform
from datetime import datetime

# Optional: For Windows EVTX reading
try:
    import Evtx.Evtx as evtx
except ImportError:
    evtx = None

# Optional: For remote Windows access via WinRM
try:
    import winrm
except ImportError:
    winrm = None


class LogCollector:
    """
    Collects logs from system log files or Windows Event Logs.
    Supports:
      - Linux auth.log (/var/log/auth.log)
      - Windows Security Event Logs (.evtx)
      - Remote Windows servers via WinRM
      - Any plain text log file
    """

    def __init__(self, log_file_path=None, remote_server=None, username=None, password=None):
        """
        Initialize the log collector

        Args:
            log_file_path (str): Path to the system log file or EVTX file
            remote_server (str): Remote Windows server hostname or IP
            username (str): Remote server username (for WinRM)
            password (str): Remote server password (for WinRM)
        """
        self.log_file_path = log_file_path
        self.remote_server = remote_server
        self.username = username
        self.password = password
        self.raw_logs = []
        self.system_type = platform.system()

        if self.system_type == "Windows" and log_file_path and log_file_path.endswith(".evtx") and evtx is None:
            raise ImportError("Evtx module not installed. Run `pip install python-evtx`")
        if remote_server and winrm is None:
            raise ImportError("winrm module not installed. Run `pip install pywinrm`")

    # -----------------------------
    # Main log collection
    # -----------------------------
    def collect_logs(self):
        """
        Collect logs depending on system type and local/remote source
        """
        if self.remote_server:
            return self._collect_remote_windows_logs()
        elif self.log_file_path:
            if self.system_type == "Linux":
                return self._collect_linux_logs()
            elif self.system_type == "Windows" and self.log_file_path.endswith(".evtx"):
                return self._collect_windows_evtx_logs()
            else:
                return self._collect_text_logs()
        else:
            raise ValueError("No log source specified")

    # -----------------------------
    # Linux logs
    # -----------------------------
    def _collect_linux_logs(self):
        collected_logs = []
        try:
            with open(self.log_file_path, 'r') as file:
                for line in file:
                    line = line.strip()
                    if not line:
                        continue
                    log_entry = self._parse_linux_auth_log(line)
                    if log_entry:
                        collected_logs.append(log_entry)
        except Exception as e:
            print(f"[LOG COLLECTOR] Error reading Linux log: {e}")

        self.raw_logs = collected_logs
        print(f"[LOG COLLECTOR] Collected {len(collected_logs)} structured Linux log entries")
        return collected_logs

    # -----------------------------
    # Windows EVTX logs
    # -----------------------------
    def _collect_windows_evtx_logs(self):
        collected_logs = []
        try:
            with evtx.Evtx(self.log_file_path) as log:
                for record in log.records():
                    xml_str = record.xml()
                    ts_match = re.search(r'<TimeCreated SystemTime="([^"]+)"', xml_str)
                    user_match = re.search(r'<Data Name="TargetUserName">([^<]+)</Data>', xml_str)
                    event_id_match = re.search(r'<EventID.*?>(\d+)</EventID>', xml_str)

                    timestamp = datetime.strptime(ts_match.group(1), "%Y-%m-%dT%H:%M:%S.%fZ") if ts_match else datetime.now()
                    username = user_match.group(1) if user_match else "N/A"
                    event_id = int(event_id_match.group(1)) if event_id_match else 0

                    event_type = self._map_windows_event_id(event_id)

                    collected_logs.append({
                        "timestamp": timestamp,
                        "timestamp_str": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                        "event_type": event_type,
                        "username": username,
                        "ip_address": "N/A",
                        "raw_message": xml_str,
                        "hour": timestamp.hour
                    })
        except Exception as e:
            print(f"[LOG COLLECTOR] Error reading Windows EVTX log: {e}")

        self.raw_logs = collected_logs
        print(f"[LOG COLLECTOR] Collected {len(collected_logs)} structured Windows log entries")
        return collected_logs

    # -----------------------------
    # Remote Windows via WinRM
    # -----------------------------
    def _collect_remote_windows_logs(self):
        collected_logs = []
        try:
            session = winrm.Session(f'http://{self.remote_server}:5985/wsman',
                                    auth=(self.username, self.password))

            ps_script = """
            Get-WinEvent -LogName Security | 
            Select-Object TimeCreated, Id, LevelDisplayName, @{Name='User';Expression={$_.Properties[5].Value}}, Message |
            ConvertTo-Json -Compress
            """
            result = session.run_ps(ps_script)
            import json
            logs = json.loads(result.std_out.decode())
            if isinstance(logs, dict):
                logs = [logs]

            for log in logs:
                timestamp = datetime.strptime(log['TimeCreated'], "%Y-%m-%d %H:%M:%S")
                event_type = self._map_windows_event_id(log['Id'])
                username = log.get('User', 'N/A')
                collected_logs.append({
                    "timestamp": timestamp,
                    "timestamp_str": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "event_type": event_type,
                    "username": username,
                    "ip_address": "N/A",
                    "raw_message": log.get('Message', ''),
                    "hour": timestamp.hour
                })
        except Exception as e:
            print(f"[LOG COLLECTOR] Error collecting remote Windows logs: {e}")

        self.raw_logs = collected_logs
        print(f"[LOG COLLECTOR] Collected {len(collected_logs)} logs from remote Windows server")
        return collected_logs

    # -----------------------------
    # Text file fallback
    # -----------------------------
    def _collect_text_logs(self):
        collected_logs = []
        try:
            with open(self.log_file_path, 'r') as file:
                for line in file:
                    line = line.strip()
                    if line:
                        collected_logs.append({"raw_message": line})
        except Exception as e:
            print(f"[LOG COLLECTOR] Error reading text log: {e}")

        self.raw_logs = collected_logs
        print(f"[LOG COLLECTOR] Collected {len(collected_logs)} text log entries")
        return collected_logs

    # -----------------------------
    # Utilities
    # -----------------------------
    @staticmethod
    def _map_windows_event_id(event_id):
        if event_id in [4625]:
            return "LOGIN_FAILED"
        elif event_id in [4624]:
            return "LOGIN_SUCCESS"
        elif event_id in [4672]:
            return "PRIVILEGE_ESCALATION"
        else:
            return "OTHER"

    def _parse_linux_auth_log(self, line):
        try:
            pattern = r"^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<service>[\w\-/]+)(?:\[\d+\])?:\s+(?P<message>.+)$"
            match = re.match(pattern, line)
            if not match:
                return None

            ts_str = f"{match.group('month')} {match.group('day')} {match.group('time')}"
            timestamp = datetime.strptime(ts_str, "%b %d %H:%M:%S")
            message = match.group('message')
            username, ip_address, event_type = "N/A", "N/A", "OTHER"

            if 'sshd' in match.group('service'):
                user_match = re.search(r'(?:for|Invalid user)\s+(\w+)\s+from\s+([\d.]+)', message)
                if user_match:
                    username, ip_address = user_match.group(1), user_match.group(2)
                if 'Failed password' in message or 'Invalid user' in message:
                    event_type = 'LOGIN_FAILED'
                elif 'Accepted password' in message or 'Accepted publickey' in message:
                    event_type = 'LOGIN_SUCCESS'
            elif 'sudo' in match.group('service'):
                event_type = 'PRIVILEGE_ESCALATION'
                user_match = re.search(r'(\w+)\s+:\s+TTY', message)
                if user_match:
                    username = user_match.group(1)

            return {
                "timestamp": timestamp,
                "timestamp_str": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "event_type": event_type,
                "username": username,
                "ip_address": ip_address,
                "process": match.group('service'),
                "raw_message": message,
                "hour": timestamp.hour
            }
        except Exception:
            return None

    # -----------------------------
    # Live tailing
    # -----------------------------
    def tail_logs(self, last_position=0, batch_size=None):
        """Tail new log entries for live monitoring (Linux/text only)"""
        if not self.log_file_path or not os.path.exists(self.log_file_path):
            return [], last_position

        try:
            with open(self.log_file_path, 'r') as file:
                all_lines = file.readlines()

            new_lines = all_lines[last_position:]
            if batch_size:
                new_lines = new_lines[:batch_size]

            new_logs = [self._parse_linux_auth_log(line.strip())
                        for line in new_lines if line.strip()]
            new_logs = [log for log in new_logs if log]

            new_position = last_position + len(new_lines)
            if new_logs:
                print(f"[LOG COLLECTOR] Found {len(new_logs)} new log entries")

            return new_logs, new_position
        except Exception as e:
            print(f"[LOG COLLECTOR] Error tailing logs: {e}")
            return [], last_position

    def get_log_count(self):
        return len(self.raw_logs)
