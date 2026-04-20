"""
Log Collector Module
Responsible for ingesting real system logs from Linux or Windows.
Supports local and remote servers.

Remote support:
  - Linux over SSH (paramiko) → pulls /var/log/auth.log or any path
  - Windows EVTX (python-evtx) → local .evtx files
  - Windows remote via WinRM (pywinrm) → PowerShell Get-WinEvent
  - Any plain text log file (fallback)
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

# Optional: For remote Linux access via SSH
try:
    import paramiko
except ImportError:
    paramiko = None


class LogCollector:
    """
    Collects logs from system log files or Windows Event Logs.
    Supports:
      - Linux auth.log (/var/log/auth.log) — local or remote via SSH
      - Windows Security Event Logs (.evtx)
      - Remote Windows servers via WinRM
      - Any plain text log file
    """

    def __init__(self, log_file_path=None, remote_server=None,
                 username=None, password=None,
                 remote_log_path='/var/log/auth.log'):
        """
        Args:
            log_file_path (str): Path to the local log file or .evtx file
            remote_server (str): Remote server hostname or IP
            username (str): SSH / WinRM username
            password (str): SSH / WinRM password
            remote_log_path (str): Path to log file on the remote Linux server
                                   (ignored for Windows WinRM connections)
        """
        self.log_file_path   = log_file_path
        self.remote_server   = remote_server
        self.username        = username
        self.password        = password
        self.remote_log_path = remote_log_path or '/var/log/auth.log'
        self.raw_logs        = []
        self.system_type     = platform.system()

        if (self.system_type == "Windows"
                and log_file_path
                and log_file_path.endswith(".evtx")
                and evtx is None):
            raise ImportError("Evtx module not installed. Run `pip install python-evtx`")

    # -----------------------------
    # Main log collection dispatcher
    # -----------------------------
    def collect_logs(self):
        """Collect logs depending on source type."""

        if self.remote_server:
            # Decide remote protocol: WinRM if winrm available AND it looks like
            # a Windows-style path or WinRM was explicitly configured; otherwise SSH.
            if winrm and not paramiko:
                return self._collect_remote_windows_logs()
            elif paramiko and not winrm:
                return self._collect_remote_linux_logs_ssh()
            elif paramiko and winrm:
                # Both installed — prefer SSH for Linux, WinRM for Windows.
                # Heuristic: if remote_log_path ends with .evtx → WinRM
                if self.remote_log_path and self.remote_log_path.endswith('.evtx'):
                    return self._collect_remote_windows_logs()
                return self._collect_remote_linux_logs_ssh()
            else:
                print("[LOG COLLECTOR] No remote library available. "
                      "Install paramiko (Linux SSH) or pywinrm (Windows WinRM).")
                return []

        elif self.log_file_path:
            if self.system_type == "Linux":
                return self._collect_linux_logs()
            elif self.system_type == "Windows" and self.log_file_path.endswith(".evtx"):
                return self._collect_windows_evtx_logs()
            else:
                # macOS or any OS reading a plain text log
                return self._collect_text_logs()

        else:
            raise ValueError("No log source specified. Provide log_file_path or remote_server.")

    # -----------------------------
    # Local Linux logs
    # -----------------------------
    def _collect_linux_logs(self):
        collected_logs = []
        try:
            with open(self.log_file_path, 'r', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = self._parse_linux_auth_log(line)
                    if entry:
                        collected_logs.append(entry)
        except PermissionError:
            print(f"[LOG COLLECTOR] Permission denied: {self.log_file_path}. "
                  "Try running with sudo or adjust file permissions.")
        except Exception as e:
            print(f"[LOG COLLECTOR] Error reading Linux log: {e}")

        self.raw_logs = collected_logs
        print(f"[LOG COLLECTOR] Collected {len(collected_logs)} structured Linux log entries")
        return collected_logs

    # -----------------------------
    # Remote Linux logs over SSH
    # -----------------------------
    def _collect_remote_linux_logs_ssh(self):
        """
        SSH into a Linux server using paramiko, read the remote log file,
        and return parsed log entries.
        """
        if paramiko is None:
            print("[LOG COLLECTOR] paramiko not installed. Run: pip install paramiko")
            return []

        collected_logs = []
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self.remote_server,
                username=self.username,
                password=self.password,
                timeout=15
            )

            # Use sudo cat so we can read protected log files (auth.log needs root)
            cmd = f"sudo cat {self.remote_log_path} 2>/dev/null || cat {self.remote_log_path}"
            _, stdout, stderr = client.exec_command(cmd, timeout=30)
            lines = stdout.read().decode('utf-8', errors='replace').splitlines()
            err   = stderr.read().decode('utf-8', errors='replace').strip()

            if err:
                print(f"[LOG COLLECTOR] SSH stderr: {err[:200]}")

            client.close()

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                entry = self._parse_linux_auth_log(line)
                if entry:
                    collected_logs.append(entry)

        except Exception as e:
            print(f"[LOG COLLECTOR] SSH connection failed ({self.remote_server}): {e}")

        self.raw_logs = collected_logs
        print(f"[LOG COLLECTOR] Collected {len(collected_logs)} log entries "
              f"from remote Linux server {self.remote_server}")
        return collected_logs

    def tail_remote_linux_logs_ssh(self, lines=200):
        """
        Tail the last N lines of the remote log file via SSH.
        Useful for live-mode polling without downloading the whole file.
        Returns list of parsed log dicts.
        """
        if paramiko is None:
            print("[LOG COLLECTOR] paramiko not installed.")
            return []

        collected_logs = []
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self.remote_server,
                username=self.username,
                password=self.password,
                timeout=15
            )

            cmd = f"sudo tail -n {lines} {self.remote_log_path} 2>/dev/null"
            _, stdout, _ = client.exec_command(cmd, timeout=20)
            raw_lines = stdout.read().decode('utf-8', errors='replace').splitlines()
            client.close()

            for line in raw_lines:
                line = line.strip()
                if line:
                    entry = self._parse_linux_auth_log(line)
                    if entry:
                        collected_logs.append(entry)

        except Exception as e:
            print(f"[LOG COLLECTOR] SSH tail failed: {e}")

        return collected_logs

    # -----------------------------
    # Windows EVTX logs (local)
    # -----------------------------
    def _collect_windows_evtx_logs(self):
        collected_logs = []
        try:
            with evtx.Evtx(self.log_file_path) as log:
                for record in log.records():
                    xml_str = record.xml()
                    ts_match       = re.search(r'<TimeCreated SystemTime="([^"]+)"', xml_str)
                    user_match     = re.search(r'<Data Name="TargetUserName">([^<]+)</Data>', xml_str)
                    event_id_match = re.search(r'<EventID.*?>(\d+)</EventID>', xml_str)
                    ip_match       = re.search(r'<Data Name="IpAddress">([^<]+)</Data>', xml_str)

                    timestamp  = (datetime.strptime(ts_match.group(1), "%Y-%m-%dT%H:%M:%S.%fZ")
                                  if ts_match else datetime.now())
                    username   = user_match.group(1)   if user_match     else 'N/A'
                    event_id   = int(event_id_match.group(1)) if event_id_match else 0
                    ip_address = ip_match.group(1)      if ip_match       else 'N/A'
                    if ip_address in ('-', '::1', ''):
                        ip_address = 'N/A'

                    event_type = self._map_windows_event_id(event_id)

                    collected_logs.append({
                        'timestamp':     timestamp,
                        'timestamp_str': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                        'event_type':    event_type,
                        'event_id':      event_id,
                        'username':      username,
                        'ip_address':    ip_address,
                        'raw_message':   xml_str[:300],
                        'hour':          timestamp.hour
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
            import json as _json
            session = winrm.Session(
                f'http://{self.remote_server}:5985/wsman',
                auth=(self.username, self.password)
            )

            ps_script = (
                "Get-WinEvent -LogName Security -MaxEvents 200 | "
                "Select-Object TimeCreated,Id,"
                "@{N='User';E={$_.Properties[5].Value}},"
                "@{N='IP';E={$_.Properties[18].Value}},"
                "Message | ConvertTo-Json -Compress"
            )
            result = session.run_ps(ps_script)
            logs   = _json.loads(result.std_out.decode())
            if isinstance(logs, dict):
                logs = [logs]

            for log in logs:
                try:
                    timestamp = datetime.strptime(
                        str(log.get('TimeCreated', ''))[:19],
                        "%Y-%m-%d %H:%M:%S"
                    )
                except Exception:
                    timestamp = datetime.now()

                event_id   = log.get('Id', 0)
                event_type = self._map_windows_event_id(event_id)
                username   = log.get('User', 'N/A') or 'N/A'
                ip_address = log.get('IP', 'N/A') or 'N/A'
                if ip_address in ('-', '::1', ''):
                    ip_address = 'N/A'

                collected_logs.append({
                    'timestamp':     timestamp,
                    'timestamp_str': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    'event_type':    event_type,
                    'event_id':      event_id,
                    'username':      username,
                    'ip_address':    ip_address,
                    'raw_message':   log.get('Message', '')[:300],
                    'hour':          timestamp.hour
                })

        except Exception as e:
            print(f"[LOG COLLECTOR] Error collecting remote Windows logs: {e}")

        self.raw_logs = collected_logs
        print(f"[LOG COLLECTOR] Collected {len(collected_logs)} logs from remote Windows server")
        return collected_logs

    # -----------------------------
    # Plain text file fallback
    # -----------------------------
    def _collect_text_logs(self):
        collected_logs = []
        try:
            with open(self.log_file_path, 'r', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        # Try structured parse first; fall back to raw dict
                        entry = self._parse_linux_auth_log(line)
                        collected_logs.append(entry if entry else {'raw_message': line})
        except Exception as e:
            print(f"[LOG COLLECTOR] Error reading text log: {e}")

        self.raw_logs = collected_logs
        print(f"[LOG COLLECTOR] Collected {len(collected_logs)} text log entries")
        return collected_logs

    # -----------------------------
    # Linux auth.log line parser
    # -----------------------------
    def _parse_linux_auth_log(self, line):
        try:
            pattern = (
                r"^(?P<month>\w+)\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
                r"(?P<host>\S+)\s+(?P<service>[\w\-/]+)(?:\[\d+\])?:\s+(?P<message>.+)$"
            )
            match = re.match(pattern, line)
            if not match:
                return None

            year   = datetime.now().year
            ts_str = f"{match.group('month')} {match.group('day').zfill(2)} {match.group('time')} {year}"
            try:
                timestamp = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y")
            except ValueError:
                timestamp = datetime.now()

            message   = match.group('message')
            service   = match.group('service')
            username  = 'N/A'
            ip_address = 'N/A'
            event_type = 'OTHER'

            if 'sshd' in service:
                m = re.search(
                    r'(?:Failed password for(?: invalid user)?|Invalid user)\s+(\S+)\s+from\s+([\d.]+)',
                    message
                )
                if m:
                    username, ip_address = m.group(1), m.group(2)
                    event_type = 'LOGIN_FAILED'
                else:
                    m = re.search(
                        r'(?:Accepted password|Accepted publickey) for\s+(\S+)\s+from\s+([\d.]+)',
                        message
                    )
                    if m:
                        username, ip_address = m.group(1), m.group(2)
                        event_type = 'LOGIN_SUCCESS'
                    elif re.search(r'(?:Disconnected|session closed|Connection closed)', message):
                        event_type = 'LOGOUT'

            elif 'sudo' in service:
                event_type = 'PRIVILEGE_ESCALATION'
                m = re.search(r'(\S+)\s+:\s+TTY', message)
                if m:
                    username = m.group(1)

            elif 'pam' in service.lower():
                m = re.search(r'user=(\S+)', message)
                if m:
                    username = m.group(1)
                if 'authentication failure' in message or 'auth could not identify' in message:
                    event_type = 'LOGIN_FAILED'
                elif 'session opened' in message:
                    event_type = 'LOGIN_SUCCESS'
                elif 'session closed' in message:
                    event_type = 'LOGOUT'

            return {
                'timestamp':     timestamp,
                'timestamp_str': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                'event_type':    event_type,
                'username':      username,
                'ip_address':    ip_address,
                'process':       service,
                'raw_message':   message,
                'hour':          timestamp.hour
            }
        except Exception:
            return None

    # -----------------------------
    # Utilities
    # -----------------------------
    @staticmethod
    def _map_windows_event_id(event_id):
        mapping = {
            4624: 'LOGIN_SUCCESS',
            4625: 'LOGIN_FAILED',
            4634: 'LOGOUT',
            4647: 'LOGOUT',
            4648: 'LOGIN_SUCCESS',
            4672: 'PRIVILEGE_ESCALATION',
            4673: 'PRIVILEGE_ESCALATION',
            4688: 'FILE_ACCESS',
            4698: 'FILE_ACCESS',
        }
        return mapping.get(event_id, 'OTHER')

    def tail_logs(self, last_position=0, batch_size=None):
        """Tail new log entries for live monitoring (local Linux/text only)."""
        if not self.log_file_path or not os.path.exists(self.log_file_path):
            return [], last_position

        try:
            with open(self.log_file_path, 'r', errors='replace') as f:
                all_lines = f.readlines()

            new_lines = all_lines[last_position:]
            if batch_size:
                new_lines = new_lines[:batch_size]

            new_logs = [
                self._parse_linux_auth_log(line.strip())
                for line in new_lines if line.strip()
            ]
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