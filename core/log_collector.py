"""
log_collector.py
UPDATED FOR WINDOWS-FIRST + Linux Support

Supports:
- Windows local text logs
- Windows remote over SSH (OpenSSH Server)
- Windows remote over WinRM
- Windows EVTX local files
- Linux local auth logs
- Linux remote over SSH
- Live tail mode
"""

import os
import re
import platform
from datetime import datetime

# Optional libraries
try:
    import paramiko
except ImportError:
    paramiko = None

try:
    import winrm
except ImportError:
    winrm = None

try:
    import Evtx.Evtx as evtx
except ImportError:
    evtx = None


class LogCollector:
    def __init__(
        self,
        log_file_path=None,
        remote_server=None,
        username=None,
        password=None,
        remote_log_path=None
    ):
        self.log_file_path = log_file_path
        self.remote_server = remote_server
        self.username = username
        self.password = password
        self.remote_log_path = remote_log_path
        self.raw_logs = []
        self.system_type = platform.system()

    # =====================================================
    # MAIN ENTRY
    # =====================================================
    def collect_logs(self):

        if self.remote_server:
            return self._collect_remote_logs()

        if self.log_file_path:
            if self.log_file_path.lower().endswith(".evtx"):
                return self._collect_windows_evtx_logs()

            if self.system_type == "Linux":
                return self._collect_linux_logs()

            return self._collect_windows_text_logs()

        return []

    # =====================================================
    # REMOTE AUTO MODE
    # =====================================================
    def _collect_remote_logs(self):

        # Force WinRM first for Windows targets
        if winrm is not None:
            return self._collect_remote_windows_logs()

        # fallback to SSH
        if paramiko is not None:
            return self._collect_remote_ssh_logs()

        print("[LOG COLLECTOR] No remote library installed.")
        return []

    # =====================================================
    # REMOTE SSH WINDOWS + LINUX
    # =====================================================
    def _collect_remote_ssh_logs(self):

        logs = []

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(
                paramiko.AutoAddPolicy()
            )

            client.connect(
                hostname=self.remote_server,
                username=self.username,
                password=self.password,
                timeout=15
            )

            is_windows = self._remote_is_windows(client)

            if is_windows:
                lines = self._read_remote_windows_file(
                    client,
                    self.remote_log_path
                )

                for line in lines:
                    entry = self._parse_windows_line(line)
                    if entry:
                        logs.append(entry)

            else:
                lines = self._read_remote_linux_file(
                    client,
                    self.remote_log_path or "/var/log/auth.log"
                )

                for line in lines:
                    entry = self._parse_linux_auth_log(line)
                    if entry:
                        logs.append(entry)

            client.close()

        except Exception as e:
            print(f"[LOG COLLECTOR] SSH error: {e}")

        self.raw_logs = logs
        return logs

    # =====================================================
    # DETECT REMOTE OS
    # =====================================================
    def _remote_is_windows(self, client):

        try:
            _, stdout, _ = client.exec_command("ver")
            text = stdout.read().decode(
                errors="ignore"
            ).lower()

            if "windows" in text:
                return True
        except:
            pass

        return False

    # =====================================================
    # WINDOWS SSH FILE READ
    # =====================================================
    def _read_remote_windows_file(self, client, path):

        if not path:
            path = r"C:\Windows\win.ini"

        path = path.replace("/", "\\")

        commands = [
            f'type "{path}"',
            f'powershell -Command Get-Content "{path}"',
            f'powershell -Command Get-WinEvent -LogName Security -MaxEvents 50'
        ]

        for cmd in commands:
            try:
                _, stdout, _ = client.exec_command(
                    cmd,
                    timeout=30
                )

                text = stdout.read().decode(
                    "utf-8",
                    errors="replace"
                )

                if text.strip():
                    return text.splitlines()

            except:
                pass

        return []

    # =====================================================
    # LINUX SSH FILE READ
    # =====================================================
    def _read_remote_linux_file(self, client, path):

        cmd = f"sudo cat {path} 2>/dev/null || cat {path}"

        _, stdout, _ = client.exec_command(
            cmd,
            timeout=30
        )

        text = stdout.read().decode(
            "utf-8",
            errors="replace"
        )

        return text.splitlines()

    # =====================================================
    # WINDOWS LOCAL TEXT LOGS
    # =====================================================
    def _collect_windows_text_logs(self):

        logs = []

        try:
            with open(
                self.log_file_path,
                "r",
                errors="replace"
            ) as f:

                for line in f:
                    line = line.strip()

                    if not line:
                        continue

                    logs.append(
                        self._parse_windows_line(line)
                    )

        except Exception as e:
            print(e)

        self.raw_logs = logs
        return logs

    # =====================================================
    # WINDOWS PARSER
    # =====================================================
    def _parse_windows_line(self, line):

        now = datetime.now()
        low = line.lower()
        event_type = "OTHER"

        if (
            "drop" in low or
            "deny" in low or
            "fail" in low or
            "blocked" in low or
            "4625" in low
        ):
            event_type = "LOGIN_FAILED"

        elif (
            "allow" in low or
            "accept" in low or
            "success" in low or
            "4624" in low
        ):
            event_type = "LOGIN_SUCCESS"

        return {
            "timestamp": now,
            "timestamp_str": now.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "event_type": event_type,
            "username": self.username or "N/A",
            "ip_address": self.remote_server or "LOCAL",
            "process": "windows",
            "raw_message": line,
            "hour": now.hour
        }

    # =====================================================
    # WINDOWS EVTX
    # =====================================================
    def _collect_windows_evtx_logs(self):

        logs = []

        if evtx is None:
            return []

        try:
            with evtx.Evtx(self.log_file_path) as log:
                for record in log.records():

                    xml = record.xml()
                    now = datetime.now()

                    logs.append({
                        "timestamp": now,
                        "timestamp_str": now.strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),
                        "event_type": "OTHER",
                        "username": "N/A",
                        "ip_address": "LOCAL",
                        "process": "evtx",
                        "raw_message": xml[:500],
                        "hour": now.hour
                    })

        except Exception as e:
            print(e)

        self.raw_logs = logs
        return logs

    # =====================================================
    # WINRM WINDOWS (FULLY UPDATED)
    # =====================================================
    def _collect_remote_windows_logs(self):

        logs = []

        if winrm is None:
            print("[LOG COLLECTOR] pywinrm not installed.")
            return []

        try:
            endpoint = f"http://{self.remote_server}:5985/wsman"

            session = winrm.Session(
                endpoint,
                auth=(self.username, self.password),
                transport="ntlm"
            )

            if (
                self.remote_log_path and
                self.remote_log_path.lower().endswith(".evtx")
            ):

                ps = rf"""
$path = "{self.remote_log_path}"
Get-WinEvent -Path $path -MaxEvents 100 |
Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message |
Format-Table -Wrap -AutoSize
"""

            elif self.remote_log_path:

                logname = self.remote_log_path.strip()

                ps = rf"""
Get-WinEvent -LogName "{logname}" -MaxEvents 100 |
Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message |
Format-Table -Wrap -AutoSize
"""

            else:

                ps = r"""
Get-WinEvent -LogName Security -MaxEvents 100 |
Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message |
Format-Table -Wrap -AutoSize
"""

            result = session.run_ps(ps)

            err = result.std_err.decode(
                "utf-8",
                errors="replace"
            ).strip()

            if err:
                print(f"[LOG COLLECTOR] WinRM error: {err}")

            text = result.std_out.decode(
                "utf-8",
                errors="replace"
            )

            if not text.strip():
                print("[LOG COLLECTOR] No WinRM logs returned.")
                return []

            for line in text.splitlines():

                line = line.strip()

                if (
                    not line or
                    line.startswith("TimeCreated") or
                    line.startswith("-----------")
                ):
                    continue

                logs.append(
                    self._parse_windows_line(line)
                )

        except Exception as e:
            print(f"[LOG COLLECTOR] WinRM exception: {e}")

        self.raw_logs = logs
        return logs

    # =====================================================
    # LOCAL LINUX
    # =====================================================
    def _collect_linux_logs(self):

        logs = []

        try:
            with open(
                self.log_file_path,
                "r",
                errors="replace"
            ) as f:

                for line in f:
                    line = line.strip()

                    if not line:
                        continue

                    entry = self._parse_linux_auth_log(line)

                    if entry:
                        logs.append(entry)

        except Exception as e:
            print(e)

        self.raw_logs = logs
        return logs

    # =====================================================
    # LINUX PARSER
    # =====================================================
    def _parse_linux_auth_log(self, line):

        try:
            now = datetime.now()
            event_type = "OTHER"

            if "Failed password" in line:
                event_type = "LOGIN_FAILED"

            elif "Accepted password" in line:
                event_type = "LOGIN_SUCCESS"

            return {
                "timestamp": now,
                "timestamp_str": now.strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "event_type": event_type,
                "username": "N/A",
                "ip_address": "N/A",
                "process": "linux",
                "raw_message": line,
                "hour": now.hour
            }

        except:
            return None

    # =====================================================
    # LIVE TAIL LOCAL
    # =====================================================
    def tail_logs(
        self,
        last_position=0,
        batch_size=None
    ):

        if not self.log_file_path:
            return [], last_position

        if not os.path.exists(
            self.log_file_path
        ):
            return [], last_position

        try:
            with open(
                self.log_file_path,
                "r",
                errors="replace"
            ) as f:

                lines = f.readlines()

            new_lines = lines[last_position:]

            if batch_size:
                new_lines = new_lines[:batch_size]

            logs = []

            for line in new_lines:
                line = line.strip()

                if line:
                    logs.append(
                        self._parse_windows_line(line)
                    )

            return logs, last_position + len(new_lines)

        except:
            return [], last_position

    # =====================================================
    # COUNT
    # =====================================================
    def get_log_count(self):
        return len(self.raw_logs)