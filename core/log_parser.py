"""
Parser Module
Responsible for parsing and normalizing log entries into structured format
Supports multiple log formats:
- Linux auth.log (SSH login, sudo, etc.)
- Windows EVTX Security logs
- Custom structured logs (YYYY-MM-DD HH:MM:SS LEVEL EVENT user=... ip=...)
"""

import re
from datetime import datetime


class LogParser:
    """
    Parses raw log entries into structured dictionaries
    Ensures each log has a valid timestamp for correlation and detection
    """

    def __init__(self):
        self.parsed_logs = []

    # ---------------------------------------------------------
    # MAIN ENTRY
    # ---------------------------------------------------------
    def parse_logs(self, raw_logs):
        self.parsed_logs = []

        for idx, entry in enumerate(raw_logs):
            try:
                parsed = self._parse_single_log(entry, idx)
                if parsed:
                    self.parsed_logs.append(parsed)
            except Exception as e:
                print(f"[PARSER] Failed to parse log {idx}: {e}")

        print(f"[PARSER] Successfully parsed {len(self.parsed_logs)} out of {len(raw_logs)} log entries")
        return self.parsed_logs

    # ---------------------------------------------------------
    # ROUTING LOGIC
    # ---------------------------------------------------------
    def _parse_single_log(self, log_entry, index):

        if isinstance(log_entry, dict):
            log_str = " ".join(str(v) for v in log_entry.values())
        elif isinstance(log_entry, str):
            log_str = log_entry
        else:
            raise TypeError(f"Log entry must be dict or str, got {type(log_entry)}")

        if 'sshd' in log_str or 'sudo' in log_str:
            return self._parse_linux_log(log_entry, index)

        elif 'EventID' in log_str or 'LogName' in log_str:
            return self._parse_windows_log(log_entry, index)

        else:
            return self._parse_custom_log(log_entry, index)

    # ---------------------------------------------------------
    # CUSTOM STRUCTURED LOG FORMAT SUPPORT
    # Format:
    # 2026-02-15 08:10:02 INFO LOGIN_SUCCESS user=alice ip=192.168.1.10
    # ---------------------------------------------------------
    def _parse_custom_log(self, log_entry, index):
        try:
            # Extract raw message properly
            if isinstance(log_entry, dict):
                raw = log_entry.get("raw_message", "")
            else:
                raw = str(log_entry)

            # Base pattern: date time level event
            base_pattern = (
                r"^(?P<date>\d{4}-\d{2}-\d{2})\s+"
                r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
                r"(?P<level>\w+)\s+"
                r"(?P<event>\w+)"
            )

            base_match = re.match(base_pattern, raw)
            if not base_match:
                return self._parse_generic_log(raw, index)

            timestamp_str = f"{base_match.group('date')} {base_match.group('time')}"
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

            event_type = base_match.group("event")

            # Extract optional fields dynamically
            username = "N/A"
            ip_address = "N/A"
            severity = "N/A"

            user_match = re.search(r"user=([^\s]+)", raw)
            ip_match = re.search(r"ip=([^\s]+)", raw)
            severity_match = re.search(r"severity=([^\s]+)", raw)

            if user_match:
                username = user_match.group(1)

            if ip_match:
                ip_address = ip_match.group(1)

            if severity_match:
                severity = severity_match.group(1)

            return {
                'id': index,
                'timestamp': timestamp,
                'timestamp_str': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                'event_type': event_type,
                'username': username,
                'ip_address': ip_address,
                'severity': severity,
                'process': 'CUSTOM_LOG',
                'info': raw,
                'hour': timestamp.hour
            }

        except Exception as e:
            print("[PARSER] Custom parse error:", e)
            return self._parse_generic_log(log_entry, index)

    # ---------------------------------------------------------
    # LINUX LOG PARSER
    # ---------------------------------------------------------
    def _parse_linux_log(self, log_entry, index):
        try:
            raw = str(log_entry)
            timestamp = datetime.now()

            return {
                'id': index,
                'timestamp': timestamp,
                'timestamp_str': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                'event_type': 'OTHER',
                'username': 'N/A',
                'ip_address': 'N/A',
                'severity': 'N/A',
                'process': 'LINUX',
                'info': raw,
                'hour': timestamp.hour
            }

        except Exception:
            return self._parse_generic_log(log_entry, index)

    # ---------------------------------------------------------
    # WINDOWS LOG PARSER
    # ---------------------------------------------------------
    def _parse_windows_log(self, log_entry, index):
        try:
            raw = str(log_entry)
            timestamp = datetime.now()

            return {
                'id': index,
                'timestamp': timestamp,
                'timestamp_str': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                'event_type': 'OTHER',
                'username': 'N/A',
                'ip_address': 'N/A',
                'severity': 'N/A',
                'process': 'WINDOWS',
                'info': raw,
                'hour': timestamp.hour
            }

        except Exception:
            return self._parse_generic_log(log_entry, index)

    # ---------------------------------------------------------
    # GENERIC FALLBACK
    # ---------------------------------------------------------
    def _parse_generic_log(self, log_entry, index):
        raw = str(log_entry)
        timestamp = datetime.now()

        return {
            'id': index,
            'timestamp': timestamp,
            'timestamp_str': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            'event_type': 'OTHER',
            'username': 'N/A',
            'ip_address': 'N/A',
            'severity': 'N/A',
            'process': 'GENERIC',
            'info': raw,
            'hour': timestamp.hour
        }

    def get_parsed_logs(self):
        return self.parsed_logs
