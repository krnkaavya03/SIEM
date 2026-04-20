"""
Parser Module
Responsible for parsing and normalizing log entries into structured format
Supports multiple log formats:
- Linux auth.log (SSH login, sudo, etc.)
- Windows EVTX Security logs (dict format from log_collector / windows_event_collector)
- Custom structured logs (YYYY-MM-DD HH:MM:SS LEVEL EVENT user=... ip=...)
"""

import re
from datetime import datetime


class LogParser:
    """
    Parses raw log entries into structured dictionaries.
    Ensures each log has a valid timestamp for correlation and detection.
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
        # If the entry already has event_type (pre-parsed by log_collector),
        # normalise it directly — avoids double-parsing.
        if isinstance(log_entry, dict) and 'event_type' in log_entry:
            return self._normalise_preparsed(log_entry, index)

        if isinstance(log_entry, dict):
            log_str = " ".join(str(v) for v in log_entry.values())
        elif isinstance(log_entry, str):
            log_str = log_entry
        else:
            raise TypeError(f"Log entry must be dict or str, got {type(log_entry)}")

        # Route by content signature
        if 'sshd' in log_str or 'sudo' in log_str or 'pam_unix' in log_str:
            return self._parse_linux_log(log_entry, index)
        elif 'EventID' in log_str or 'LogName' in log_str or 'event_id' in log_str:
            return self._parse_windows_log(log_entry, index)
        else:
            return self._parse_custom_log(log_entry, index)

    # ---------------------------------------------------------
    # PRE-PARSED DICT NORMALISER
    # Handles dicts that already have event_type set (from log_collector,
    # windows_event_collector, syslog_collector, etc.)
    # ---------------------------------------------------------
    def _normalise_preparsed(self, log_entry, index):
        # Parse timestamp if it's a datetime object
        ts = log_entry.get('timestamp')
        ts_str = log_entry.get('timestamp_str', '')

        if isinstance(ts, datetime):
            timestamp = ts
            if not ts_str:
                ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
        elif ts_str:
            try:
                timestamp = datetime.strptime(ts_str[:19], "%Y-%m-%d %H:%M:%S")
            except Exception:
                timestamp = datetime.now()
                ts_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        else:
            timestamp = datetime.now()
            ts_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")

        return {
            'id':            index,
            'timestamp':     timestamp,
            'timestamp_str': ts_str,
            'event_type':    log_entry.get('event_type', 'OTHER'),
            'username':      log_entry.get('username', 'N/A') or 'N/A',
            'ip_address':    log_entry.get('ip_address', 'N/A') or 'N/A',
            'severity':      log_entry.get('severity', 'N/A'),
            'process':       log_entry.get('process', log_entry.get('source', 'UNKNOWN')),
            'info':          log_entry.get('raw_message', log_entry.get('raw', '')),
            'hour':          timestamp.hour,
            # preserve extra enrichment fields
            'http_path':     log_entry.get('http_path'),
            'event_id':      log_entry.get('event_id'),
            'channel':       log_entry.get('channel'),
        }

    # ---------------------------------------------------------
    # LINUX AUTH.LOG PARSER
    # Handles lines like:
    #   Mar 31 14:22:01 hostname sshd[1234]: Failed password for john from 1.2.3.4 port 22 ssh2
    #   Mar 31 14:23:10 hostname sudo: alice : TTY=pts/0 ; COMMAND=/bin/bash
    #   Apr  5 09:11:02 hostname sshd[5678]: Accepted password for bob from 10.0.0.5 port 22 ssh2
    # ---------------------------------------------------------
    def _parse_linux_log(self, log_entry, index):
        try:
            raw = log_entry.get('raw_message', '') if isinstance(log_entry, dict) else str(log_entry)

            # RFC-3164 style: "Mon DD HH:MM:SS host service[pid]: message"
            pattern = (
                r"^(?P<month>\w+)\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
                r"(?P<host>\S+)\s+(?P<service>[\w\-/]+)(?:\[\d+\])?:\s+(?P<message>.+)$"
            )
            match = re.match(pattern, raw)
            if not match:
                return self._parse_generic_log(log_entry, index)

            # Build timestamp (no year in auth.log — use current year)
            year = datetime.now().year
            ts_str = f"{match.group('month')} {match.group('day').zfill(2)} {match.group('time')} {year}"
            try:
                timestamp = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y")
            except ValueError:
                timestamp = datetime.now()

            message = match.group('message')
            service = match.group('service')
            username = 'N/A'
            ip_address = 'N/A'
            event_type = 'OTHER'

            # ── SSH events ──
            if 'sshd' in service:
                # Failed password / Invalid user
                m = re.search(
                    r'(?:Failed password for(?: invalid user)?|Invalid user)\s+(\S+)\s+from\s+([\d.]+)',
                    message
                )
                if m:
                    username, ip_address = m.group(1), m.group(2)
                    event_type = 'LOGIN_FAILED'
                else:
                    # Accepted password / publickey
                    m = re.search(
                        r'(?:Accepted password|Accepted publickey) for\s+(\S+)\s+from\s+([\d.]+)',
                        message
                    )
                    if m:
                        username, ip_address = m.group(1), m.group(2)
                        event_type = 'LOGIN_SUCCESS'
                    else:
                        # Disconnected / session closed
                        if re.search(r'(?:Disconnected|session closed|Connection closed)', message):
                            event_type = 'LOGOUT'
                        # pam_unix auth failure
                        m = re.search(r'pam_unix.*?user=(\S+)', message)
                        if m:
                            username = m.group(1)
                            if 'failure' in message.lower():
                                event_type = 'LOGIN_FAILED'

            # ── sudo events ──
            elif 'sudo' in service:
                event_type = 'PRIVILEGE_ESCALATION'
                m = re.search(r'(\S+)\s+:\s+TTY', message)
                if m:
                    username = m.group(1)
                # Extract "COMMAND=..." for info
                cmd_match = re.search(r'COMMAND=(.+)$', message)
                extra_info = cmd_match.group(1) if cmd_match else message

            # ── PAM events ──
            elif 'pam_unix' in service or 'pam' in service.lower():
                if 'authentication failure' in message or 'auth could not identify' in message:
                    event_type = 'LOGIN_FAILED'
                elif 'session opened' in message:
                    event_type = 'LOGIN_SUCCESS'
                elif 'session closed' in message:
                    event_type = 'LOGOUT'
                m = re.search(r'user=(\S+)', message)
                if m:
                    username = m.group(1)

            return {
                'id':            index,
                'timestamp':     timestamp,
                'timestamp_str': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                'event_type':    event_type,
                'username':      username,
                'ip_address':    ip_address,
                'severity':      'N/A',
                'process':       service,
                'info':          message,
                'hour':          timestamp.hour,
                'http_path':     None,
            }

        except Exception as e:
            print(f"[PARSER] Linux parse error: {e}")
            return self._parse_generic_log(log_entry, index)

    # ---------------------------------------------------------
    # WINDOWS EVENT LOG PARSER
    # Handles dicts from windows_event_collector or raw XML strings
    # ---------------------------------------------------------
    def _parse_windows_log(self, log_entry, index):
        try:
            # Dict format (from windows_event_collector)
            if isinstance(log_entry, dict):
                ts = log_entry.get('timestamp') or log_entry.get('timestamp_str', '')
                if isinstance(ts, datetime):
                    timestamp = ts
                    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    try:
                        timestamp = datetime.strptime(str(ts)[:19], "%Y-%m-%d %H:%M:%S")
                        ts_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        timestamp = datetime.now()
                        ts_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")

                event_id = log_entry.get('event_id', 0)
                event_type = log_entry.get('event_type', self._map_windows_event_id(event_id))
                username = log_entry.get('username', 'N/A') or 'N/A'
                ip_address = log_entry.get('ip_address', 'N/A') or 'N/A'
                raw = log_entry.get('raw', log_entry.get('raw_message', ''))

            else:
                # Raw XML string (from older EVTX path)
                raw = str(log_entry)
                ts_match = re.search(r'<TimeCreated SystemTime="([^"]+)"', raw)
                timestamp = datetime.strptime(ts_match.group(1), "%Y-%m-%dT%H:%M:%S.%fZ") \
                    if ts_match else datetime.now()
                ts_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")

                event_id_match = re.search(r'<EventID.*?>(\d+)</EventID>', raw)
                event_id = int(event_id_match.group(1)) if event_id_match else 0
                event_type = self._map_windows_event_id(event_id)

                user_match = re.search(r'<Data Name="TargetUserName">([^<]+)</Data>', raw)
                username = user_match.group(1) if user_match else 'N/A'

                ip_match = re.search(r'<Data Name="IpAddress">([^<]+)</Data>', raw)
                ip_address = ip_match.group(1) if ip_match else 'N/A'
                if ip_address in ('-', '::1', ''):
                    ip_address = 'N/A'

            return {
                'id':            index,
                'timestamp':     timestamp,
                'timestamp_str': ts_str,
                'event_type':    event_type,
                'username':      username,
                'ip_address':    ip_address,
                'severity':      'N/A',
                'process':       'WINDOWS_EVENT',
                'info':          str(raw)[:300],
                'hour':          timestamp.hour,
                'http_path':     None,
                'event_id':      event_id,
            }

        except Exception as e:
            print(f"[PARSER] Windows parse error: {e}")
            return self._parse_generic_log(log_entry, index)

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

    # ---------------------------------------------------------
    # CUSTOM STRUCTURED LOG FORMAT
    # Format: 2026-02-15 08:10:02 INFO LOGIN_SUCCESS user=alice ip=192.168.1.10
    # ---------------------------------------------------------
    def _parse_custom_log(self, log_entry, index):
        try:
            raw = log_entry.get('raw_message', '') if isinstance(log_entry, dict) else str(log_entry)

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
            event_type = base_match.group('event')

            user_match = re.search(r"user=([^\s]+)", raw)
            ip_match   = re.search(r"ip=([^\s]+)", raw)
            sev_match  = re.search(r"severity=([^\s]+)", raw)
            path_match = re.search(r"path=([^\s]+)", raw)

            return {
                'id':            index,
                'timestamp':     timestamp,
                'timestamp_str': timestamp_str,
                'event_type':    event_type,
                'username':      user_match.group(1) if user_match else 'N/A',
                'ip_address':    ip_match.group(1)   if ip_match   else 'N/A',
                'severity':      sev_match.group(1)  if sev_match  else 'N/A',
                'process':       'CUSTOM_LOG',
                'info':          raw,
                'hour':          timestamp.hour,
                'http_path':     path_match.group(1) if path_match else None,
            }

        except Exception as e:
            print(f"[PARSER] Custom parse error: {e}")
            return self._parse_generic_log(log_entry, index)

    # ---------------------------------------------------------
    # GENERIC FALLBACK
    # ---------------------------------------------------------
    def _parse_generic_log(self, log_entry, index):
        raw = str(log_entry)
        timestamp = datetime.now()
        return {
            'id':            index,
            'timestamp':     timestamp,
            'timestamp_str': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            'event_type':    'OTHER',
            'username':      'N/A',
            'ip_address':    'N/A',
            'severity':      'N/A',
            'process':       'GENERIC',
            'info':          raw[:300],
            'hour':          timestamp.hour,
            'http_path':     None,
        }

    def get_parsed_logs(self):
        return self.parsed_logs




        