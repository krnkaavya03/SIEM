"""
core/windows_event_collector.py
Windows Event Log collector for SIEM Hybrid Framework.

Supports:
  - Local Windows Event Log via pywin32 (win32evtlog)
  - Remote via WMI (wmi) or SSH fallback (paramiko + PowerShell)

Event ID mapping (Security log):
  4624 → LOGIN_SUCCESS
  4625 → LOGIN_FAILED
  4634 → LOGOUT
  4648 → LOGIN_SUCCESS (explicit credentials)
  4672 → PRIVILEGE_ESCALATION (special privileges assigned)
  4698 → FILE_ACCESS (scheduled task created)
  4720 → OTHER (user account created)

Usage:
    collector = WindowsEventCollector()
    events = collector.collect(max_events=100)   # local
    events = collector.collect_remote(server, user, password, max_events=50)
"""

import logging
import re
from datetime import datetime

logger = logging.getLogger("WindowsEventCollector")
logging.basicConfig(level=logging.INFO, format="[%(name)s] %(message)s")

CHANNEL       = "Security"
MAX_EVENTS    = 50

# Map Windows Event IDs → SIEM event types
EVENT_ID_MAP = {
    4624: "LOGIN_SUCCESS",
    4625: "LOGIN_FAILED",
    4634: "LOGOUT",
    4647: "LOGOUT",
    4648: "LOGIN_SUCCESS",
    4672: "PRIVILEGE_ESCALATION",
    4673: "PRIVILEGE_ESCALATION",
    4688: "FILE_ACCESS",       # process creation
    4698: "FILE_ACCESS",       # scheduled task
    4720: "OTHER",
    4723: "OTHER",
    4740: "OTHER",             # account lockout
}

LOGON_TYPES = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    10: "RemoteInteractive",
    11: "CachedInteractive",
}


def _ts_to_str(ts) -> str:
    try:
        return ts.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _win32_event_to_siem(record, channel: str = "Security") -> dict:
    """Convert a pywin32 EventLogRecord to a SIEM event dict."""
    event_id  = record.EventID & 0xFFFF
    event_type = EVENT_ID_MAP.get(event_id, "OTHER")
    timestamp  = _ts_to_str(record.TimeGenerated)
    raw_msg    = "\n".join(record.StringInserts or [])

    username = "N/A"
    ip_address = "N/A"

    inserts = record.StringInserts or []

    # Most security events have subject/target account at inserts[0] or [5]
    if event_id in (4624, 4625, 4634, 4648):
        # 4624: [0]=SubjectUserSid [1]=SubjectUserName [2]=SubjectDomainName ...
        #        [5]=TargetUserName [8]=LogonType [18]=IpAddress
        if len(inserts) > 5 and inserts[5] not in ("-", ""):
            username = inserts[5]
        elif len(inserts) > 1:
            username = inserts[1]
        if len(inserts) > 18:
            ip_address = inserts[18] if inserts[18] not in ("-", "::1") else "127.0.0.1"

    elif event_id == 4672:
        if len(inserts) > 1:
            username = inserts[1]

    # Clean up username
    if username in ("-", "", None):
        username = "N/A"

    return {
        "event_type":    event_type,
        "event_id":      event_id,
        "ip_address":    ip_address,
        "username":      username,
        "timestamp_str": timestamp,
        "raw":           raw_msg[:200],
        "channel":       channel,
        "source":        "windows_event_log",
    }


class WindowsEventCollector:
    """
    Collects Windows Security Event Log entries and converts them to SIEM events.
    Works locally (pywin32) or remotely (Paramiko + PowerShell).
    """

    def __init__(self):
        self._pywin32_available  = self._check_pywin32()
        self._paramiko_available = self._check_paramiko()

    # ---- Public API ----

    def collect(self, channel: str = CHANNEL, max_events: int = MAX_EVENTS) -> list:
        """
        Collect recent events from the local Windows Event Log.
        Returns list of SIEM event dicts.
        """
        if not self._pywin32_available:
            logger.warning("pywin32 not installed — install with: pip install pywin32")
            return []
        return self._collect_local(channel, max_events)

    def collect_remote(self, server: str, username: str, password: str,
                       channel: str = CHANNEL,
                       max_events: int = MAX_EVENTS) -> list:
        """
        Collect event log from a remote Windows server over SSH (Paramiko + PowerShell).
        Returns list of SIEM event dicts.
        """
        if not self._paramiko_available:
            logger.warning("paramiko not installed — install with: pip install paramiko")
            return []
        return self._collect_remote_ssh(server, username, password, channel, max_events)

    def get_status(self) -> dict:
        return {
            "local_available":  self._pywin32_available,
            "remote_available": self._paramiko_available,
        }

    # ---- Local collection ----

    def _collect_local(self, channel: str, max_events: int) -> list:
        try:
            import win32evtlog
            import win32con
        except ImportError:
            return []

        events = []
        flags  = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        try:
            handle = win32evtlog.OpenEventLog(None, channel)
            total  = win32evtlog.GetNumberOfEventLogRecords(handle)
            logger.info(f"Windows Event Log '{channel}': {total} total records, reading up to {max_events}")

            collected = 0
            while collected < max_events:
                records = win32evtlog.ReadEventLog(handle, flags, 0)
                if not records:
                    break
                for record in records:
                    if collected >= max_events:
                        break
                    event_id = record.EventID & 0xFFFF
                    if event_id in EVENT_ID_MAP:
                        events.append(_win32_event_to_siem(record, channel))
                    collected += 1

            win32evtlog.CloseEventLog(handle)
            logger.info(f"Collected {len(events)} relevant events from local Windows Event Log")

        except Exception as e:
            logger.error(f"Windows Event Log read failed: {e}")

        return events

    # ---- Remote collection via SSH + PowerShell ----

    def _collect_remote_ssh(self, server: str, username: str, password: str,
                             channel: str, max_events: int) -> list:
        """
        Run PowerShell Get-EventLog on the remote machine and parse the output.
        """
        try:
            import paramiko
        except ImportError:
            return []

        ps_cmd = (
            f"Get-EventLog -LogName {channel} -Newest {max_events} "
            f"-InstanceId {','.join(str(k) for k in EVENT_ID_MAP.keys())} | "
            f"Select-Object TimeGenerated,EventID,UserName,Message | "
            f"ConvertTo-Csv -NoTypeInformation"
        )
        cmd = f'powershell -Command "{ps_cmd}"'

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(server, username=username, password=password, timeout=15)
            _, stdout, stderr = client.exec_command(cmd, timeout=30)
            output = stdout.read().decode("utf-8", errors="replace")
            err    = stderr.read().decode("utf-8", errors="replace")
            client.close()

            if err and "error" in err.lower():
                logger.warning(f"Remote PowerShell stderr: {err[:200]}")

            return self._parse_ps_csv(output, channel)

        except Exception as e:
            logger.error(f"Remote Windows Event Log collection failed: {e}")
            return []

    def _parse_ps_csv(self, csv_text: str, channel: str) -> list:
        """Parse PowerShell CSV output into SIEM event dicts."""
        lines = [l.strip() for l in csv_text.strip().splitlines() if l.strip()]
        if len(lines) < 2:
            return []

        headers = [h.strip('"').lower() for h in lines[0].split(",")]
        events  = []

        for line in lines[1:]:
            parts = [p.strip('"') for p in line.split(",", len(headers) - 1)]
            row   = dict(zip(headers, parts))

            try:
                event_id = int(row.get("eventid", 0))
            except ValueError:
                continue

            event_type = EVENT_ID_MAP.get(event_id, "OTHER")
            ts_str = row.get("timegenerated", "")
            try:
                ts = datetime.strptime(ts_str[:19], "%m/%d/%Y %H:%M:%S")
                timestamp = ts.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            msg = row.get("message", "")
            ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", msg)

            events.append({
                "event_type":    event_type,
                "event_id":      event_id,
                "ip_address":    ip_match.group(1) if ip_match else "N/A",
                "username":      row.get("username", "N/A") or "N/A",
                "timestamp_str": timestamp,
                "raw":           msg[:200],
                "channel":       channel,
                "source":        "windows_event_log_remote",
            })

        logger.info(f"Parsed {len(events)} events from remote PowerShell output")
        return events

    # ---- Dependency checks ----

    @staticmethod
    def _check_pywin32() -> bool:
        try:
            import win32evtlog
            return True
        except ImportError:
            return False

    @staticmethod
    def _check_paramiko() -> bool:
        try:
            import paramiko
            return True
        except ImportError:
            return False


# ─────────────────────────────────────────────
# Standalone test
# ─────────────────────────────────────────────
if __name__ == "__main__":
    collector = WindowsEventCollector()
    status = collector.get_status()
    print(f"Local collection available : {status['local_available']}")
    print(f"Remote collection available: {status['remote_available']}")

    if status["local_available"]:
        events = collector.collect(max_events=20)
        print(f"\nCollected {len(events)} events:")
        for e in events[:5]:
            print(f"  {e['event_type']:<25} user={e['username']:<15} ip={e['ip_address']}")
    else:
        print("\npywin32 not installed — run on Windows: pip install pywin32")
