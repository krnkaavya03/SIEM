"""
core/syslog_collector.py
UDP/TCP Syslog listener for SIEM Hybrid Framework.
Receives RFC-3164 / RFC-5424 syslog messages from routers, firewalls,
Linux hosts, and network appliances.

Usage (blocking):
    collector = SyslogCollector(host="0.0.0.0", port=514, protocol="udp")
    for message in collector.listen():
        print(message)          # each item is a parsed dict

Usage (background thread — feed directly into SIEM pipeline):
    collector = SyslogCollector()
    collector.start_background()
    ...
    logs = collector.drain()    # get buffered messages
    collector.stop()
"""

import socket
import threading
import logging
import re
from datetime import datetime
from collections import deque

logger = logging.getLogger("SyslogCollector")
logging.basicConfig(level=logging.INFO, format="[%(name)s] %(message)s")

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 514
BUFFER_SIZE  = 4096
MAX_BUFFER   = 10_000      # ring buffer cap

# RFC-3164 syslog pattern: <PRI>Mon DD HH:MM:SS HOST TAG: MSG
SYSLOG_RE = re.compile(
    r"^<(\d{1,3})>"                                      # priority
    r"(?:(\d{4})\s+)?"                                   # optional year (some impls)
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"        # timestamp
    r"(\S+)\s+"                                          # hostname
    r"(\S+?)(?:\[(\d+)\])?:\s+"                         # tag[pid]
    r"(.*)"                                              # message
)

# RFC-5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
SYSLOG5424_RE = re.compile(
    r"^<(\d{1,3})>(\d+)\s+"
    r"(\S+)\s+"        # timestamp
    r"(\S+)\s+"        # hostname
    r"(\S+)\s+"        # appname
    r"(\S+)\s+"        # procid
    r"(\S+)\s+"        # msgid
    r"(\S+)\s*"        # structured data
    r"(.*)"            # message
)


def _parse_priority(pri: int) -> tuple:
    facility = pri >> 3
    severity  = pri & 0x07
    fac_names = {
        0:"kern", 1:"user", 4:"auth", 9:"clock", 10:"authpriv",
        11:"ftp", 16:"local0", 17:"local1", 18:"local2", 19:"local3",
        20:"local4", 21:"local5", 22:"local6", 23:"local7",
    }
    sev_names = {
        0:"EMERGENCY", 1:"ALERT", 2:"CRITICAL", 3:"ERROR",
        4:"WARNING",   5:"NOTICE", 6:"INFO",    7:"DEBUG",
    }
    return fac_names.get(facility, str(facility)), sev_names.get(severity, str(severity))


def _syslog_to_siem(raw: str, source_ip: str) -> dict:
    """
    Parse a raw syslog line and return a SIEM-compatible event dict.
    Falls back to a generic event if the format is unrecognised.
    """
    raw = raw.strip()
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    event_type    = "OTHER"
    username      = "N/A"
    hostname      = source_ip
    message       = raw
    facility      = "unknown"
    sev_label     = "INFO"

    m = SYSLOG5424_RE.match(raw) or SYSLOG_RE.match(raw)
    if m:
        groups = m.groups()
        try:
            pri = int(groups[0])
            facility, sev_label = _parse_priority(pri)
        except Exception:
            pass
        if len(groups) >= 4:
            hostname = groups[3] or source_ip
        message = groups[-1] or raw

    # Map syslog severity → SIEM event type
    msg_lower = message.lower()
    if any(k in msg_lower for k in ("failed password", "authentication failure",
                                     "invalid user", "login failed")):
        event_type = "LOGIN_FAILED"
        m2 = re.search(r"(?:user|for)\s+(\S+)", msg_lower)
        if m2:
            username = m2.group(1)

    elif any(k in msg_lower for k in ("accepted password", "session opened",
                                       "login successful", "logged in")):
        event_type = "LOGIN_SUCCESS"
        m2 = re.search(r"(?:for user|user)\s+(\S+)", msg_lower)
        if m2:
            username = m2.group(1)

    elif any(k in msg_lower for k in ("sudo:", "privilege", "su:", "runas")):
        event_type = "PRIVILEGE_ESCALATION"

    elif any(k in msg_lower for k in ("disconnected", "session closed", "logout")):
        event_type = "LOGOUT"

    elif any(k in msg_lower for k in ("open", "read", "write", "file", "access")):
        event_type = "FILE_ACCESS"

    # Extract IP from message if present
    ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", message)
    detected_ip = ip_match.group(1) if ip_match else source_ip

    return {
        "event_type":    event_type,
        "ip_address":    detected_ip,
        "username":      username,
        "hostname":      hostname,
        "timestamp_str": timestamp_str,
        "raw":           raw,
        "facility":      facility,
        "syslog_severity": sev_label,
        "source":        "syslog",
    }


class SyslogCollector:
    """
    Listens for syslog messages over UDP or TCP and converts them to SIEM events.
    """

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 protocol: str = "udp"):
        self.host     = host
        self.port     = port
        self.protocol = protocol.lower()
        self._buffer  = deque(maxlen=MAX_BUFFER)
        self._running = False
        self._thread  = None

    # ---- Public API ----

    def listen(self):
        """
        Blocking generator — yields parsed event dicts as they arrive.
        Use start_background() for non-blocking operation.
        """
        if self.protocol == "udp":
            yield from self._listen_udp()
        else:
            yield from self._listen_tcp()

    def start_background(self):
        """Start listening in a daemon thread. Messages buffered via drain()."""
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(target=self._background_loop, daemon=True)
        self._thread.start()
        logger.info(f"Syslog listener started on {self.protocol.upper()}:{self.port}")

    def drain(self) -> list:
        """Return and clear all buffered messages."""
        msgs = list(self._buffer)
        self._buffer.clear()
        return msgs

    def stop(self):
        """Signal the background thread to stop."""
        self._running = False
        logger.info("Syslog listener stopping...")

    def get_status(self) -> dict:
        return {
            "running":    self._running,
            "protocol":   self.protocol.upper(),
            "host":       self.host,
            "port":       self.port,
            "buffered":   len(self._buffer),
        }

    # ---- Internal ----

    def _background_loop(self):
        for event in self.listen():
            if not self._running:
                break
            self._buffer.append(event)

    def _listen_udp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(2.0)
        try:
            sock.bind((self.host, self.port))
            logger.info(f"UDP syslog listening on {self.host}:{self.port}")
            while self._running or self._running is None:
                try:
                    data, addr = sock.recvfrom(BUFFER_SIZE)
                    raw = data.decode("utf-8", errors="replace")
                    yield _syslog_to_siem(raw, addr[0])
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.warning(f"UDP receive error: {e}")
        finally:
            sock.close()

    def _listen_tcp(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.settimeout(2.0)
        try:
            server.bind((self.host, self.port))
            server.listen(10)
            logger.info(f"TCP syslog listening on {self.host}:{self.port}")
            while self._running or self._running is None:
                try:
                    conn, addr = server.accept()
                    threading.Thread(
                        target=self._handle_tcp_client,
                        args=(conn, addr),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
        finally:
            server.close()

    def _handle_tcp_client(self, conn, addr):
        buf = b""
        try:
            while True:
                chunk = conn.recv(BUFFER_SIZE)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    raw = line.decode("utf-8", errors="replace")
                    if raw.strip():
                        self._buffer.append(_syslog_to_siem(raw, addr[0]))
        except Exception as e:
            logger.debug(f"TCP client {addr}: {e}")
        finally:
            conn.close()


# ─────────────────────────────────────────────
# Standalone test — inject a fake syslog line
# ─────────────────────────────────────────────
if __name__ == "__main__":
    test_lines = [
        "<34>Mar 30 14:22:01 192.168.1.1 sshd[12345]: Failed password for john from 45.22.11.9 port 4444 ssh2",
        "<86>Mar 30 14:23:10 server01 sudo: kaavya : command not allowed ; TTY=pts/0 ; USER=root",
        "<38>Mar 30 14:24:55 webserver nginx[987]: Accepted password for alice from 10.0.0.5 port 22 ssh2",
    ]
    for line in test_lines:
        result = _syslog_to_siem(line, "192.168.1.1")
        print(f"  {result['event_type']:<25} user={result['username']:<12} ip={result['ip_address']}")
