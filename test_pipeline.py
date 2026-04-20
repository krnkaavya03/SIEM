"""
test_pipeline.py — SIEMSecure Full Pipeline Test Suite
=======================================================
Generates realistic log files for all 3 formats, then runs each through
the full 6-step SIEM pipeline and reports results.

Run:
    python test_pipeline.py
    python test_pipeline.py --verbose
    python test_pipeline.py --only linux
    python test_pipeline.py --only windows
    python test_pipeline.py --only custom
"""

import sys
import os
import json
import time
import argparse
from datetime import datetime, timedelta
from collections import defaultdict

# ── Path setup ────────────────────────────────────────────
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

import config
from core.log_parser      import LogParser
from core.detection_engine    import DetectionEngine
from core.correlation_engine  import CorrelationEngine
from core.alert_manager       import AlertManager
from core.statistics_engine   import StatisticsEngine

LOGS_DIR = os.path.join(ROOT, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)

VERBOSE = False

# ─────────────────────────────────────────────────────────
# COLOUR HELPERS
# ─────────────────────────────────────────────────────────
def _c(text, code): return f"\033[{code}m{text}\033[0m"
def red(t):    return _c(t, 91)
def green(t):  return _c(t, 92)
def yellow(t): return _c(t, 93)
def cyan(t):   return _c(t, 96)
def bold(t):   return _c(t, 1)

SEV_COLOR = {
    "CRITICAL": red,
    "HIGH":     lambda t: _c(t, 91),
    "MEDIUM":   yellow,
    "LOW":      green,
}

# ─────────────────────────────────────────────────────────
# LOG GENERATORS
# ─────────────────────────────────────────────────────────

def _ts(delta_minutes=0):
    """Return a timestamp string offset from now."""
    dt = datetime.now() - timedelta(minutes=delta_minutes)
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def _auth_ts(delta_minutes=0):
    """auth.log style timestamp: 'Mar 31 14:22:01'"""
    dt = datetime.now() - timedelta(minutes=delta_minutes)
    return dt.strftime("%b %d %H:%M:%S").replace(" 0", "  ")


def generate_linux_auth_log(path):
    """
    Generate a realistic /var/log/auth.log file covering:
      - Brute force attacks (5+ failed logins from same IP)
      - Successful logins (normal and from suspicious hour)
      - Privilege escalation (sudo)
      - Multiple IPs per user
      - Blacklisted IP access attempt
      - Invalid user attempts
    """
    lines = []

    # 1. Brute force: attacker from 203.0.113.45 (blacklisted) fails 6 times then succeeds
    for i in range(6):
        lines.append(f"{_auth_ts(60-i)} server01 sshd[1001]: Failed password for admin from 203.0.113.45 port {4000+i} ssh2")
    lines.append(f"{_auth_ts(53)} server01 sshd[1001]: Accepted password for admin from 203.0.113.45 port 4006 ssh2")

    # 2. Normal user logins from two different IPs (triggers MULTIPLE_IPS correlation)
    lines.append(f"{_auth_ts(50)} server01 sshd[1002]: Accepted password for alice from 10.0.0.10 port 22 ssh2")
    lines.append(f"{_auth_ts(45)} server01 sshd[1003]: Accepted password for alice from 192.168.1.55 port 22 ssh2")

    # 3. Privilege escalation after failed login (triggers correlation)
    lines.append(f"{_auth_ts(40)} server01 sshd[1004]: Failed password for bob from 10.0.0.20 port 22 ssh2")
    lines.append(f"{_auth_ts(39)} server01 sshd[1004]: Accepted password for bob from 10.0.0.20 port 22 ssh2")
    lines.append(f"{_auth_ts(38)} server01 sudo: bob : TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash")

    # 4. Invalid user attempts (common scan pattern)
    for user in ["oracle", "postgres", "ubuntu", "pi", "test"]:
        lines.append(f"{_auth_ts(35)} server01 sshd[1005]: Invalid user {user} from 198.51.100.88 port 22 ssh2")

    # 5. Multiple users from same IP (shared IP correlation)
    lines.append(f"{_auth_ts(30)} server01 sshd[1006]: Accepted password for carol from 10.0.0.50 port 22 ssh2")
    lines.append(f"{_auth_ts(29)} server01 sshd[1007]: Accepted password for dave from 10.0.0.50 port 22 ssh2")
    lines.append(f"{_auth_ts(28)} server01 sshd[1008]: Accepted password for eve from 10.0.0.50 port 22 ssh2")

    # 6. Suspicious hour login (2am)
    suspicious_dt = datetime.now().replace(hour=2, minute=30, second=0)
    sus_ts = suspicious_dt.strftime("%b %d %H:%M:%S").replace(" 0", "  ")
    lines.append(f"{sus_ts} server01 sshd[1009]: Accepted password for frank from 172.16.0.5 port 22 ssh2")

    # 7. Normal successful logouts
    lines.append(f"{_auth_ts(20)} server01 sshd[1002]: Disconnected from user alice 10.0.0.10 port 22")
    lines.append(f"{_auth_ts(15)} server01 sshd[1006]: session closed for user carol")

    # 8. PAM auth failures
    lines.append(f"{_auth_ts(10)} server01 pam_unix[2000]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.199 user=root")

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")

    return len(lines)


def generate_windows_event_log(path):
    """
    Generate a Windows Event Log CSV (as would be returned by PowerShell).
    Covers: login failures, successes, privilege escalation, logouts.
    """
    # We write structured dicts that the parser's _normalise_preparsed handles.
    # This simulates what windows_event_collector returns.
    events = []

    # Brute force from same IP
    for i in range(5):
        events.append({
            "event_type":    "LOGIN_FAILED",
            "event_id":      4625,
            "username":      "Administrator",
            "ip_address":    "203.0.113.45",
            "timestamp_str": _ts(50 - i),
            "source":        "windows_event_log",
            "raw":           f"An account failed to log on. Failure reason: Unknown user name or bad password."
        })

    # Successful login after brute force (correlation attack)
    events.append({
        "event_type":    "LOGIN_SUCCESS",
        "event_id":      4624,
        "username":      "Administrator",
        "ip_address":    "203.0.113.45",
        "timestamp_str": _ts(44),
        "source":        "windows_event_log",
        "raw":           "An account was successfully logged on."
    })

    # Privilege escalation
    events.append({
        "event_type":    "PRIVILEGE_ESCALATION",
        "event_id":      4672,
        "username":      "Administrator",
        "ip_address":    "N/A",
        "timestamp_str": _ts(43),
        "source":        "windows_event_log",
        "raw":           "Special privileges assigned to new logon."
    })

    # Normal user logins
    for user, ip in [("alice", "10.0.0.10"), ("bob", "10.0.0.20"), ("carol", "192.168.1.5")]:
        events.append({
            "event_type":    "LOGIN_SUCCESS",
            "event_id":      4624,
            "username":      user,
            "ip_address":    ip,
            "timestamp_str": _ts(30),
            "source":        "windows_event_log",
            "raw":           "An account was successfully logged on."
        })

    # Multiple users from same IP
    for user in ["dave", "eve"]:
        events.append({
            "event_type":    "LOGIN_SUCCESS",
            "event_id":      4624,
            "username":      user,
            "ip_address":    "10.0.0.50",
            "timestamp_str": _ts(25),
            "source":        "windows_event_log",
            "raw":           "An account was successfully logged on."
        })

    # File access events
    events.append({
        "event_type":    "FILE_ACCESS",
        "event_id":      4688,
        "username":      "Administrator",
        "ip_address":    "N/A",
        "timestamp_str": _ts(20),
        "source":        "windows_event_log",
        "raw":           "A new process has been created. Process: cmd.exe"
    })

    # Logouts
    for user in ["alice", "bob"]:
        events.append({
            "event_type":    "LOGOUT",
            "event_id":      4634,
            "username":      user,
            "ip_address":    "N/A",
            "timestamp_str": _ts(10),
            "source":        "windows_event_log",
            "raw":           "An account was logged off."
        })

    with open(path, "w") as f:
        json.dump(events, f, indent=2)

    return len(events)


def generate_custom_log(path):
    """
    Generate custom structured log format:
    YYYY-MM-DD HH:MM:SS LEVEL EVENT_TYPE user=X ip=Y [path=Z]
    """
    lines = []

    # Brute force
    for i in range(7):
        lines.append(f"{_ts(70-i)} WARN LOGIN_FAILED user=mallory ip=198.51.100.88")

    # Success after brute force
    lines.append(f"{_ts(62)} INFO LOGIN_SUCCESS user=mallory ip=198.51.100.88")

    # Normal activity
    lines.append(f"{_ts(60)} INFO LOGIN_SUCCESS user=alice ip=10.0.1.10")
    lines.append(f"{_ts(55)} INFO LOGIN_SUCCESS user=bob ip=10.0.1.20")
    lines.append(f"{_ts(50)} INFO FILE_ACCESS user=alice ip=10.0.1.10 path=/etc/passwd")
    lines.append(f"{_ts(48)} INFO FILE_ACCESS user=alice ip=10.0.1.10 path=/etc/shadow")

    # Privilege escalation
    lines.append(f"{_ts(45)} CRITICAL PRIVILEGE_ESCALATION user=mallory ip=198.51.100.88")

    # Blacklisted IP
    lines.append(f"{_ts(40)} WARN LOGIN_FAILED user=root ip=192.0.2.199")
    lines.append(f"{_ts(39)} WARN LOGIN_FAILED user=root ip=192.0.2.199")
    lines.append(f"{_ts(38)} WARN LOGIN_FAILED user=root ip=192.0.2.199")

    # Multiple IPs for same user
    lines.append(f"{_ts(35)} INFO LOGIN_SUCCESS user=carol ip=10.0.1.30")
    lines.append(f"{_ts(30)} INFO LOGIN_SUCCESS user=carol ip=172.16.0.5")
    lines.append(f"{_ts(25)} INFO LOGIN_SUCCESS user=carol ip=192.168.5.1")

    # Admin path access
    lines.append(f"{_ts(20)} WARN FILE_ACCESS user=bob ip=10.0.1.20 path=/admin/config")

    # Logouts
    lines.append(f"{_ts(15)} INFO LOGOUT user=alice ip=10.0.1.10")
    lines.append(f"{_ts(10)} INFO LOGOUT user=bob ip=10.0.1.20")

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")

    return len(lines)


# ─────────────────────────────────────────────────────────
# PIPELINE RUNNER
# ─────────────────────────────────────────────────────────

def run_pipeline(name, raw_logs):
    """
    Run the full 6-step SIEM pipeline on a list of raw log entries.
    Returns a result dict.
    """
    t0 = time.time()
    result = {
        "name":          name,
        "raw_count":     len(raw_logs),
        "parsed":        0,
        "detections":    0,
        "correlations":  0,
        "alerts":        0,
        "critical":      0,
        "high":          0,
        "medium":        0,
        "low":           0,
        "alerts_list":   [],
        "errors":        [],
        "elapsed_ms":    0,
    }

    try:
        # Step 2: Parse
        parser = LogParser()
        parsed_logs = parser.parse_logs(raw_logs)
        result["parsed"] = len(parsed_logs)

        if not parsed_logs:
            result["errors"].append("No logs parsed successfully")
            return result

        # Step 3: Detect
        detection_engine = DetectionEngine(test_mode=False)
        detections = detection_engine.analyze_logs(parsed_logs)
        result["detections"] = len(detections)

        # Step 4: Correlate
        correlation_engine = CorrelationEngine()
        correlations = correlation_engine.correlate_events(parsed_logs, detections)
        result["correlations"] = len(correlations)

        # Step 5: Alert
        alert_manager = AlertManager()
        alerts = alert_manager.process_detections(detections, correlations)
        result["alerts"] = len(alerts)
        result["alerts_list"] = alerts

        for a in alerts:
            sev = a.get("severity", "LOW")
            if sev == "CRITICAL": result["critical"] += 1
            elif sev == "HIGH":   result["high"]     += 1
            elif sev == "MEDIUM": result["medium"]   += 1
            else:                 result["low"]      += 1

        # Step 6: Statistics (silent)
        stats_engine = StatisticsEngine()
        stats_engine.generate_statistics(parsed_logs, detections, correlations, alerts)

    except Exception as e:
        import traceback
        result["errors"].append(str(e))
        if VERBOSE:
            traceback.print_exc()

    result["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    return result


# ─────────────────────────────────────────────────────────
# REPORT PRINTER
# ─────────────────────────────────────────────────────────

def print_result(r):
    ok = not r["errors"]
    status = green("PASS") if ok else red("FAIL")
    parse_pct = round(r["parsed"] / r["raw_count"] * 100) if r["raw_count"] else 0

    print(f"\n{'='*65}")
    print(f"  {bold(r['name'])}   [{status}]   {r['elapsed_ms']} ms")
    print(f"{'='*65}")
    print(f"  Logs collected  : {r['raw_count']}")
    print(f"  Logs parsed     : {r['parsed']} ({parse_pct}%)")
    print(f"  Detections      : {r['detections']}")
    print(f"  Correlations    : {r['correlations']}")
    print(f"  Alerts total    : {r['alerts']}")
    print(f"  {'🔴 CRITICAL':<14}: {r['critical']}")
    print(f"  {'🟠 HIGH':<14}: {r['high']}")
    print(f"  {'🟡 MEDIUM':<14}: {r['medium']}")
    print(f"  {'🟢 LOW':<14}: {r['low']}")

    if r["errors"]:
        print(f"\n  {red('Errors:')}")
        for e in r["errors"]:
            print(f"    ✗ {e}")

    if VERBOSE and r["alerts_list"]:
        print(f"\n  {'─'*60}")
        print(f"  {'Alert Detail':}")
        print(f"  {'─'*60}")
        for a in r["alerts_list"]:
            sev = a.get("severity", "LOW")
            col = SEV_COLOR.get(sev, lambda x: x)
            print(f"  {col(f'[{sev:8}]')} {a['type']:11} | {a['rule']:30} | "
                  f"user={a.get('username','N/A'):12} ip={a.get('ip_address','N/A')}")


def print_summary(results):
    total_raw     = sum(r["raw_count"]    for r in results)
    total_parsed  = sum(r["parsed"]       for r in results)
    total_alerts  = sum(r["alerts"]       for r in results)
    total_crit    = sum(r["critical"]     for r in results)
    total_high    = sum(r["high"]         for r in results)
    total_ms      = sum(r["elapsed_ms"]   for r in results)
    passed        = sum(1 for r in results if not r["errors"])

    print(f"\n{'═'*65}")
    print(bold(f"  OVERALL SUMMARY   {passed}/{len(results)} suites passed"))
    print(f"{'═'*65}")
    print(f"  Total logs processed : {total_raw}")
    print(f"  Successfully parsed  : {total_parsed} "
          f"({round(total_parsed/total_raw*100) if total_raw else 0}%)")
    print(f"  Total alerts raised  : {total_alerts}")
    print(f"  Critical             : {total_crit}")
    print(f"  High                 : {total_high}")
    print(f"  Total time           : {total_ms} ms")

    all_rules = defaultdict(int)
    for r in results:
        for a in r["alerts_list"]:
            all_rules[a["rule"]] += 1

    if all_rules:
        print(f"\n  {'─'*60}")
        print(f"  Rules fired across all suites:")
        for rule, count in sorted(all_rules.items(), key=lambda x: -x[1]):
            print(f"    {rule:35} {count:>3} alert(s)")

    print(f"{'═'*65}\n")


# ─────────────────────────────────────────────────────────
# INDIVIDUAL TEST SUITES
# ─────────────────────────────────────────────────────────

def test_linux(verbose=False):
    path = os.path.join(LOGS_DIR, "test_linux_auth.log")
    count = generate_linux_auth_log(path)
    print(f"\n{cyan('[Linux]')} Generated {count} auth.log lines → {path}")

    # Read back as raw text lines (what LogCollector._collect_linux_logs returns)
    from core.log_collector import LogCollector
    collector = LogCollector(log_file_path=path)
    raw_logs = collector._collect_linux_logs()

    return run_pipeline("Linux auth.log", raw_logs)


def test_windows(verbose=False):
    path = os.path.join(LOGS_DIR, "test_windows_events.json")
    count = generate_windows_event_log(path)
    print(f"\n{cyan('[Windows]')} Generated {count} Windows Event log entries → {path}")

    with open(path) as f:
        raw_logs = json.load(f)

    return run_pipeline("Windows Event Log", raw_logs)


def test_custom(verbose=False):
    path = os.path.join(LOGS_DIR, "test_custom.log")
    count = generate_custom_log(path)
    print(f"\n{cyan('[Custom]')} Generated {count} custom log lines → {path}")

    with open(path) as f:
        raw_lines = [line.strip() for line in f if line.strip()]

    return run_pipeline("Custom Format Log", raw_lines)


def test_mixed(verbose=False):
    """
    Mixed test: combine all three log types in a single pipeline run.
    Real-world SIEM deployments ingest from multiple sources simultaneously.
    """
    from core.log_collector import LogCollector

    lpath = os.path.join(LOGS_DIR, "test_linux_auth.log")
    wpath = os.path.join(LOGS_DIR, "test_windows_events.json")
    cpath = os.path.join(LOGS_DIR, "test_custom.log")

    # Ensure all files exist
    generate_linux_auth_log(lpath)
    generate_windows_event_log(wpath)
    generate_custom_log(cpath)

    collector = LogCollector(log_file_path=lpath)
    linux_logs = collector._collect_linux_logs()

    with open(wpath) as f:
        win_logs = json.load(f)

    with open(cpath) as f:
        custom_lines = [line.strip() for line in f if line.strip()]

    all_logs = linux_logs + win_logs + custom_lines
    print(f"\n{cyan('[Mixed]')} Combined: {len(linux_logs)} Linux + {len(win_logs)} Windows + {len(custom_lines)} Custom = {len(all_logs)} total")

    return run_pipeline("Mixed (All Sources)", all_logs)


def test_volume(verbose=False, n=1000):
    """Stress test: generate N log lines and measure throughput."""
    import random

    users    = ["alice", "bob", "carol", "dave", "eve", "mallory", "root", "admin"]
    good_ips = ["10.0.0.1", "10.0.0.2", "192.168.1.10", "172.16.0.5"]
    bad_ips  = ["203.0.113.45", "198.51.100.88", "192.0.2.199"]
    all_ips  = good_ips + bad_ips

    lines = []
    for i in range(n):
        user   = random.choice(users)
        ip     = random.choice(all_ips)
        event  = random.choice(["LOGIN_FAILED", "LOGIN_FAILED", "LOGIN_SUCCESS",
                                 "FILE_ACCESS", "PRIVILEGE_ESCALATION", "LOGOUT"])
        lines.append(f"{_ts(n - i)} INFO {event} user={user} ip={ip}")

    path = os.path.join(LOGS_DIR, f"test_volume_{n}.log")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"\n{cyan('[Volume]')} Generated {n} mixed log lines → {path}")
    return run_pipeline(f"Volume Stress Test ({n} logs)", lines)


# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────

def main():
    global VERBOSE
    parser = argparse.ArgumentParser(description="SIEMSecure Pipeline Test Suite")
    parser.add_argument("--verbose",  action="store_true", help="Show per-alert detail")
    parser.add_argument("--only",     choices=["linux", "windows", "custom", "mixed", "volume"],
                        help="Run only one suite")
    parser.add_argument("--volume-n", type=int, default=1000,
                        help="Number of logs for volume test (default: 1000)")
    args = parser.parse_args()
    VERBOSE = args.verbose

    print(bold("""
╔══════════════════════════════════════════════════════════════╗
║         SIEMSecure — Full Pipeline Test Suite                ║
║  Tests: Linux auth.log | Windows Event Log | Custom Format   ║
╚══════════════════════════════════════════════════════════════╝"""))

    results = []

    suites = {
        "linux":   test_linux,
        "windows": test_windows,
        "custom":  test_custom,
        "mixed":   test_mixed,
        "volume":  lambda v: test_volume(v, n=args.volume_n),
    }

    if args.only:
        to_run = [args.only]
    else:
        to_run = ["linux", "windows", "custom", "mixed", "volume"]

    for suite_name in to_run:
        r = suites[suite_name](VERBOSE)
        print_result(r)
        results.append(r)

    print_summary(results)

    # Exit code: 0 = all pass, 1 = any failure
    if any(r["errors"] for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
    