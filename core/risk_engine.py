"""
core/risk_engine.py  —  SIEMSecure Pro v3.0
Per-user risk scoring and anomaly detection.
Works with zero external dependencies (sklearn optional for better anomaly detection).
"""

import os
import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format="[RiskEngine] %(message)s")
log = logging.getLogger("RiskEngine")

ALERT_HISTORY_DB = "alert_history.json"
ROLLING_DAYS     = 7

SEVERITY_WEIGHTS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

RISK_BUCKETS = [(20, "CRITICAL"), (10, "HIGH"), (5, "MEDIUM"), (1, "LOW"), (0, "CLEAN")]

RISK_COLORS = {
    "CRITICAL": "#e74c3c",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#27ae60",
    "CLEAN":    "#2ecc71",
}


def _level(score: float) -> str:
    for threshold, label in RISK_BUCKETS:
        if score >= threshold:
            return label
    return "CLEAN"


class RiskEngine:

    def __init__(self):
        self._user_alerts: dict = defaultdict(list)
        self._load_history()

    def calculate_risk(self, alerts):
        """Calculate risk score for each alert and user"""
        
        user_scores = {}

        for alert in alerts:
            user = alert.get("username") or alert.get("user") or "unknown"
            severity = alert.get("severity", "LOW")

            # Assign weights
            if severity == "CRITICAL":
                score = 40
            elif severity == "HIGH":
                score = 25
            elif severity == "MEDIUM":
                score = 15
            else:
                score = 5

            user_scores[user] = user_scores.get(user, 0) + score

        # Attach risk score to each alert
        for alert in alerts:
            user = alert.get("username") or alert.get("user") or "unknown"
            alert["risk_score"] = user_scores.get(user, 0)

            # Risk level classification
            if alert["risk_score"] >= 80:
                alert["risk_level"] = "CRITICAL"
            elif alert["risk_score"] >= 50:
                alert["risk_level"] = "HIGH"
            elif alert["risk_score"] >= 25:
                alert["risk_level"] = "MEDIUM"
            else:
                alert["risk_level"] = "LOW"

        return alerts
    # ── Public API ─────────────────────────────────────────────────────────────

    def update(self, alerts: list):
        for alert in alerts:
            user = alert.get("username", "N/A")
            if user and user != "N/A":
                self._user_alerts[user].append(alert)

    def get_score(self, username: str) -> dict:
        cutoff = datetime.now() - timedelta(days=ROLLING_DAYS)
        recent = []
        for a in self._user_alerts.get(username, []):
            ts_str = a.get("timestamp", "")
            try:
                ts = datetime.strptime(ts_str[:19], "%Y-%m-%d %H:%M:%S")
                if ts >= cutoff:
                    recent.append(a)
            except Exception:
                recent.append(a)

        breakdown = defaultdict(int)
        raw_score = 0.0
        for a in recent:
            sev = a.get("severity", "LOW").upper()
            raw_score += SEVERITY_WEIGHTS.get(sev, 1)
            breakdown[sev] += 1

        level = _level(raw_score)
        return {
            "username":    username,
            "raw_score":   round(raw_score, 1),
            "level":       level,
            "color":       RISK_COLORS.get(level, "#888"),
            "alert_count": len(recent),
            "breakdown":   dict(breakdown),
            "window_days": ROLLING_DAYS,
        }

    def get_all_scores(self) -> list:
        profiles = [self.get_score(u) for u in self._user_alerts]
        return sorted(profiles, key=lambda p: p["raw_score"], reverse=True)

    def get_full_report(self) -> dict:
        profiles = self.get_all_scores()
        return {
            "total_users":     len(profiles),
            "critical_users":  sum(1 for p in profiles if p["level"] == "CRITICAL"),
            "high_risk_users": sum(1 for p in profiles if p["level"] == "HIGH"),
            "profiles":        profiles,
            "generated_at":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    def detect_anomalies(self, parsed_logs: list) -> list:
        """Auto-selects Isolation Forest (sklearn) or Z-score fallback."""
        if not parsed_logs:
            return []
        try:
            return self._isolation_forest(parsed_logs)
        except ImportError:
            return self._zscore(parsed_logs)
        except Exception as e:
            log.warning(f"Isolation Forest failed ({e}), using Z-score fallback")
            return self._zscore(parsed_logs)

    # ── Anomaly backends ───────────────────────────────────────────────────────

    def _isolation_forest(self, logs: list) -> list:
        from sklearn.ensemble import IsolationForest
        import numpy as np

        user_hours = defaultdict(list)
        user_fails = defaultdict(int)
        user_ok    = defaultdict(int)

        for log_entry in logs:
            user  = log_entry.get("username", "N/A")
            event = log_entry.get("event_type", "")
            ts    = log_entry.get("timestamp_str", "")
            try:
                h = datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S").hour
                user_hours[user].append(h)
            except Exception:
                pass
            if event == "LOGIN_FAILED":
                user_fails[user] += 1
            elif event == "LOGIN_SUCCESS":
                user_ok[user] += 1

        users = list(set(list(user_hours) + list(user_fails)))
        if len(users) < 3:
            return self._zscore(logs)

        X = []
        for u in users:
            hours = user_hours.get(u, [12])
            avg_h = sum(hours) / len(hours)
            fails = user_fails.get(u, 0)
            total = fails + user_ok.get(u, 0)
            X.append([avg_h, fails, fails / max(total, 1)])

        preds = IsolationForest(contamination=0.15, random_state=42).fit_predict(
            np.array(X)
        )

        anomalies = []
        for i, (u, pred) in enumerate(zip(users, preds)):
            if pred == -1:
                f = X[i]
                anomalies.append({
                    "username":    u,
                    "type":        "ML_ANOMALY",
                    "severity":    "MEDIUM",
                    "method":      "Isolation Forest",
                    "description": (
                        f"Anomalous login pattern for {u} — "
                        f"avg hour: {f[0]:.1f}, fails: {int(f[1])}, "
                        f"fail ratio: {f[2]:.0%}"
                    ),
                })
        return anomalies

    def _zscore(self, logs: list) -> list:
        user_fails = defaultdict(int)
        for entry in logs:
            if entry.get("event_type") == "LOGIN_FAILED":
                user_fails[entry.get("username", "N/A")] += 1
        if len(user_fails) < 2:
            return []
        values = list(user_fails.values())
        mean   = sum(values) / len(values)
        std    = (sum((v - mean)**2 for v in values) / len(values)) ** 0.5
        if std == 0:
            return []
        anomalies = []
        for user, count in user_fails.items():
            z = (count - mean) / std
            if z > 2.0:
                anomalies.append({
                    "username":    user,
                    "type":        "ZSCORE_ANOMALY",
                    "severity":    "MEDIUM" if z < 3 else "HIGH",
                    "method":      "Z-score",
                    "description": f"High failed logins for {user}: {count} (Z={z:.1f})",
                })
        return anomalies

    # ── Persistence ────────────────────────────────────────────────────────────

    def _load_history(self):
        if not os.path.exists(ALERT_HISTORY_DB):
            return
        try:
            with open(ALERT_HISTORY_DB) as f:
                history = json.load(f)
            for alert in history:
                user = alert.get("username", "N/A")
                if user and user != "N/A":
                    self._user_alerts[user].append(alert)
        except Exception as e:
            log.warning(f"Could not load alert history: {e}")