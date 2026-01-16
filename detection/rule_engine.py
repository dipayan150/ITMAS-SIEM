from collections import defaultdict
from datetime import datetime, timedelta
import uuid

# -----------------------------
# Rule: Brute Force SSH Attempts
# -----------------------------
def detect_bruteforce(events, threshold=5, window_seconds=300):
    alerts = []
    failures = defaultdict(list)

    for event in events:
        if event["event_type"] == "AUTH_FAILURE":
            failures[event["host"]].append(event)

    for host, events in failures.items():
        events.sort(key=lambda x: x["timestamp"])

        for i in range(len(events)):
            window_start = datetime.fromisoformat(events[i]["timestamp"])
            window_end = window_start + timedelta(seconds=window_seconds)

            window_events = [
                e for e in events
                if window_start <= datetime.fromisoformat(e["timestamp"]) <= window_end
            ]

            if len(window_events) >= threshold:
                alerts.append(create_alert(
                    rule_name="Brute Force Login Attempt",
                    severity="HIGH",
                    description=f"{len(window_events)} failed logins detected on {host}",
                    evidence=window_events
                ))
                break

    return alerts


# -----------------------------
# Rule: Excessive System Errors
# -----------------------------
def detect_system_errors(events, threshold=20):
    alerts = []

    error_events = [e for e in events if e["event_type"] == "SYSTEM_ERROR"]

    if len(error_events) >= threshold:
        alerts.append(create_alert(
            rule_name="Excessive System Errors",
            severity="MEDIUM",
            description=f"{len(error_events)} system errors detected",
            evidence=error_events[:10]
        ))

    return alerts


# -----------------------------
# Alert Factory
# -----------------------------
def create_alert(rule_name, severity, description, evidence):
    return {
        "alert_id": str(uuid.uuid4()),
        "rule_name": rule_name,
        "severity": severity,
        "description": description,
        "timestamp": datetime.utcnow().isoformat(),
        "evidence": evidence
    }


# -----------------------------
# Run All Rules
# -----------------------------
def run_rules(events):
    alerts = []
    alerts.extend(detect_bruteforce(events))
    alerts.extend(detect_system_errors(events))
    return alerts

def anomaly_to_alert(anomaly):
    return {
        "alert_id": "ML-" + anomaly["event"]["timestamp"],
        "rule_name": "ML Anomaly Detected",
        "severity": "MEDIUM",
        "description": "Unusual system behavior detected",
        "timestamp": anomaly["event"]["timestamp"],
        "evidence": [anomaly["event"]]
    }
