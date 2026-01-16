# =========================
# Imports
# =========================
import os
from datetime import datetime

from parsers.macos_parser import normalize_macos_log
from detection.rule_engine import run_rules
from detection.anomaly_detection import AnomalyDetector
from alerting.alert_manager import AlertManager


# =========================
# Phase 1: Log Collection
# =========================
LOG_DIR = "data/raw_logs"

def collect_logs():
    logs = []

    for filename in os.listdir(LOG_DIR):
        filepath = os.path.join(LOG_DIR, filename)

        if not os.path.isfile(filepath):
            continue

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue

                logs.append({
                    "ingest_time": datetime.utcnow().isoformat(),
                    "source": filename,
                    "line_number": line_number,
                    "raw_event": line
                })

    return logs


# =========================
# MAIN PIPELINE
# =========================
if __name__ == "__main__":

    # ---------- Phase 1 ----------
    raw_logs = collect_logs()
    print(f"[+] Collected {len(raw_logs)} raw events")

    # ---------- Phase 2 ----------
    normalized_events = []
    for log in raw_logs:
        event = normalize_macos_log(log["raw_event"])
        if event:
            normalized_events.append(event)

    print(f"[+] Normalized {len(normalized_events)} events")

    # ---------- Phase 3 ----------
    alerts = run_rules(normalized_events)
    print(f"[!] Rule-based alerts: {len(alerts)}")

    # ---------- Phase 4 ----------
    detector = AnomalyDetector()
    detector.train(normalized_events)
    anomalies = detector.detect(normalized_events)
    print(f"[ML] Anomalies detected: {len(anomalies)}")

    # =========================
    # Phase 5 (STEP 5.5) — ALERT AUTOMATION
    # =========================

    email_config = {
        "server": "smtp.gmail.com",
        "port": 587,
        "from": os.getenv("ITMAS_EMAIL_USER"),
        "to": os.getenv("ITMAS_EMAIL_USER"),
        "username": os.getenv("ITMAS_EMAIL_USER"),
        "password": os.getenv("ITMAS_EMAIL_PASS")
    }

    alert_manager = AlertManager(email_config=email_config)

    # --- Rule-based alerts ---
    for alert in alerts:
        alert_manager.send_alert(alert)

    # --- ML anomaly alerts ---
    for anomaly in anomalies:
        ml_alert = {
            "rule_name": "ML Anomaly Detected",
            "severity": "MEDIUM",
            "description": "Unusual behavior detected by ML model",
            "timestamp": anomaly["event"]["timestamp"],
            "evidence": [anomaly["event"]]
        }
        alert_manager.send_alert(ml_alert)
