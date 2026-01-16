from log_collector import collect_logs
from parsers.macos_parser import normalize_macos_log
from detection.rule_engine import run_rules
from detection.anomaly_detection import AnomalyDetector
from alerting.alert_manager import AlertManager
from dashboard.dashboard_data import store_dashboard_data
from config.settings import EMAIL_CONFIG
from collections import Counter

def print_alert_summary(all_alerts):
    if not all_alerts:
        print("\n================ ALERT SUMMARY =================")
        print("No alerts generated.")
        print("================================================")
        return

    severity_count = Counter(alert["severity"] for alert in all_alerts)
    rule_count = Counter(alert["rule_name"] for alert in all_alerts)

    hosts = []
    for alert in all_alerts:
        for ev in alert.get("evidence", []):
            if "host" in ev:
                hosts.append(ev["host"])

    host_count = Counter(hosts)

    print("\n================ ALERT SUMMARY =================")
    print(f"Total Alerts        : {len(all_alerts)}")
    print(f"High Severity       : {severity_count.get('HIGH', 0)}")
    print(f"Medium Severity     : {severity_count.get('MEDIUM', 0)}")
    print(f"Low Severity        : {severity_count.get('LOW', 0)}")

    print("\nAlert Breakdown:")
    for rule, count in rule_count.items():
        print(f"- {rule:<30} : {count}")

    if host_count:
        print("\nTop Affected Hosts:")
        for host, count in host_count.most_common(3):
            print(f"- {host} : {count} events")

    print("================================================")


def main():
    # -------- Phase 1 --------
    raw_logs = collect_logs()
    print(f"[+] Collected {len(raw_logs)} raw logs")

    # -------- Phase 2 --------
    normalized_events = [
        normalize_macos_log(log["raw_event"])
        for log in raw_logs
        if normalize_macos_log(log["raw_event"])
    ]
    print(f"[+] Normalized {len(normalized_events)} events")

    # -------- Phase 3 --------
    alerts = run_rules(normalized_events)
    print(f"[!] Rule alerts: {len(alerts)}")

    # -------- Phase 4 --------
    detector = AnomalyDetector()
    detector.train(normalized_events)
    anomalies = detector.detect(normalized_events)
    print(f"[ML] Anomalies: {len(anomalies)}")

    # -------- Phase 5 --------
    alert_manager = AlertManager(email_config=EMAIL_CONFIG)

    all_alerts = []

    # --- Rule-based alerts ---
    for alert in alerts:
        alert_manager.send_alert(alert)
        all_alerts.append(alert)

    # --- ML anomaly alerts ---
    for anomaly in anomalies:
        ml_alert = {
            "rule_name": "ML Anomaly Detected",
            "severity": "MEDIUM",
            "description": "Anomalous behavior detected",
            "timestamp": anomaly["event"]["timestamp"],
            "evidence": [anomaly["event"]]
    }
    alert_manager.send_alert(ml_alert)
    all_alerts.append(ml_alert)


    for anomaly in anomalies:
        ml_alert = {
            "rule_name": "ML Anomaly Detected",
            "severity": "MEDIUM",
            "description": "Anomalous behavior detected",
            "timestamp": anomaly["event"]["timestamp"],
            "evidence": [anomaly["event"]]
        }
        alert_manager.send_alert(ml_alert)

    # -------- Dashboard Feed --------
    store_dashboard_data(normalized_events, alerts, anomalies)

    print_alert_summary(all_alerts)

if __name__ == "__main__":
    main()



