import json
from datetime import datetime

DASHBOARD_FILE = "dashboard/dashboard_data.json"

def store_dashboard_data(events, alerts, anomalies):
    data = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_count": len(events),
        "alert_count": len(alerts),
        "anomaly_count": len(anomalies),
        "alerts": alerts[:5],
        "anomalies": anomalies[:5]
    }

    with open(DASHBOARD_FILE, "w") as f:
        json.dump(data, f, indent=2)
