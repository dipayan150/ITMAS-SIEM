import smtplib
from email.message import EmailMessage
from datetime import datetime
import json

class AlertManager:
    def __init__(self, email_config=None):
        self.email_config = email_config

    def send_alert(self, alert):
        severity = alert.get("severity", "INFO")

        self.print_alert(alert)

        if severity == "HIGH" and self.email_config:
            self.send_email(alert)

    def print_alert(self, alert):
        print("\n" + "=" * 60)
        print(f"[ALERT] {alert['rule_name']} ({alert['severity']})")
        print(f"Time: {alert['timestamp']}")
        print(f"Description: {alert['description']}")
        print("=" * 60)

    def send_email(self, alert):
        msg = EmailMessage()
        msg["Subject"] = f"[ITMAS ALERT] {alert['rule_name']}"
        msg["From"] = self.email_config["from"]
        msg["To"] = self.email_config["to"]

        msg.set_content(json.dumps(alert, indent=2))

        with smtplib.SMTP(self.email_config["server"], self.email_config["port"]) as server:
            server.starttls()
            server.login(
                self.email_config["username"],
                self.email_config["password"]
            )
            server.send_message(msg)
