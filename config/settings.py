import os

# -------- Paths --------
LOG_DIR = "data/raw_logs"

# -------- ML --------
ANOMALY_CONTAMINATION = 0.02

# -------- Alerting --------
EMAIL_CONFIG = {
    "server": "smtp.gmail.com",
    "port": 587,
    "from": os.getenv("ITMAS_EMAIL_USER"),
    "to": os.getenv("ITMAS_EMAIL_USER"),
    "username": os.getenv("ITMAS_EMAIL_USER"),
    "password": os.getenv("ITMAS_EMAIL_PASS")
}

# -------- Detection Thresholds --------
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 300
