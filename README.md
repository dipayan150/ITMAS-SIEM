# ITMAS — Intelligent Threat Monitoring and Alerting System

ITMAS is a Python-based SIEM-style security monitoring system that performs:

- Centralized log ingestion (macOS compatible)
- Log parsing & normalization
- Rule-based threat detection
- Machine-learning-based anomaly detection
- Automated alerting (SOAR-style)

## Architecture

Log Sources → Ingestion → Parsing → Detection (Rules + ML) → Alerting


## Features

- macOS unified log support
- Brute-force attack detection
- Isolation Forest anomaly detection
- Severity-based alert routing
- Modular, extensible design

## Tech Stack

- Python 3
- scikit-learn
- Regex parsing
- Isolation Forest
- SMTP alerting

## How to Run

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python log_collector.py

## Future Enhancements
- Slack / Webhook alerts
- Phishing detection (NLP)
- Dashboard visualization
- Alert persistence (SQLite)
