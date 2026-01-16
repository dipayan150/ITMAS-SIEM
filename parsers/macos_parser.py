import re
from datetime import datetime

MACOS_LOG_PATTERN = re.compile(
    r"""
    ^(?P<month>\w{3})\s+
    (?P<day>\d{1,2})\s+
    (?P<time>\d{2}:\d{2}:\d{2})\s+
    (?P<host>\S+)\s+
    (?P<process>[^\[]+)
    \[(?P<pid>\d+)\]:
    \s+(?P<message>.*)
    """,
    re.VERBOSE
)

MONTH_MAP = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12"
}

def parse_macos_log(raw_event):
    match = MACOS_LOG_PATTERN.match(raw_event)

    if not match:
        return None  # unstructured / non-standard log

    parts = match.groupdict()

    # Build ISO timestamp (year inferred)
    year = datetime.utcnow().year
    timestamp = f"{year}-{MONTH_MAP[parts['month']]}-{parts['day'].zfill(2)}T{parts['time']}"

    return {
        "timestamp": timestamp,
        "host": parts["host"],
        "process": parts["process"].strip(),
        "pid": int(parts["pid"]),
        "message": parts["message"]
    }
def classify_event(message):
    msg = message.lower()

    if "failed password" in msg:
        return "AUTH_FAILURE", "HIGH"
    if "accepted password" in msg:
        return "AUTH_SUCCESS", "LOW"
    if "deny" in msg or "block" in msg or "refused" in msg:
        return "NETWORK_DENY", "MEDIUM"
    if "sudo" in msg or "root" in msg:
        return "PRIV_ESC_ATTEMPT", "HIGH"
    if "error" in msg or "failed" in msg:
        return "SYSTEM_ERROR", "LOW"

    return "INFO", "INFO"


def normalize_macos_log(raw_event):
    parsed = parse_macos_log(raw_event)
    if not parsed:
        return None

    event_type, severity = classify_event(parsed["message"])

    return {
        "timestamp": parsed["timestamp"],
        "host": parsed["host"],
        "process": parsed["process"],
        "pid": parsed["pid"],
        "event_type": event_type,
        "severity": severity,
        "message": parsed["message"]
    }
