"""
detection_engine/config.py
All constants and configuration values for the detection engine.
No logic — only values.
"""

import os

# ── Elasticsearch connection ──────────────────────────────────────────────────
ES_HOST = os.environ.get(
    "ES_HOST",
    "http://localhost:9200",  # Default Docker-WSL2 bridge IP
)
ES_RAW_INDEX = "siem-raw-*"
ES_ALERTS_INDEX_PREFIX = "siem-alerts"        # → siem-alerts-YYYY.MM.dd
ES_POLL_BATCH_SIZE = 100

# ── Engine behaviour ──────────────────────────────────────────────────────────
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL", "5"))
STATE_FILE_PATH = "engine_state.json"

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "engine.log")
UNKNOWN_EVENTS_LOG = os.path.join(LOG_DIR, "unknown_events.log")
DROPPED_EVENTS_LOG = os.path.join(LOG_DIR, "dropped_events.log")
ALERTS_BUFFER_FILE = os.path.join(LOG_DIR, "alerts_buffer.jsonl")

# ── Watch list ────────────────────────────────────────────────────────────────
WATCH_LIST_TTL_SECONDS = 300

# ── Rule thresholds ───────────────────────────────────────────────────────────
THRESHOLD_SSH_BRUTEFORCE = 6
THRESHOLD_USER_BRUTEFORCE = 5
THRESHOLD_PASSWORD_SPRAY = 3
THRESHOLD_DISTRIBUTED_BF = 3
THRESHOLD_SUDO_BRUTEFORCE = 3

# ── Rule timeframes (sliding window, seconds) ────────────────────────────────
TIMEFRAME_SSH_BRUTEFORCE = 60
TIMEFRAME_USER_BRUTEFORCE = 60
TIMEFRAME_PASSWORD_SPRAY = 120
TIMEFRAME_DISTRIBUTED_BF = 120
TIMEFRAME_SUDO_BRUTEFORCE = 60

# ── Ignore / suppression windows (seconds) ───────────────────────────────────
IGNORE_SSH_BRUTEFORCE = 60
IGNORE_USER_BRUTEFORCE = 60
IGNORE_PASSWORD_SPRAY = 120
IGNORE_DISTRIBUTED_BF = 120
IGNORE_SUDO_BRUTEFORCE = 60

# ── Allowlist defaults ────────────────────────────────────────────────────────
ALLOWLISTED_IPS = ["127.0.0.1", "::1"]
# ALLOWLISTED_CIDRS = ["10.0.0.0/8"]  # Uncomment for internal-network testing
ALLOWLISTED_CIDRS: list[str] = []
ALLOWLISTED_USERS: list[str] = []
