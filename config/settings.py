"""
Global settings for the Threat Actor Monitor.
All secrets are loaded from environment variables / .env — never hardcode tokens.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# --- Telegram ---
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# --- Polling ---
POLL_INTERVAL_MINUTES = int(os.getenv("POLL_INTERVAL_MINUTES", "10"))
REQUEST_TIMEOUT_SECONDS = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "15"))
MAX_CONCURRENT_FETCHES = int(os.getenv("MAX_CONCURRENT_FETCHES", "8"))

# --- Storage ---
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
SEEN_ITEMS_DB = os.path.join(DATA_DIR, "seen_items.sqlite3")
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
LOG_FILE = os.path.join(LOG_DIR, "monitor.log")

# --- Alert behavior ---
MIN_CONFIDENCE_TO_ALERT = float(os.getenv("MIN_CONFIDENCE_TO_ALERT", "0.35"))
ALERT_BATCH_MAX_PER_CYCLE = int(os.getenv("ALERT_BATCH_MAX_PER_CYCLE", "20"))
