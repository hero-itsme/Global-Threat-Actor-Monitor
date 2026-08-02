"""
Lightweight SQLite store for:
  - tracking which article URLs/GUIDs have already been processed (dedup)
  - persisting matched detections for later querying/reporting
"""
import sqlite3
import time
import json
import os
from contextlib import contextmanager

from config.settings import SEEN_ITEMS_DB, DATA_DIR

SCHEMA = """
CREATE TABLE IF NOT EXISTS seen_items (
    item_id TEXT PRIMARY KEY,
    source TEXT,
    title TEXT,
    url TEXT,
    first_seen_ts REAL
);

CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id TEXT,
    source TEXT,
    title TEXT,
    url TEXT,
    published TEXT,
    apt_groups TEXT,       -- JSON list
    techniques TEXT,       -- JSON list of {id, name, tactic, kill_chain}
    kill_chain_stages TEXT,-- JSON list
    confidence REAL,
    created_ts REAL,
    alerted INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_detections_created ON detections(created_ts);
"""


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(SEEN_ITEMS_DB)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


@contextmanager
def get_conn():
    conn = sqlite3.connect(SEEN_ITEMS_DB)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def is_seen(item_id: str) -> bool:
    with get_conn() as conn:
        row = conn.execute("SELECT 1 FROM seen_items WHERE item_id = ?", (item_id,)).fetchone()
        return row is not None


def mark_seen(item_id: str, source: str, title: str, url: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO seen_items (item_id, source, title, url, first_seen_ts) VALUES (?, ?, ?, ?, ?)",
            (item_id, source, title, url, time.time()),
        )


def save_detection(item_id, source, title, url, published, apt_groups, techniques, kill_chain_stages, confidence):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO detections
               (item_id, source, title, url, published, apt_groups, techniques, kill_chain_stages, confidence, created_ts, alerted)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
            (
                item_id, source, title, url, published,
                json.dumps(apt_groups), json.dumps(techniques), json.dumps(kill_chain_stages),
                confidence, time.time(),
            ),
        )


def mark_alerted(item_id: str):
    with get_conn() as conn:
        conn.execute("UPDATE detections SET alerted = 1 WHERE item_id = ?", (item_id,))


def recent_detections(limit=50):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM detections ORDER BY created_ts DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
