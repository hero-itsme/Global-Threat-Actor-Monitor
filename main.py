
"""
Global Threat Actor Monitor
============================
Runs the existing CTI pipeline without requiring Telegram.

Features:
  1. Polls configured OSINT sources.
  2. Skips previously processed items using SQLite.
  3. Analyzes new items for APT groups, MITRE ATT&CK techniques,
     and Cyber Kill Chain stages.
  4. Saves relevant detections to SQLite.
  5. Prints detections above the configured confidence threshold
     directly to the terminal.

Usage:
    python main.py --once   # Run one cycle and exit
    python main.py          # Run continuously
"""

import argparse
import asyncio
import logging
import os
import sys
import time

from config.settings import (
    POLL_INTERVAL_MINUTES,
    LOG_FILE,
    LOG_DIR,
    MIN_CONFIDENCE_TO_ALERT,
    ALERT_BATCH_MAX_PER_CYCLE,
)
from core.osint_poller import poll_all_sources
from core.killchain_mapper import analyze
from core.storage import (
    init_db,
    is_seen,
    mark_seen,
    save_detection,
)


# Ensure the log directory exists.
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)

logger = logging.getLogger("threat_monitor.main")


def print_detection(item, detection):
    """Display one CTI detection in the terminal."""

    logger.info("=" * 70)
    logger.info("GLOBAL THREAT ACTOR MONITOR - DETECTION")
    logger.info("=" * 70)
    logger.info("Source: %s", item.get("source", "Unknown"))
    logger.info("Title: %s", item.get("title", "Untitled"))
    logger.info("URL: %s", item.get("url", "Unavailable"))
    logger.info("Published: %s", item.get("published", "Unknown"))
    logger.info("APT groups: %s", detection.apt_groups)
    logger.info("ATT&CK techniques: %s", detection.techniques)
    logger.info("Kill Chain stages: %s", detection.kill_chain_stages)
    logger.info("Confidence: %.2f", detection.confidence)
    logger.info("=" * 70)


async def run_cycle():
    """Run one poll, detect, save, and report cycle."""

    cycle_start = time.time()

    # 1. Collect intelligence from configured OSINT sources.
    items = await poll_all_sources()

    # 2. Remove previously processed items.
    new_items = []

    for item in items:
        item_id = item["item_id"]

        if is_seen(item_id):
            continue

        mark_seen(
            item_id,
            item["source"],
            item["title"],
            item["url"],
        )

        new_items.append(item)

    logger.info("%s new items to analyze this cycle", len(new_items))

    # 3. Analyze each new item using the existing CTI engine.
    relevant = []

    for item in new_items:
        try:
            detection = analyze(item["text"])

            if not detection.is_relevant:
                continue

            # 4. Save relevant detections to the existing SQLite database.
            save_detection(
                item["item_id"],
                item["source"],
                item["title"],
                item["url"],
                item["published"],
                detection.apt_groups,
                detection.techniques,
                detection.kill_chain_stages,
                detection.confidence,
            )

            relevant.append((item, detection))

        except Exception:
            logger.exception(
                "Failed to analyze item: %s",
                item.get("title", item.get("item_id", "Unknown")),
            )

    logger.info(
        "%s items matched an APT group or ATT&CK technique",
        len(relevant),
    )

    # 5. Print high-confidence detections instead of sending Telegram alerts.
    to_display = [
        pair
        for pair in relevant
        if pair[1].confidence >= MIN_CONFIDENCE_TO_ALERT
    ]

    to_display = to_display[:ALERT_BATCH_MAX_PER_CYCLE]

    for item, detection in to_display:
        print_detection(item, detection)

    duration = round(time.time() - cycle_start, 1)

    logger.info(
        "Cycle complete in %ss | polled=%s new=%s relevant=%s "
        "displayed=%s",
        duration,
        len(items),
        len(new_items),
        len(relevant),
        len(to_display),
    )

    return {
        "polled": len(items),
        "new": len(new_items),
        "relevant": len(relevant),
        "displayed": len(to_display),
        "duration_s": duration,
    }


async def main_loop():
    """Run monitoring continuously while the environment is active."""

    init_db()

    logger.info("Global Threat Actor Monitor starting.")
    logger.info(
        "Polling interval: %s minutes | Confidence threshold: %s",
        POLL_INTERVAL_MINUTES,
        MIN_CONFIDENCE_TO_ALERT,
    )
    logger.info("Telegram notifications are disabled.")

    while True:
        try:
            await run_cycle()
        except Exception:
            logger.exception("Monitoring cycle failed.")

        logger.info(
            "Next cycle in %s minutes.",
            POLL_INTERVAL_MINUTES,
        )

        await asyncio.sleep(POLL_INTERVAL_MINUTES * 60)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Global Threat Actor Monitor - Codespaces edition"
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single monitoring cycle and exit.",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    init_db()

    if args.once:
        try:
            asyncio.run(run_cycle())
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user.")
        except Exception:
            logger.exception("Monitoring cycle failed.")
            sys.exit(1)
    else:
        try:
            asyncio.run(main_loop())
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user.")
