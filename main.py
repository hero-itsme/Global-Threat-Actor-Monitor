"""
Global Threat Actor Monitor
============================
Entry point. Runs an infinite loop that, every POLL_INTERVAL_MINUTES:
  1. Polls all 30 OSINT sources concurrently
  2. Skips items already seen (dedup via SQLite)
  3. Runs each new item through the APT / MITRE ATT&CK / Kill Chain matcher
  4. Persists matches and sends Telegram alerts for anything above the
     confidence threshold

Run:
    python main.py                 # continuous loop, polls every 10 min
    python main.py --once          # single cycle then exit (good for cron/testing)
    python main.py --backfill 50   # process up to 50 items per source once, ignoring the "new only" dedup skip for reporting stats
"""
import argparse
import asyncio
import logging
import os
import sys
import time

import aiohttp

from config.settings import (
    POLL_INTERVAL_MINUTES, LOG_FILE, LOG_DIR, MIN_CONFIDENCE_TO_ALERT,
    ALERT_BATCH_MAX_PER_CYCLE,
)
from core.osint_poller import poll_all_sources
from core.killchain_mapper import analyze
from core.storage import init_db, is_seen, mark_seen, save_detection, mark_alerted
from alerts.telegram_bot import send_telegram_alert, send_startup_message

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


async def run_cycle():
    """Executes exactly one poll -> detect -> alert cycle. Returns summary stats."""
    cycle_start = time.time()
    items = await poll_all_sources()

    new_items = []
    for item in items:
        if is_seen(item["item_id"]):
            continue
        mark_seen(item["item_id"], item["source"], item["title"], item["url"])
        new_items.append(item)

    logger.info(f"{len(new_items)} new items to analyze this cycle")

    relevant = []
    for item in new_items:
        detection = analyze(item["text"])
        if detection.is_relevant:
            save_detection(
                item["item_id"], item["source"], item["title"], item["url"], item["published"],
                detection.apt_groups, detection.techniques, detection.kill_chain_stages,
                detection.confidence,
            )
            relevant.append((item, detection))

    logger.info(f"{len(relevant)} items matched an APT group or ATT&CK technique")

    alerted = 0
    to_alert = [pair for pair in relevant if pair[1].confidence >= MIN_CONFIDENCE_TO_ALERT]
    to_alert = to_alert[:ALERT_BATCH_MAX_PER_CYCLE]

    if to_alert:
        async with aiohttp.ClientSession() as session:
            for item, detection in to_alert:
                ok = await send_telegram_alert(session, item, detection)
                if ok:
                    mark_alerted(item["item_id"])
                    alerted += 1
                await asyncio.sleep(1.5)  # gentle rate limit for Telegram API

    duration = round(time.time() - cycle_start, 1)
    logger.info(
        f"Cycle complete in {duration}s | polled={len(items)} new={len(new_items)} "
        f"relevant={len(relevant)} alerted={alerted}"
    )
    return {
        "polled": len(items), "new": len(new_items),
        "relevant": len(relevant), "alerted": alerted, "duration_s": duration,
    }


async def main_loop():
    init_db()
    logger.info("Global Threat Actor Monitor starting up.")
    logger.info(f"Polling {POLL_INTERVAL_MINUTES}-minute interval, {MIN_CONFIDENCE_TO_ALERT} confidence threshold.")
    await send_startup_message()

    while True:
        try:
            await run_cycle()
        except Exception as e:
            logger.exception(f"Unhandled error in monitoring cycle: {e}")
        await asyncio.sleep(POLL_INTERVAL_MINUTES * 60)


def parse_args():
    p = argparse.ArgumentParser(description="Global Threat Actor Monitor")
    p.add_argument("--once", action="store_true", help="Run a single cycle and exit")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    init_db()
    if args.once:
        asyncio.run(run_cycle())
    else:
        try:
            asyncio.run(main_loop())
        except KeyboardInterrupt:
            logger.info("Shutting down (KeyboardInterrupt).")
