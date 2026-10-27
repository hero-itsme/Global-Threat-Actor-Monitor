"""
Async RSS/Atom poller for all configured OSINT sources.

Uses aiohttp + feedparser. Each source is fetched independently and
failures (timeouts, malformed feeds, HTTP errors) are logged and
skipped — one bad feed never stalls the cycle.
"""
import asyncio
import hashlib
import logging
import time

import aiohttp
import feedparser

from config.settings import REQUEST_TIMEOUT_SECONDS, MAX_CONCURRENT_FETCHES
from config.osint_sources import OSINT_SOURCES

logger = logging.getLogger("threat_monitor.poller")

HEADERS = {
    "User-Agent": "GlobalThreatActorMonitor/1.0 (+OSINT research bot; contact: set-your-contact@example.com)"
}


def make_item_id(source_name: str, entry) -> str:
    raw = entry.get("id") or entry.get("link") or entry.get("title", "")
    return hashlib.sha256(f"{source_name}:{raw}".encode("utf-8")).hexdigest()


async def _fetch_one(session: aiohttp.ClientSession, source: dict, sem: asyncio.Semaphore) -> list:
    items = []
    async with sem:
        try:
            timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
            async with session.get(source["url"], headers=HEADERS, timeout=timeout) as resp:
                if resp.status != 200:
                    logger.warning(f"[{source['name']}] HTTP {resp.status}")
                    return items
                raw = await resp.read()
        except Exception as e:
            logger.warning(f"[{source['name']}] fetch failed: {e}")
            return items

    try:
        parsed = feedparser.parse(raw)
    except Exception as e:
        logger.warning(f"[{source['name']}] parse failed: {e}")
        return items

    for entry in parsed.entries:
        title = entry.get("title", "").strip()
        summary = entry.get("summary", "") or entry.get("description", "")
        link = entry.get("link", "")
        published = entry.get("published", "") or entry.get("updated", "")
        item_id = make_item_id(source["name"], entry)
        items.append({
            "item_id": item_id,
            "source": source["name"],
            "category": source.get("category", "news"),
            "title": title,
            "summary": summary,
            "url": link,
            "published": published,
            "text": f"{title}\n{summary}",
            "fetched_ts": time.time(),
        })
    return items


async def poll_all_sources() -> list:
    """Fetch every configured OSINT source concurrently. Returns a flat list of items."""
    sem = asyncio.Semaphore(MAX_CONCURRENT_FETCHES)
    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_FETCHES)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [_fetch_one(session, src, sem) for src in OSINT_SOURCES]
        results = await asyncio.gather(*tasks, return_exceptions=False)

    all_items = []
    for r in results:
        all_items.extend(r)
    logger.info(f"Polled {len(OSINT_SOURCES)} sources, retrieved {len(all_items)} items total")
    return all_items
