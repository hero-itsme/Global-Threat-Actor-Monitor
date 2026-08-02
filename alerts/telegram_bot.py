"""
Telegram alert dispatcher.

Uses Telegram's Bot HTTP API directly (no heavy SDK dependency needed
for simple sendMessage calls). Formats a rich, readable alert per
detection including APT attribution, MITRE techniques, and kill chain
stage.
"""
import logging
import html
import aiohttp

from config.settings import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

logger = logging.getLogger("threat_monitor.telegram")

API_BASE = "https://api.telegram.org/bot{token}/sendMessage"

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}


def _severity_for_confidence(confidence: float) -> str:
    if confidence >= 0.8:
        return "critical"
    if confidence >= 0.6:
        return "high"
    if confidence >= 0.4:
        return "medium"
    return "low"


def format_alert(item: dict, detection) -> str:
    sev = _severity_for_confidence(detection.confidence)
    emoji = SEVERITY_EMOJI[sev]

    apt_line = ", ".join(detection.apt_groups) if detection.apt_groups else "Unattributed"
    techniques_lines = "\n".join(
        f"  • {t['id']} — {t['name']} ({t['tactic']})" for t in detection.techniques
    ) or "  • None matched"
    kill_chain_line = " → ".join(detection.kill_chain_stages) if detection.kill_chain_stages else "N/A"

    title = html.escape(item["title"])
    source = html.escape(item["source"])
    url = item["url"]

    text = (
        f"{emoji} <b>{sev.upper()} — Threat Actor Activity Detected</b>\n\n"
        f"<b>Title:</b> {title}\n"
        f"<b>Source:</b> {source}\n"
        f"<b>Published:</b> {html.escape(item.get('published', 'unknown'))}\n"
        f"<b>Confidence:</b> {detection.confidence:.2f}\n\n"
        f"<b>Attributed Actor(s):</b> {html.escape(apt_line)}\n\n"
        f"<b>MITRE ATT&amp;CK Techniques:</b>\n{html.escape(techniques_lines)}\n\n"
        f"<b>Cyber Kill Chain:</b> {html.escape(kill_chain_line)}\n\n"
        f"<a href=\"{url}\">Read full article →</a>"
    )
    return text


async def send_telegram_alert(session: aiohttp.ClientSession, item: dict, detection) -> bool:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.error("TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not configured — skipping send")
        return False

    text = format_alert(item, detection)
    url = API_BASE.format(token=TELEGRAM_BOT_TOKEN)
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": False,
    }
    try:
        async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status != 200:
                body = await resp.text()
                logger.error(f"Telegram send failed ({resp.status}): {body}")
                return False
            return True
    except Exception as e:
        logger.error(f"Telegram send exception: {e}")
        return False


async def send_startup_message():
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    async with aiohttp.ClientSession() as session:
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": "🛰️ <b>Global Threat Actor Monitor</b> started.\nMonitoring 35+ APT groups across 30 OSINT sources every 10 minutes.",
            "parse_mode": "HTML",
        }
        url = API_BASE.format(token=TELEGRAM_BOT_TOKEN)
        try:
            await session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=15))
        except Exception as e:
            logger.warning(f"Startup message failed: {e}")
