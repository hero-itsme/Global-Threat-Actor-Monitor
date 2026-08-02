# Global Threat Actor Monitor

Automated Python system that monitors **40 APT groups** worldwide, maps
detected activity to **MITRE ATT&CK techniques** and the **Cyber Kill
Chain**, and sends **real-time Telegram alerts** sourced from **30 public
OSINT feeds**, polled every **10 minutes**.

## Architecture

```
threat_monitor/
├── main.py                 # Entry point + scheduler loop
├── report.py                # CLI to inspect stored detections
├── config/
│   ├── settings.py          # Env-driven configuration
│   ├── apt_groups.py        # 40 APT groups + 148 aliases + MITRE Group IDs
│   ├── mitre_attack.py      # 29 curated ATT&CK techniques -> Kill Chain map
│   └── osint_sources.py     # 30 OSINT RSS/Atom feeds
├── core/
│   ├── osint_poller.py      # Async concurrent feed fetcher (aiohttp)
│   ├── killchain_mapper.py  # Detection engine (alias + keyword matching, scoring)
│   └── storage.py           # SQLite dedup store + detections history
├── alerts/
│   └── telegram_bot.py      # Telegram Bot API alert formatting/sending
├── data/                    # SQLite DB lives here (auto-created)
├── logs/                    # Rotating text logs (auto-created)
├── requirements.txt
└── .env.example
```

### How a cycle works
1. **Poll** — all 30 OSINT sources are fetched concurrently (bounded by
   `MAX_CONCURRENT_FETCHES`); a slow or broken feed never blocks the others.
2. **Dedup** — each article gets a stable hash ID; already-seen items are
   skipped via SQLite (`data/seen_items.sqlite3`).
3. **Detect** — new article text (title + summary) is scanned for:
   - APT group names/aliases (148 aliases across 40 groups)
   - MITRE ATT&CK technique keywords (29 techniques across all 14 tactics)
4. **Map** — each matched technique's tactic is mapped to a Cyber Kill
   Chain stage (Recon → Weaponization → Delivery → Exploitation →
   Installation → C2 → Actions on Objectives).
5. **Score** — a transparent, explainable confidence score (0–1) is
   computed from how many groups/techniques matched and whether they
   co-occur.
6. **Alert** — anything at/above `MIN_CONFIDENCE_TO_ALERT` (default 0.35)
   is sent to Telegram as a formatted HTML message and persisted to SQLite.

## Setup

```bash
cd threat_monitor
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env`:

```
TELEGRAM_BOT_TOKEN=<from @BotFather>
TELEGRAM_CHAT_ID=<your channel/group/DM chat id>
```

**Getting a Telegram bot token & chat ID:**
1. Message `@BotFather` on Telegram → `/newbot` → copy the token.
2. Add the bot to your target channel/group (or just DM it).
3. Send any message to it, then open:
   `https://api.telegram.org/bot<TOKEN>/getUpdates`
   and read the `"chat":{"id": ...}` value.

## Running

```bash
# Continuous mode — polls every 10 minutes forever
python main.py

# Single cycle (good for testing or running via cron/systemd timer instead of a loop)
python main.py --once

# View what's been detected so far, without Telegram
python report.py --limit 30
```
<img width="997" height="243" alt="Threat Monitor" src="https://github.com/user-attachments/assets/3a0fd669-050b-46fe-a99d-2a6f093c6b5d" />

<img width="504" height="497" alt="Threat Alert" src="https://github.com/user-attachments/assets/1486fa40-40a9-4b5c-8f19-aeb6b6c1dd55" />

## Running as a background service (systemd)

Create `/etc/systemd/system/threat-monitor.service`:

```ini
[Unit]
Description=Global Threat Actor Monitor
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/threat_monitor
EnvironmentFile=/opt/threat_monitor/.env
ExecStart=/usr/bin/python3 /opt/threat_monitor/main.py
Restart=always
RestartSec=15

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now threat-monitor
sudo journalctl -u threat-monitor -f
```

## Tuning

| Setting | File | Effect |
|---|---|---|
| `POLL_INTERVAL_MINUTES` | `.env` | How often the full cycle runs (default 10) |
| `MIN_CONFIDENCE_TO_ALERT` | `.env` | Raise to reduce noise, lower to catch more |
| `ALERT_BATCH_MAX_PER_CYCLE` | `.env` | Caps Telegram messages sent per cycle |
| `APT_GROUPS` | `config/apt_groups.py` | Add/remove tracked actors & aliases |
| `TECHNIQUES` | `config/mitre_attack.py` | Add more ATT&CK techniques/keywords |
| `OSINT_SOURCES` | `config/osint_sources.py` | Add/remove/replace feeds (paid feeds welcome) |

## Design notes & limitations

- **Rule-based, not ML.** Detection is keyword/alias matching against
  article text — fast, free, fully explainable, and easy to tune, but it
  will miss activity described without those exact terms and can produce
  false positives on generic phrasing. For higher precision, plug in an
  LLM-based re-scoring step before alerting (the `Detection` object gives
  you a clean structured hook to do that).
- **Public feeds only by default.** All 30 sources are free/public RSS
  feeds. Swap in paid threat-intel feeds (Recorded Future, Mandiant
  Advantage, Flashpoint, GreyNoise, etc.) by adding entries with the same
  `{name, url, category}` shape — most offer RSS/API endpoints.
- **Attribution is inherently uncertain.** `suspected_origin` fields
  reflect public reporting, not certainty — treat as a lead, not proof.
- **Respect feed terms of service** and rate limits; the built-in
  concurrency cap and 10-minute interval are deliberately conservative.
