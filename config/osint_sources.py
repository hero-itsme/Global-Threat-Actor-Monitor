"""
OSINT Source Registry — 30 public RSS/Atom feeds covering threat intel
blogs, vendor research teams, CERTs, and vulnerability advisories.

Each source is polled independently; failures on one source never block
the others (see core/osint_poller.py). Feel free to swap in your own
paid feeds (Recorded Future, Mandiant Advantage, Flashpoint, etc.) by
adding them here with the same shape.
"""

OSINT_SOURCES = [
    # --- Major independent security news outlets ---
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "category": "news"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "category": "news"},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "category": "news"},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "category": "news"},
    {"name": "SecurityWeek", "url": "https://www.securityweek.com/feed/", "category": "news"},
    {"name": "The Record (Recorded Future News)", "url": "https://therecord.media/feed", "category": "news"},
    {"name": "Infosecurity Magazine", "url": "https://www.infosecurity-magazine.com/rss/news/", "category": "news"},
    {"name": "SC Media", "url": "https://www.scmagazine.com/feed", "category": "news"},
    {"name": "CyberScoop", "url": "https://cyberscoop.com/feed/", "category": "news"},
    {"name": "Graham Cluley", "url": "https://grahamcluley.com/feed/", "category": "news"},

    # --- Vendor threat intel / research blogs ---
    {"name": "Microsoft Security Blog", "url": "https://www.microsoft.com/en-us/security/blog/feed/", "category": "vendor"},
    {"name": "Google Threat Intelligence (Mandiant)", "url": "https://cloud.google.com/blog/topics/threat-intelligence/rss/", "category": "vendor"},
    {"name": "Cisco Talos", "url": "https://blog.talosintelligence.com/rss/", "category": "vendor"},
    {"name": "Palo Alto Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "category": "vendor"},
    {"name": "CrowdStrike Blog", "url": "https://www.crowdstrike.com/blog/feed/", "category": "vendor"},
    {"name": "Kaspersky Securelist", "url": "https://securelist.com/feed/", "category": "vendor"},
    {"name": "ESET WeLiveSecurity", "url": "https://www.welivesecurity.com/en/rss/feed/", "category": "vendor"},
    {"name": "Symantec/Broadcom Threat Hub", "url": "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/rss.xml", "category": "vendor"},
    {"name": "Trend Micro Research", "url": "https://www.trendmicro.com/en_us/research.rss", "category": "vendor"},
    {"name": "Check Point Research", "url": "https://research.checkpoint.com/feed/", "category": "vendor"},
    {"name": "Mandiant Blog", "url": "https://www.mandiant.com/resources/blog/rss.xml", "category": "vendor"},
    {"name": "Recorded Future Blog", "url": "https://www.recordedfuture.com/feed", "category": "vendor"},
    {"name": "SentinelOne Labs", "url": "https://www.sentinelone.com/labs/feed/", "category": "vendor"},
    {"name": "Sophos News", "url": "https://news.sophos.com/en-us/feed/", "category": "vendor"},
    {"name": "Proofpoint Threat Insight", "url": "https://www.proofpoint.com/us/rss.xml", "category": "vendor"},
    {"name": "Volexity Blog", "url": "https://www.volexity.com/blog/feed/", "category": "vendor"},

    # --- Government / CERT advisories ---
    {"name": "CISA Advisories", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "category": "gov"},
    {"name": "CISA News", "url": "https://www.cisa.gov/news.xml", "category": "gov"},
    {"name": "UK NCSC News", "url": "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml", "category": "gov"},
    {"name": "CERT-EU", "url": "https://cert.europa.eu/publications/threat-intelligence-rss", "category": "gov"},
]

assert len(OSINT_SOURCES) >= 30, "Source registry fell below the required 30 feeds"
