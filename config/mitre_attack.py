"""
MITRE ATT&CK Technique <-> Cyber Kill Chain mapping.

Rather than embedding the full ATT&CK STIX bundle (14 tactics, 600+
techniques), this module ships a curated, high-signal set of techniques
that are most frequently referenced in threat intel reporting, each with:
  - tactic        : the ATT&CK tactic it belongs to
  - keywords       : phrases used to detect the technique in free text
  - kill_chain     : the corresponding Lockheed Martin Cyber Kill Chain stage

Extend TECHNIQUES with more entries as needed — the matching engine in
core/killchain_mapper.py works off this table automatically.
"""

# Lockheed Martin Cyber Kill Chain, in order
KILL_CHAIN_STAGES = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command & Control",
    "Actions on Objectives",
]

# ATT&CK Tactic -> Kill Chain stage (approximate mapping used across the industry)
TACTIC_TO_KILLCHAIN = {
    "Reconnaissance": "Reconnaissance",
    "Resource Development": "Weaponization",
    "Initial Access": "Delivery",
    "Execution": "Exploitation",
    "Persistence": "Installation",
    "Privilege Escalation": "Installation",
    "Defense Evasion": "Installation",
    "Credential Access": "Actions on Objectives",
    "Discovery": "Actions on Objectives",
    "Lateral Movement": "Actions on Objectives",
    "Collection": "Actions on Objectives",
    "Command and Control": "Command & Control",
    "Exfiltration": "Actions on Objectives",
    "Impact": "Actions on Objectives",
}

TECHNIQUES = {
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "keywords": ["phishing", "spearphishing", "spear-phishing", "malicious email", "phishing email", "lure document"],
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "keywords": ["exploited vulnerability", "zero-day", "0-day", "unpatched", "public-facing application", "web shell", "webshell", "rce exploit"],
    },
    "T1195": {
        "name": "Supply Chain Compromise",
        "tactic": "Initial Access",
        "keywords": ["supply chain attack", "supply-chain compromise", "compromised update", "trojanized installer", "software supply chain"],
    },
    "T1133": {
        "name": "External Remote Services",
        "tactic": "Initial Access",
        "keywords": ["vpn compromise", "rdp exposed", "remote desktop protocol", "external remote service"],
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "keywords": ["powershell script", "malicious macro", "vbscript", "living off the land", "lolbin", "command line execution"],
    },
    "T1203": {
        "name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "keywords": ["client-side exploit", "malicious document", "exploit document", "macro-enabled"],
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "keywords": ["scheduled task", "cron job persistence", "scheduled job"],
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "keywords": ["registry run key", "startup folder", "autostart", "bootkit"],
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion",
        "keywords": ["process injection", "dll injection", "process hollowing", "reflective loading"],
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "keywords": ["obfuscated payload", "packed malware", "encrypted payload", "steganography"],
    },
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "keywords": ["log deletion", "anti-forensic", "cleared event logs", "wiped logs"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "keywords": ["valid accounts", "compromised credentials used", "legitimate account abuse"],
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "keywords": ["credential dumping", "mimikatz", "lsass dump", "password hash extraction"],
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "keywords": ["brute force attack", "password spraying", "credential stuffing"],
    },
    "T1087": {
        "name": "Account Discovery",
        "tactic": "Discovery",
        "keywords": ["account enumeration", "domain enumeration"],
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "keywords": ["system reconnaissance", "host fingerprinting"],
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "keywords": ["lateral movement", "remote services abuse", "psexec", "wmi lateral movement"],
    },
    "T1560": {
        "name": "Archive Collected Data",
        "tactic": "Collection",
        "keywords": ["data staged", "archived stolen data", "compressed data for exfiltration"],
    },
    "T1071": {
        "name": "Application Layer Protocol (C2)",
        "tactic": "Command and Control",
        "keywords": ["c2 communication", "command and control server", "https c2", "dns tunneling", "beaconing"],
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "keywords": ["downloaded second-stage payload", "dropped additional malware", "tool transfer"],
    },
    "T1572": {
        "name": "Protocol Tunneling",
        "tactic": "Command and Control",
        "keywords": ["protocol tunneling", "tunneled traffic", "proxy c2"],
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "keywords": ["data exfiltration", "exfiltrated data", "stolen data uploaded", "data theft"],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "keywords": ["ransomware", "encrypted files", "ransom note", "double extortion", "file encryption attack"],
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "keywords": ["deleted shadow copies", "disabled backups", "inhibited recovery"],
    },
    "T1498": {
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "keywords": ["ddos attack", "denial of service", "network flooding"],
    },
    "T1584": {
        "name": "Compromise Infrastructure",
        "tactic": "Resource Development",
        "keywords": ["compromised infrastructure", "hijacked domain", "bulletproof hosting"],
    },
    "T1583": {
        "name": "Acquire Infrastructure",
        "tactic": "Resource Development",
        "keywords": ["registered domain for c2", "acquired vps", "purchased infrastructure"],
    },
    "T1592": {
        "name": "Gather Victim Host Information",
        "tactic": "Reconnaissance",
        "keywords": ["reconnaissance scan", "victim profiling", "open source recon", "osint gathering on target"],
    },
    "T1598": {
        "name": "Phishing for Information",
        "tactic": "Reconnaissance",
        "keywords": ["phishing for information", "social engineering recon", "pretexting"],
    },
}


def keyword_to_kill_chain(tactic: str) -> str:
    return TACTIC_TO_KILLCHAIN.get(tactic, "Actions on Objectives")
