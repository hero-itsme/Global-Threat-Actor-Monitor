"""
APT Group Registry
-------------------
Publicly documented threat actor names, aliases, and MITRE ATT&CK Group IDs.
Sourced from MITRE ATT&CK Groups (https://attack.mitre.org/groups/) and
public vendor reporting (Mandiant, CrowdStrike, Microsoft, Kaspersky, etc.)

Each entry:
  mitre_id      : MITRE ATT&CK Group ID (e.g. G0007) if tracked, else None
  aliases       : list of names/aliases used across vendors — used for
                   keyword matching against OSINT article text
  suspected_origin : publicly attributed country/region (as reported by
                   open sources — attribution is inherently uncertain)
  target_sectors: commonly reported targeted sectors
"""

APT_GROUPS = {
    "APT28": {
        "mitre_id": "G0007",
        "aliases": ["APT28", "Fancy Bear", "Sofacy", "Sednit", "STRONTIUM", "Forest Blizzard", "Pawn Storm"],
        "suspected_origin": "Russia",
        "target_sectors": ["Government", "Military", "Media"],
    },
    "APT29": {
        "mitre_id": "G0016",
        "aliases": ["APT29", "Cozy Bear", "The Dukes", "Midnight Blizzard", "NOBELIUM", "Yttrium"],
        "suspected_origin": "Russia",
        "target_sectors": ["Government", "Think Tanks", "Healthcare"],
    },
    "Sandworm": {
        "mitre_id": "G0034",
        "aliases": ["Sandworm", "Sandworm Team", "Voodoo Bear", "Seashell Blizzard", "Iron Viking"],
        "suspected_origin": "Russia",
        "target_sectors": ["Energy", "Government", "Critical Infrastructure"],
    },
    "Turla": {
        "mitre_id": "G0010",
        "aliases": ["Turla", "Snake", "Uroburos", "Venomous Bear", "Waterbug"],
        "suspected_origin": "Russia",
        "target_sectors": ["Government", "Diplomatic", "Defense"],
    },
    "Gamaredon": {
        "mitre_id": "G0047",
        "aliases": ["Gamaredon", "Primitive Bear", "Armageddon", "Shuckworm"],
        "suspected_origin": "Russia",
        "target_sectors": ["Government", "Ukraine-focused"],
    },
    "APT41": {
        "mitre_id": "G0096",
        "aliases": ["APT41", "Double Dragon", "Winnti", "Wicked Panda", "BARIUM"],
        "suspected_origin": "China",
        "target_sectors": ["Gaming", "Healthcare", "Telecom", "Supply Chain"],
    },
    "APT1": {
        "mitre_id": "G0006",
        "aliases": ["APT1", "Comment Crew", "Comment Panda", "PLA Unit 61398"],
        "suspected_origin": "China",
        "target_sectors": ["Manufacturing", "Defense"],
    },
    "APT10": {
        "mitre_id": "G0045",
        "aliases": ["APT10", "Stone Panda", "MenuPass", "Red Apollo", "Cicada"],
        "suspected_origin": "China",
        "target_sectors": ["MSPs", "Cloud Providers", "Government"],
    },
    "APT40": {
        "mitre_id": "G0065",
        "aliases": ["APT40", "Leviathan", "TEMP.Periscope", "Kryptonite Panda", "Gingham Typhoon"],
        "suspected_origin": "China",
        "target_sectors": ["Maritime", "Defense", "Research"],
    },
    "Volt Typhoon": {
        "mitre_id": "G1017",
        "aliases": ["Volt Typhoon", "Vanguard Panda", "BRONZE SILHOUETTE"],
        "suspected_origin": "China",
        "target_sectors": ["Critical Infrastructure", "Communications", "Utilities"],
    },
    "Mustang Panda": {
        "mitre_id": "G0129",
        "aliases": ["Mustang Panda", "TA416", "Bronze President", "Red Lich"],
        "suspected_origin": "China",
        "target_sectors": ["NGOs", "Government", "Southeast Asia"],
    },
    "Lazarus Group": {
        "mitre_id": "G0032",
        "aliases": ["Lazarus Group", "Hidden Cobra", "Guardians of Peace", "APT38", "Zinc", "Diamond Sleet"],
        "suspected_origin": "North Korea",
        "target_sectors": ["Financial", "Cryptocurrency", "Defense"],
    },
    "Kimsuky": {
        "mitre_id": "G0094",
        "aliases": ["Kimsuky", "Velvet Chollima", "Black Banshee", "Emerald Sleet", "Thallium"],
        "suspected_origin": "North Korea",
        "target_sectors": ["Think Tanks", "Government", "Nuclear Policy"],
    },
    "Andariel": {
        "mitre_id": "G0138",
        "aliases": ["Andariel", "Silent Chollima", "Onyx Sleet", "Stonefly"],
        "suspected_origin": "North Korea",
        "target_sectors": ["Defense", "Healthcare", "Financial"],
    },
    "APT33": {
        "mitre_id": "G0064",
        "aliases": ["APT33", "Elfin", "Refined Kitten", "Peach Sandstorm"],
        "suspected_origin": "Iran",
        "target_sectors": ["Aviation", "Energy", "Petrochemical"],
    },
    "APT34": {
        "mitre_id": "G0049",
        "aliases": ["APT34", "OilRig", "Helix Kitten", "Crambus", "Cobalt Gypsy"],
        "suspected_origin": "Iran",
        "target_sectors": ["Government", "Financial", "Energy"],
    },
    "APT35": {
        "mitre_id": "G0059",
        "aliases": ["APT35", "Charming Kitten", "Phosphorus", "Mint Sandstorm", "TA453"],
        "suspected_origin": "Iran",
        "target_sectors": ["Academia", "Government", "Media"],
    },
    "MuddyWater": {
        "mitre_id": "G0069",
        "aliases": ["MuddyWater", "Mango Sandstorm", "Static Kitten", "Seedworm"],
        "suspected_origin": "Iran",
        "target_sectors": ["Telecom", "Government", "Oil and Gas"],
    },
    "Agrius": {
        "mitre_id": "G1030",
        "aliases": ["Agrius", "Pink Sandstorm", "BlackShadow"],
        "suspected_origin": "Iran",
        "target_sectors": ["Israel-focused", "Diamond Industry"],
    },
    "Equation Group": {
        "mitre_id": "G0020",
        "aliases": ["Equation Group", "Equation"],
        "suspected_origin": "USA (alleged)",
        "target_sectors": ["Telecom", "Government"],
    },
    "APT-C-36": {
        "mitre_id": None,
        "aliases": ["APT-C-36", "Blind Eagle"],
        "suspected_origin": "South America",
        "target_sectors": ["Colombia", "Government", "Financial"],
    },
    "Machete": {
        "mitre_id": "G0095",
        "aliases": ["Machete", "APT-C-43"],
        "suspected_origin": "South America",
        "target_sectors": ["Military", "Government - LATAM"],
    },
    "DarkHotel": {
        "mitre_id": "G0012",
        "aliases": ["DarkHotel", "APT-C-06", "Tapaoux"],
        "suspected_origin": "South Korea (alleged)",
        "target_sectors": ["Hospitality", "Executives"],
    },
    "Winnti Group": {
        "mitre_id": "G0044",
        "aliases": ["Winnti Group", "Blackfly", "Bronze Atlas"],
        "suspected_origin": "China",
        "target_sectors": ["Gaming", "Pharmaceuticals"],
    },
    "FIN7": {
        "mitre_id": "G0046",
        "aliases": ["FIN7", "Carbon Spider", "Sangria Tempest"],
        "suspected_origin": "Unknown/Russia-linked",
        "target_sectors": ["Retail", "Hospitality", "Financial"],
    },
    "FIN12": {
        "mitre_id": "G1004",
        "aliases": ["FIN12"],
        "suspected_origin": "Unknown",
        "target_sectors": ["Healthcare"],
    },
    "Wizard Spider": {
        "mitre_id": "G0102",
        "aliases": ["Wizard Spider", "TrickBot Gang", "UNC1878", "Periwinkle Tempest"],
        "suspected_origin": "Russia",
        "target_sectors": ["Healthcare", "Financial", "Ransomware"],
    },
    "Scattered Spider": {
        "mitre_id": "G1015",
        "aliases": ["Scattered Spider", "UNC3944", "Octo Tempest", "Muddled Libra"],
        "suspected_origin": "Unknown (English-speaking)",
        "target_sectors": ["Telecom", "BPO", "Gaming", "Retail"],
    },
    "APT39": {
        "mitre_id": "G0087",
        "aliases": ["APT39", "Chafer", "Remix Kitten"],
        "suspected_origin": "Iran",
        "target_sectors": ["Telecom", "Travel"],
    },
    "APT42": {
        "mitre_id": "G1044",
        "aliases": ["APT42", "Charming Kitten subgroup", "Damselfly"],
        "suspected_origin": "Iran",
        "target_sectors": ["NGOs", "Journalists", "Activists"],
    },
    "Transparent Tribe": {
        "mitre_id": "G0134",
        "aliases": ["Transparent Tribe", "APT36", "Mythic Leopard"],
        "suspected_origin": "Pakistan",
        "target_sectors": ["Government", "Military - India focus"],
    },
    "SideWinder": {
        "mitre_id": "G0121",
        "aliases": ["SideWinder", "Rattlesnake", "T-APT-04"],
        "suspected_origin": "India (alleged)",
        "target_sectors": ["Government", "Military - South Asia"],
    },
    "Patchwork": {
        "mitre_id": "G0040",
        "aliases": ["Patchwork", "Dropping Elephant", "APT-C-09"],
        "suspected_origin": "India (alleged)",
        "target_sectors": ["Government", "Think Tanks - South Asia"],
    },
    "Bitter": {
        "mitre_id": "G1002",
        "aliases": ["Bitter", "APT-C-08", "T-APT-17"],
        "suspected_origin": "South Asia",
        "target_sectors": ["Government", "Energy - South Asia"],
    },
    "Molerats": {
        "mitre_id": "G0021",
        "aliases": ["Molerats", "Gaza Cybergang", "TA402"],
        "suspected_origin": "Middle East",
        "target_sectors": ["Government - Middle East"],
    },
    "OceanLotus": {
        "mitre_id": "G0050",
        "aliases": ["OceanLotus", "APT32", "SeaLotus", "Canvas Cyclone"],
        "suspected_origin": "Vietnam",
        "target_sectors": ["Manufacturing", "Media", "ASEAN Government"],
    },
    "Lotus Blossom": {
        "mitre_id": "G0030",
        "aliases": ["Lotus Blossom", "Spring Dragon", "Billbug"],
        "suspected_origin": "China",
        "target_sectors": ["Government - Southeast Asia"],
    },
    "Earth Lusca": {
        "mitre_id": None,
        "aliases": ["Earth Lusca", "TAG-22"],
        "suspected_origin": "China",
        "target_sectors": ["Government", "Gambling", "Media"],
    },
    "BlackTech": {
        "mitre_id": "G0098",
        "aliases": ["BlackTech", "Palmerworm", "Circuit Panda"],
        "suspected_origin": "China",
        "target_sectors": ["Telecom", "Government - East Asia"],
    },
    "RedCurl": {
        "mitre_id": None,
        "aliases": ["RedCurl", "Earth Kapre"],
        "suspected_origin": "Unknown",
        "target_sectors": ["Corporate Espionage"],
    },
}


def get_all_aliases_map():
    """Returns a flat dict: alias(lowercase) -> canonical group name, for fast text matching."""
    alias_map = {}
    for canonical, meta in APT_GROUPS.items():
        for alias in meta["aliases"]:
            alias_map[alias.lower()] = canonical
    return alias_map


ALIAS_MAP = get_all_aliases_map()

if __name__ == "__main__":
    print(f"Loaded {len(APT_GROUPS)} APT groups, {len(ALIAS_MAP)} total aliases.")
