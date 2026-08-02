"""
Core detection logic.

Given a piece of free text (title + summary from an OSINT article), this
module:
  1. Detects mentions of tracked APT groups (via alias matching)
  2. Detects mentions of MITRE ATT&CK techniques (via keyword matching)
  3. Maps each detected technique's tactic to a Cyber Kill Chain stage
  4. Produces a confidence score for the overall detection

This is intentionally a transparent, rule-based (keyword/regex) matcher —
not a black box — so analysts can see exactly why an alert fired and tune
config/apt_groups.py / config/mitre_attack.py directly.
"""
import re
from dataclasses import dataclass, field

from config.apt_groups import ALIAS_MAP, APT_GROUPS
from config.mitre_attack import TECHNIQUES, keyword_to_kill_chain


def _word_boundary_search(needle: str, haystack: str) -> bool:
    """Case-insensitive whole-phrase search with loose word boundaries."""
    pattern = r"(?<![a-z0-9])" + re.escape(needle.lower()) + r"(?![a-z0-9])"
    return re.search(pattern, haystack.lower()) is not None


@dataclass
class Detection:
    apt_groups: list = field(default_factory=list)          # canonical group names
    techniques: list = field(default_factory=list)          # [{id, name, tactic, kill_chain}]
    kill_chain_stages: list = field(default_factory=list)   # ordered unique stages
    confidence: float = 0.0

    @property
    def is_relevant(self) -> bool:
        return bool(self.apt_groups) or bool(self.techniques)


def detect_apt_groups(text: str) -> list:
    found = set()
    for alias, canonical in ALIAS_MAP.items():
        if _word_boundary_search(alias, text):
            found.add(canonical)
    return sorted(found)


def detect_techniques(text: str) -> list:
    matches = []
    for tech_id, meta in TECHNIQUES.items():
        for kw in meta["keywords"]:
            if kw.lower() in text.lower():
                matches.append({
                    "id": tech_id,
                    "name": meta["name"],
                    "tactic": meta["tactic"],
                    "kill_chain": keyword_to_kill_chain(meta["tactic"]),
                })
                break  # one match per technique is enough
    return matches


def compute_confidence(apt_groups: list, techniques: list, text: str) -> float:
    """
    Simple, explainable scoring:
      +0.45 for each distinct APT group mention (capped)
      +0.12 for each distinct technique matched (capped)
      +0.10 bonus if both an APT group AND a technique co-occur (higher-fidelity signal)
    Score is clamped to [0, 1].
    """
    score = 0.0
    score += min(len(apt_groups) * 0.45, 0.9)
    score += min(len(techniques) * 0.12, 0.48)
    if apt_groups and techniques:
        score += 0.10
    return round(min(score, 1.0), 2)


def analyze(text: str) -> Detection:
    apt_groups = detect_apt_groups(text)
    techniques = detect_techniques(text)
    kill_chain_stages = []
    for t in techniques:
        if t["kill_chain"] not in kill_chain_stages:
            kill_chain_stages.append(t["kill_chain"])
    confidence = compute_confidence(apt_groups, techniques, text)
    return Detection(
        apt_groups=apt_groups,
        techniques=techniques,
        kill_chain_stages=kill_chain_stages,
        confidence=confidence,
    )
