"""
wordlists.py - Corporate/professional password pattern generator for targeted attacks
"""

from datetime import datetime
from typing import Optional


COMMON_CORPORATE_SUFFIXES = [
    "2023", "2024", "2025", "2026",
    "123", "1234", "12345", "123456",
    "!", "!!", "@", "#", "123!",
    "01", "2023!", "2024!", "2025!",
    "@2023", "@2024", "@2025",
]

COMMON_LEET_MAP = {
    "a": "4", "e": "3", "i": "1",
    "o": "0", "s": "5", "t": "7",
}

COMMON_CORPORATE_BASES = [
    "Password", "password",
    "Welcome", "welcome",
    "Admin", "admin",
    "Wifi", "wifi", "WiFi",
    "Network", "network",
    "Internet", "internet",
    "Guest", "guest",
    "Office", "office",
    "Company", "company",
    "Secure", "secure",
    "Access", "access",
    "Connect", "connect",
    "Corporate", "corporate",
    "Intranet", "intranet",
    "Vpn", "vpn", "VPN",
]


# Alias used internally (must be defined before _leet)
LEET_MAP = COMMON_LEET_MAP


def _leet(word: str) -> str:
    result = ""
    for ch in word:
        result += LEET_MAP.get(ch.lower(), ch)
    return result


def _variants(word: str) -> list[str]:
    """Generate common variants of a word."""
    variants = [
        word,
        word.lower(),
        word.upper(),
        word.capitalize(),
        word.capitalize() + "!",
        word.lower() + "!",
        _leet(word),
    ]
    for suffix in COMMON_CORPORATE_SUFFIXES:
        variants.append(word + suffix)
        variants.append(word.lower() + suffix)
        variants.append(word.capitalize() + suffix)
    return list(dict.fromkeys(variants))  # deduplicate


def generate_corporate_wordlist(
    company_name: str = "",
    extra_words: Optional[list] = None,
    min_length: int = 8,
    max_length: int = 63,
) -> list[str]:
    """
    Generate a targeted wordlist for corporate WiFi audits.

    Combines:
      - Company name variants
      - Generic corporate password patterns
      - Seasonal/year-based patterns
      - Extra words provided by the auditor
    """
    words: list[str] = []
    extra_words = extra_words or []

    # Company name variants
    if company_name:
        for part in company_name.split():
            words.extend(_variants(part))
        words.extend(_variants(company_name.replace(" ", "")))
        words.extend(_variants(company_name.replace(" ", "-")))
        words.extend(_variants(company_name.replace(" ", "_")))

    # Generic corporate bases
    for base in COMMON_CORPORATE_BASES:
        words.extend(_variants(base))

    # Extra words from auditor
    for word in extra_words:
        words.extend(_variants(word))

    # Seasonal patterns (quarters + year)
    year = datetime.now().year
    for y in range(year - 1, year + 2):
        for season in ["Spring", "Summer", "Autumn", "Winter",
                       "January", "February", "March", "April", "May",
                       "June", "July", "August", "September", "October",
                       "November", "December", "Q1", "Q2", "Q3", "Q4"]:
            words.extend(_variants(f"{season}{y}"))

    # Common simple passwords that organizations still use
    simple = [
        "changeme", "letmein", "football", "baseball", "dragon",
        "master", "monkey", "shadow", "sunshine", "princess",
        "iloveyou", "trustno1", "superman", "batman",
        "qwerty123", "abc123", "pass1234",
        "wifi1234", "wireless", "netgear", "router",
    ]
    for word in simple:
        words.extend(_variants(word))

    # Filter by length
    words = [w for w in words if min_length <= len(w) <= max_length]

    # Deduplicate preserving order
    seen: set[str] = set()
    result = []
    for w in words:
        if w not in seen:
            seen.add(w)
            result.append(w)

    return result
