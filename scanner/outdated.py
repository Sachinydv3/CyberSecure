"""Outdated-software fingerprint table.

This is intentionally a small, hand-picked subset rather than a full CVE
feed. It demonstrates the *pattern* of version fingerprinting — match a
``Server`` / ``X-Powered-By`` / ``Generator`` style string against a known
list and flag anything older than the cutoff. It is **not** a substitute
for a real vulnerability database.

Each entry is keyed by a stable identifier (the product name normalised
to lowercase). The matcher tolerates extra text around the version
(e.g. ``"Apache/2.2.15 (CentOS)"`` still matches ``"apache"`` → 2.2.15).
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple


# product_id -> (regex, latest_known_good_version, human_label)
# The regex must capture the version string in group 1.
_OUTDATED: Dict[str, Tuple[str, Tuple[int, ...], str]] = {
    "apache": (
        r"apache[/\s](\d+\.\d+\.\d+)",
        (2, 4, 60),
        "Apache HTTP Server",
    ),
    "nginx": (
        r"nginx[/\s](\d+\.\d+\.\d+)",
        (1, 25, 0),
        "nginx",
    ),
    "iis": (
        r"microsoft-iis[/\s](\d+\.\d+)",
        (10, 0),
        "Microsoft IIS",
    ),
    "php": (
        r"php[/\s](\d+\.\d+\.\d+)",
        (8, 3, 0),
        "PHP",
    ),
    "openssl": (
        r"openssl[/\s](\d+\.\d+\.\d+[a-z]?)",
        (3, 2, 0),
        "OpenSSL",
    ),
    "tomcat": (
        r"tomcat[/\s](\d+\.\d+\.\d+)",
        (9, 0, 85),
        "Apache Tomcat",
    ),
}


def _parse_version(raw: str) -> Optional[Tuple[int, ...]]:
    """Turn '2.2.15' or '1.0.1u' into a (2, 2, 15) / (1, 0, 1) tuple.

    Trailing non-numeric suffixes (release letters) are stripped.
    """
    cleaned = re.sub(r"[^0-9.]", "", raw)
    parts = cleaned.split(".")
    out: List[int] = []
    for p in parts:
        if not p:
            continue
        try:
            out.append(int(p))
        except ValueError:
            break
        # Don't bother with more than 4 version parts.
        if len(out) >= 4:
            break
    return tuple(out) if out else None


def match_version(header_value: str):
    """Inspect a single header value for any known product below its cutoff.

    Returns a list of dicts — one per match. Empty list if nothing matched
    or everything is current.
    """
    matches: List[Dict] = []
    if not header_value:
        return matches

    text = header_value.lower()
    for product_id, (pattern, latest, label) in _OUTDATED.items():
        m = re.search(pattern, text)
        if not m:
            continue
        observed = _parse_version(m.group(1))
        if observed is None:
            continue
        if observed < latest:
            matches.append({
                "product": label,
                "product_id": product_id,
                "observed": ".".join(str(p) for p in observed),
                "latest_known": ".".join(str(p) for p in latest),
            })
    return matches
