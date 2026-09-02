"""Password strength scoring engine.

Produces a deterministic 0–100 score from a password string, along with
a label (``weak`` / ``medium`` / ``strong`` / ``very_strong``) and a list
of pass/fail checks that drive both the UI and tests.

The algorithm combines:
- Length contribution
- Character-class diversity
- Shannon-style entropy (total bits)
- Pattern penalties: common-password list, sequential runs, repeated
  characters, keyboard rows, and digits-only strings.
"""

from __future__ import annotations

import math
import re
from typing import Dict, List

from . import common_passwords as CP


_LABEL_THRESHOLDS = (
    (80, "very_strong"),
    (60, "strong"),
    (40, "medium"),
    (0, "weak"),
)

_KEYBOARD_ROWS = (
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
)


def _label_for(score: int) -> str:
    for threshold, label in _LABEL_THRESHOLDS:
        if score >= threshold:
            return label
    return "weak"


def _charset_size(pw: str) -> int:
    """Return the effective alphabet size used by the password."""
    size = 0
    if re.search(r"[a-z]", pw):
        size += 26
    if re.search(r"[A-Z]", pw):
        size += 26
    if re.search(r"\d", pw):
        size += 10
    if re.search(r"[^A-Za-z0-9]", pw):
        size += 33
    return size or 1


def _shannon_bits(pw: str) -> float:
    """Approximate total entropy in bits = H(char) × length."""
    if not pw:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in pw:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(pw)
    h = 0.0
    for c in freq.values():
        p = c / n
        h -= p * math.log2(p)
    return h * n


def _has_sequence(pw: str) -> bool:
    """Detect ascending or descending runs of 4+ consecutive characters."""
    s = pw.lower()
    for i in range(len(s) - 3):
        a, b, c, d = (s[i + k] for k in range(4))
        if ord(b) - ord(a) == ord(c) - ord(b) == ord(d) - ord(c) == 1:
            return True
        if ord(a) - ord(b) == ord(b) - ord(c) == ord(c) - ord(d) == 1:
            return True
    return False


def _has_repeat(pw: str) -> bool:
    """Detect 3+ identical characters in a row."""
    return bool(re.search(r"(.)\1\1", pw))


def _has_keyboard_row(pw: str) -> bool:
    """Detect 4+ consecutive keys from a single keyboard row."""
    s = pw.lower()
    for row in _KEYBOARD_ROWS:
        for i in range(len(row) - 3):
            chunk = row[i : i + 4]
            if chunk in s or chunk[::-1] in s:
                return True
    return False


def evaluate(password: str) -> Dict:
    """Evaluate a password and return a structured result dict.

    Returned keys: ``length``, ``score``, ``label``, ``bits``,
    ``charset``, ``checks``.
    """
    pw = password or ""
    length = len(pw)
    charset = _charset_size(pw)
    bits = min(_shannon_bits(pw), 128.0)  # cap so absurd inputs plateau

    score = 0

    # --- Length contribution (0..40) ---
    if length >= 16:
        score += 40
    elif length >= 12:
        score += 30
    elif length >= 8:
        score += 20
    elif length >= 6:
        score += 10
    else:
        score += max(0, length - 1) * 2

    # --- Character-class contribution (0..28) ---
    classes = sum(
        bool(re.search(p, pw))
        for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
    )
    score += classes * 7

    # --- Entropy contribution (0..25) ---
    if bits >= 80:
        score += 25
    elif bits >= 60:
        score += 18
    elif bits >= 40:
        score += 10
    elif bits >= 25:
        score += 5

    # --- Penalties ---
    if pw.lower() in CP.COMMON_PASSWORDS:
        score -= 35
    if _has_sequence(pw):
        score -= 10
    if _has_repeat(pw):
        score -= 10
    if _has_keyboard_row(pw):
        score -= 8
    if re.fullmatch(r"\d+", pw):
        score -= 15

    score = max(0, min(100, score))

    checks: List[Dict] = [
        {"label": "At least 12 characters", "passed": length >= 12},
        {"label": "Contains uppercase letter", "passed": bool(re.search(r"[A-Z]", pw))},
        {"label": "Contains lowercase letter", "passed": bool(re.search(r"[a-z]", pw))},
        {"label": "Contains a digit", "passed": bool(re.search(r"\d", pw))},
        {"label": "Contains a symbol", "passed": bool(re.search(r"[^A-Za-z0-9]", pw))},
        {"label": "Not in common-password list", "passed": pw.lower() not in CP.COMMON_PASSWORDS},
        {"label": "No sequential run (abc/123)", "passed": not _has_sequence(pw)},
        {"label": "No keyboard row (qwerty)", "passed": not _has_keyboard_row(pw)},
        {"label": "No 3+ repeated characters", "passed": not _has_repeat(pw)},
    ]

    return {
        "length": length,
        "score": score,
        "label": _label_for(score),
        "bits": round(bits, 1),
        "charset": charset,
        "checks": checks,
    }
