"""Cryptographically secure strong-password generator.

Uses :mod:`secrets` for randomness (never :mod:`random`). Each generated
password is guaranteed to contain at least one character from each of:
lowercase, uppercase, digits, symbols.
"""

from __future__ import annotations

import secrets
import string
from typing import Dict, List

from . import strength


# Symbols chosen to render safely in HTML without escaping.
_SAFE_SYMBOLS = "!@#$%^&*?-_+=."

_DEFAULT_LENGTH = 18
_MIN_COUNT = 1
_MAX_COUNT = 5


def _rand(n: int, alphabet: str) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _generate(length: int = _DEFAULT_LENGTH) -> str:
    """Generate a strong random password of ``length`` characters."""
    if length < 4:
        length = 4
    groups = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        _SAFE_SYMBOLS,
    ]
    # Guarantee one of each group.
    chars = [_rand(1, g) for g in groups]
    pool = "".join(groups)
    chars.append(_rand(length - len(chars), pool))
    seq = list("".join(chars))
    secrets.SystemRandom().shuffle(seq)
    return "".join(seq)


def _strengthen(base: str) -> List[str]:
    """Return a list of slightly-transformed variants of a user-supplied base.

    Used to give the user a familiar anchor they can remember while
    nudging them toward a stronger password.
    """
    out: List[str] = []
    b = (base or "").strip()
    if not b:
        return out

    suffix = _rand(4, string.digits + _SAFE_SYMBOLS)
    mid = _rand(1, _SAFE_SYMBOLS)

    if len(b) >= 4:
        cut = len(b) // 2
        variant = b[:cut] + mid + b[cut:] + suffix
    else:
        variant = b.capitalize() + mid + suffix

    out.append(variant)
    return out


def suggest(base: str = "", count: int = 3) -> List[Dict]:
    """Return up to ``count`` strong-password suggestions with scores."""
    count = max(_MIN_COUNT, min(count, _MAX_COUNT))

    pool: List[str] = list(_strengthen(base))
    while len(pool) < count:
        pool.append(_generate())

    seen: set = set()
    out: List[Dict] = []
    for p in pool:
        if p in seen:
            continue
        seen.add(p)
        ev = strength.evaluate(p)
        out.append({"value": p, "score": ev["score"], "label": ev["label"]})

    out.sort(key=lambda x: x["score"], reverse=True)
    return out[:count]
