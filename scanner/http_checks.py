"""HTTP security checks.

Each public function returns a list of finding dicts with the shape
``{severity, category, title, detail, recommendation}``. The functions
are pure: they take a parsed URL plus the bytes/headers of an HTTP
response and never reach out to the network themselves. The view layer
is responsible for making the request (and gating on localhost-only
mode, timeouts, etc.).

Why this split? It keeps each check unit-testable with hand-built
``email.message.Message`` headers — no need to spin up a test server.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List
from urllib.parse import urlparse


# --------------------------------------------------------------------------- #
# Header catalogue — what we expect to see, and what its absence means.
# --------------------------------------------------------------------------- #
# Map of header-name (lowercase) -> (severity, title, recommendation)
EXPECTED_HEADERS: Dict[str, Dict[str, str]] = {
    "strict-transport-security": {
        "severity": "high",
        "title": "Missing Strict-Transport-Security (HSTS)",
        "recommendation": (
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
            "to force browsers to use HTTPS. Without it, an attacker can "
            "downgrade a session to plaintext on the first visit."
        ),
    },
    "content-security-policy": {
        "severity": "medium",
        "title": "Missing Content-Security-Policy (CSP)",
        "recommendation": (
            "Add a Content-Security-Policy header that restricts script "
            "sources. A starter policy: "
            "'default-src 'self'; script-src 'self'; object-src 'none'; "
            "frame-ancestors 'none''. This is the single most effective "
            "mitigation against cross-site scripting."
        ),
    },
    "x-content-type-options": {
        "severity": "low",
        "title": "Missing X-Content-Type-Options: nosniff",
        "recommendation": (
            "Add 'X-Content-Type-Options: nosniff' so browsers refuse to "
            "MIME-sniff responses into a different content type."
        ),
    },
    "x-frame-options": {
        "severity": "low",
        "title": "Missing X-Frame-Options or frame-ancestors",
        "recommendation": (
            "Add 'X-Frame-Options: DENY' (or 'frame-ancestors 'none'' in "
            "CSP) to prevent your pages from being embedded in an "
            "attacker-controlled iframe (clickjacking)."
        ),
    },
    "referrer-policy": {
        "severity": "low",
        "title": "Missing Referrer-Policy",
        "recommendation": (
            "Add 'Referrer-Policy: strict-origin-when-cross-origin' so the "
            "full URL isn't leaked to third parties via the Referer header."
        ),
    },
    "permissions-policy": {
        "severity": "low",
        "title": "Missing Permissions-Policy",
        "recommendation": (
            "Add a Permissions-Policy header disabling powerful features "
            "(camera, microphone, geolocation) you don't use, e.g. "
            "'Permissions-Policy: camera=(), microphone=(), geolocation=()'."
        ),
    },
}


# Headers that leak server identity / version. Their presence is a finding
# even though the recommendation is "remove the header".
DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


# Sensitive paths we probe (HTTP HEAD). Each entry has severity because
# exposing some of these (e.g. /.env) is far worse than others (e.g.
# /robots.txt, which is informational).
SENSITIVE_PATHS = [
    ("/.env",              "high"),
    ("/.git/config",       "high"),
    ("/wp-admin/",         "medium"),
    ("/administrator/",    "medium"),
    ("/phpmyadmin/",       "high"),
    ("/.well-known/security.txt", "info"),
    ("/server-status",     "medium"),    # Apache
    ("/server-info",       "medium"),    # Apache
    ("/elmah.axd",         "medium"),    # ASP.NET error log
    ("/console/",          "high"),      # Rails / Django admin
    ("/api/",              "info"),
    ("/debug/",            "medium"),
    ("/healthz",           "info"),
    ("/robots.txt",        "info"),
    ("/sitemap.xml",       "info"),
]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _normalise_headers(headers) -> Dict[str, str]:
    """Lower-case the keys of an ``email.message.Message``-style header map."""
    out: Dict[str, str] = {}
    for k, v in dict(headers).items():
        if k is None:
            continue
        out[k.lower()] = v
    return out


def _is_https(url: str) -> bool:
    return urlparse(url).scheme.lower() == "https"


# --------------------------------------------------------------------------- #
# Individual checks
# --------------------------------------------------------------------------- #
def check_headers(url: str, headers) -> List[Dict]:
    """Flag missing security headers and version-disclosing headers."""
    findings: List[Dict] = []
    norm = _normalise_headers(headers)

    for name, meta in EXPECTED_HEADERS.items():
        if name not in norm:
            findings.append({
                "severity": meta["severity"],
                "category": "http-headers",
                "title": meta["title"],
                "detail": f"The response from {url} did not include a '{name}' header.",
                "recommendation": meta["recommendation"],
            })

    for name in DISCLOSURE_HEADERS:
        if name in norm and norm[name]:
            findings.append({
                "severity": "medium",
                "category": "http-headers",
                "title": f"Server identity disclosed in '{name}' header",
                "detail": f"{name}: {norm[name]}",
                "recommendation": (
                    f"Remove the '{name}' header (or strip the version) so "
                    f"attackers don't get a free fingerprint of your software. "
                    f"On most servers this is a one-line config change."
                ),
            })

    return findings


def check_cookies(url: str, headers) -> List[Dict]:
    """Inspect Set-Cookie headers for missing Secure / HttpOnly / SameSite."""
    findings: List[Dict] = []
    # ``get_all`` handles multiple Set-Cookie values that email.Message
    # otherwise collapses into a single comma-joined string.
    raw_list: Iterable[str]
    if hasattr(headers, "get_all"):
        raw_list = headers.get_all("Set-Cookie") or []
    else:
        raw_list = [headers.get("Set-Cookie", "")]
    raw_list = [r for r in raw_list if r]

    if not raw_list:
        return findings

    for raw in raw_list:
        first = raw.split(";", 1)[0]
        name = first.split("=", 1)[0].strip() or "(unnamed)"
        lower = raw.lower()

        # HttpOnly + Secure are only meaningful for cookies sent over HTTPS.
        if "secure" not in lower:
            sev = "high" if _is_https(url) else "medium"
            findings.append({
                "severity": sev,
                "category": "cookies",
                "title": f"Cookie '{name}' missing Secure flag",
                "detail": f"Set-Cookie: {raw}",
                "recommendation": (
                    "Add the 'Secure' attribute so the browser only sends "
                    "the cookie over HTTPS."
                ),
            })
        if "httponly" not in lower:
            findings.append({
                "severity": "medium",
                "category": "cookies",
                "title": f"Cookie '{name}' missing HttpOnly flag",
                "detail": f"Set-Cookie: {raw}",
                "recommendation": (
                    "Add the 'HttpOnly' attribute so client-side JavaScript "
                    "cannot read the cookie. This is the standard defence "
                    "against session theft via XSS."
                ),
            })
        if "samesite" not in lower:
            findings.append({
                "severity": "low",
                "category": "cookies",
                "title": f"Cookie '{name}' missing SameSite attribute",
                "detail": f"Set-Cookie: {raw}",
                "recommendation": (
                    "Add 'SameSite=Lax' (or 'Strict' for sensitive cookies) "
                    "to prevent the cookie from being sent on cross-site "
                    "requests."
                ),
            })

    return findings


def check_exposure(url: str, fetch) -> List[Dict]:
    """Probe a curated list of sensitive paths on the same host.

    ``fetch`` is a callable ``(url: str) -> (status: int, headers)``.
    Inject this so the caller controls timeouts, retries, and whether the
    request even leaves the network.
    """
    findings: List[Dict] = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path, severity in SENSITIVE_PATHS:
        target = base + path
        try:
            status, _headers = fetch(target)
        except Exception:
            # Network failure for one path shouldn't sink the whole report.
            continue
        # 2xx → exposed. 401/403 → behind auth (still informational).
        if 200 <= status < 300:
            findings.append({
                "severity": severity,
                "category": "exposure",
                "title": f"Sensitive path reachable: {path}",
                "detail": f"{target} returned HTTP {status}.",
                "recommendation": (
                    f"Restrict access to {path} at the webserver / reverse "
                    f"proxy. If this resource is not needed, remove the "
                    f"route entirely."
                ),
            })
        elif severity == "info" and 200 <= status < 400:
            findings.append({
                "severity": "info",
                "category": "exposure",
                "title": f"Path accessible: {path}",
                "detail": f"{target} returned HTTP {status}.",
                "recommendation": "Informational only.",
            })

    return findings


def check_outdated_software(headers) -> List[Dict]:
    """Match Server / X-Powered-By strings against the outdated-software table."""
    findings: List[Dict] = []
    norm = _normalise_headers(headers)

    # Local import to keep http_checks importable in isolation.
    from . import outdated

    for header in ("server", "x-powered-by", "x-aspnet-version"):
        value = norm.get(header)
        if not value:
            continue
        for match in outdated.match_version(value):
            findings.append({
                "severity": "medium",
                "category": "outdated",
                "title": f"Outdated {match['product']} version detected",
                "detail": (
                    f"Header '{header}' reported {match['observed']}. "
                    f"Latest known good: {match['latest_known']}."
                ),
                "recommendation": (
                    f"Upgrade {match['product']} to at least "
                    f"{match['latest_known']}. Older versions have "
                    f"publicly known vulnerabilities that automated scanners "
                    f"will exploit."
                ),
            })

    return findings


# --------------------------------------------------------------------------- #
# Top-level orchestrator
# --------------------------------------------------------------------------- #
def run_http_checks(url: str, headers, fetch) -> List[Dict]:
    """Run every HTTP check against a single target.

    ``headers`` is the parsed headers from the *initial* response to
    ``url``. ``fetch`` is the HEAD-style callable used by
    :func:`check_exposure` (see its docstring).
    """
    findings: List[Dict] = []
    findings.extend(check_headers(url, headers))
    findings.extend(check_cookies(url, headers))
    findings.extend(check_outdated_software(headers))
    findings.extend(check_exposure(url, fetch))
    return findings


def severity_rank(s: str) -> int:
    """Sort key: high > medium > low > info."""
    return {"high": 0, "medium": 1, "low": 2, "info": 3}.get(s, 4)


_SAFE_URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)


def is_safe_url(url: str) -> bool:
    """Crude URL sanity check — must look like http(s)://host/..."""
    if not url or not isinstance(url, str):
        return False
    if len(url) > 2048:
        return False
    if not _SAFE_URL_RE.match(url):
        return False
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    if not parsed.netloc:
        return False
    return True
