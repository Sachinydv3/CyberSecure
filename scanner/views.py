"""Views for the Vulnerability Scanner.

A single view handles both GET (render empty form) and POST (run scan,
render findings). Mirrors ``analyzer.views.form_submit``.
"""

from __future__ import annotations

import logging
import socket
import urllib.request
from typing import List, Tuple
from urllib.parse import urlparse

from django.shortcuts import render

from . import http_checks, port_checks
from .forms import ScanForm

log = logging.getLogger(__name__)


# Cap any single HTTP fetch at 5s. SSL handshakes on third-party sites
# can be slow; this prevents the whole scan from hanging.
_HTTP_TIMEOUT = 5.0

# Per-port connect timeout. 1s is plenty for a local dev server and
# fast enough on a LAN that you won't notice.
_PORT_TIMEOUT = 1.0

# Cap the number of findings we render, so a misconfigured target that
# produces hundreds of duplicate exposures doesn't produce an unusable
# page. 50 is generous.
_MAX_FINDINGS = 50


# --------------------------------------------------------------------------- #
# HTTP helpers (the "fetch" callable injected into http_checks.check_exposure)
# --------------------------------------------------------------------------- #
def _safe_fetch(url: str) -> Tuple[int, dict]:
    """Issue a HEAD/GET fallback, return ``(status_code, headers)``.

    Falls back to GET if the server doesn't respond to HEAD (some
    frameworks return 405 or 501). Returns ``(0, {})`` on network error
    so the caller can distinguish "could not connect" from "exposed".
    """
    req = urllib.request.Request(url, method="HEAD")
    # Identify ourselves so admins can see us in their access logs.
    req.add_header("User-Agent", "SecureCyber-Scanner/1.0")
    try:
        resp = urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT)
        # urlopen in Python 3 returns an http.client.HTTPResponse; its
        # headers are email.message.Message — exactly what http_checks
        # expects.
        return resp.status, resp.headers
    except urllib.error.HTTPError as e:
        # 4xx/5xx with headers is still useful — return those headers so
        # we can keep checking even when the path is blocked.
        return e.code, e.headers if e.headers else {}
    except Exception as e:
        log.info("Fetch failed for %s: %s", url, e.__class__.__name__)
        return 0, {}


def _safe_initial_fetch(url: str) -> Tuple[int, dict]:
    """Same as ``_safe_fetch`` but for the *initial* scan target — GET so
    we get cookies / headers from a real page view.
    """
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "SecureCyber-Scanner/1.0")
    try:
        resp = urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT)
        return resp.status, resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.headers if e.headers else {}
    except Exception as e:
        log.info("Initial fetch failed for %s: %s", url, e.__class__.__name__)
        return 0, {}


def _host_from_url(url: str) -> str:
    """Return just the hostname (no scheme, no port)."""
    parsed = urlparse(url)
    return parsed.hostname or ""


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #
def run_scan(form: ScanForm) -> dict:
    """Run every enabled check against the form's target.

    Returns a dict ready to drop into the template context.
    """
    target = form.cleaned_data["target"]
    scan_type = form.cleaned_data["scan_type"]
    localhost_only = form.cleaned_data["localhost_only"]

    findings: List[dict] = []
    errors: List[str] = []

    host = _host_from_url(target)
    host_is_loopback = port_checks._is_loopback(host)

    # ------- HTTP checks -------
    if scan_type in ("full", "http"):
        status, headers = _safe_initial_fetch(target)
        if status == 0:
            errors.append(
                f"Could not connect to {target} over HTTP. "
                f"Check the URL is reachable and the scheme is correct."
            )
        else:
            findings.extend(http_checks.run_http_checks(target, headers, _safe_fetch))

    # ------- Port scan -------
    if scan_type in ("full", "ports"):
        if localhost_only and not host_is_loopback:
            errors.append(
                f"Port scan skipped: '{host}' is not a loopback / private "
                f"address and 'localhost-only' is enabled."
            )
        else:
            findings.extend(
                port_checks.scan_ports(host, timeout=_PORT_TIMEOUT)
            )

    # Sort: severity high → low → info, then by category for stability.
    findings.sort(key=lambda f: (http_checks.severity_rank(f["severity"]), f["category"]))
    truncated = len(findings) > _MAX_FINDINGS
    if truncated:
        findings = findings[:_MAX_FINDINGS]

    # Severity counts (for the summary header).
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return {
        "target": target,
        "host": host,
        "scan_type": scan_type,
        "localhost_only": localhost_only,
        "host_is_loopback": host_is_loopback,
        "findings": findings,
        "errors": errors,
        "counts": counts,
        "truncated": truncated,
        "max_findings": _MAX_FINDINGS,
    }


# --------------------------------------------------------------------------- #
# View
# --------------------------------------------------------------------------- #
def index(request):
    """GET → render empty form; POST → run scan, render results."""
    form = ScanForm()
    result = None
    if request.method == "POST":
        form = ScanForm(request.POST)
        if form.is_valid():
            result = run_scan(form)

    return render(
        request,
        "scanner/index.html",
        {"form": form, "result": result},
    )
