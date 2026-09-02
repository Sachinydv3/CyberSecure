"""Views for the dashboard: the home grid and placeholder pages for
future cybersecurity tools."""

from django.shortcuts import render


PLACEHOLDERS = {
    "hash": "Hash Inspector",
    "breach": "Breach Lookup",
}

DESCRIPTIONS = {
    "hash": "Generate or verify SHA-1, SHA-256, and BLAKE2 hashes of any "
            "text or file you upload.",
    "breach": "Look up whether an email address has appeared in a public "
              "data breach, using HIBP-style k-anonymity.",
}


def home(request):
    """Render the dashboard landing page with a card grid of tools."""
    tools = [
        {
            "name": "Password Strength Analyzer",
            "url": "analyzer:analyzer_index",
            "ready": True,
            "icon": "🔑",
            "description": (
                "Evaluate length, complexity, and uniqueness of any "
                "password. Get stronger alternatives and reuse alerts."
            ),
        },
        {
            "name": "Vulnerability Scanner",
            "url": "scanner:scanner_index",
            "ready": True,
            "icon": "🛠️",
            "description": (
                "Lightweight HTTP + port scan: missing security headers, "
                "server-disclosure, sensitive-path exposure, and a "
                "TCP-connect scan of common ports."
            ),
        },
        {
            "name": "Phishing Email Detector",
            "url": "phishing:index",
            "ready": True,
            "icon": "🎣",
            "description": (
                "Analyze email content using machine learning to detect "
                "phishing attempts and common fraud patterns."
            ),
        },
        {
            "name": PLACEHOLDERS["hash"],
            "url": "dashboard:tool_hash",
            "ready": False,
            "icon": "#️⃣",
            "description": DESCRIPTIONS["hash"],
        },
        {
            "name": PLACEHOLDERS["breach"],
            "url": "dashboard:tool_breach",
            "ready": False,
            "icon": "🛡️",
            "description": DESCRIPTIONS["breach"],
        },
    ]
    return render(request, "dashboard/home.html", {"tools": tools})


def placeholder(request, tool: str):
    """Render a 'coming soon' page for a not-yet-implemented tool."""
    context = {
        "tool": tool,
        "tool_name": PLACEHOLDERS.get(tool, "Coming soon"),
        "tool_description": DESCRIPTIONS.get(tool, ""),
    }
    return render(request, "dashboard/placeholders/_base.html", context)
