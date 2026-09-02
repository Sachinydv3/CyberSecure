"""Views for the Password Strength Analyzer.

Three entry points:
- ``index`` / ``form_submit`` — server-rendered form (also handles
  non-JS submission).
- ``ajax_check`` — JSON endpoint used by ``analyzer.js`` for live
  keystroke-driven feedback.
- ``ajax_suggest`` — JSON endpoint that returns generated suggestions.
- ``learn`` — educational content page.
"""

from __future__ import annotations

import json
import logging

from django.http import HttpResponseBadRequest, JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_POST

from . import strength, suggester
from .forms import PasswordForm
from .models import PasswordHistory

log = logging.getLogger(__name__)

_MAX_INPUT_LEN = 256


def _ensure_session(request):
    """Force-create a Django session so we can scope password history."""
    if not request.session.session_key:
        request.session.save()
    return request.session.session_key


def index(request):
    """Render the analyzer page (GET only)."""
    form = PasswordForm()
    return render(request, "analyzer/index.html", {"form": form, "result": None})


def learn(request):
    """Educational page about password security."""
    return render(request, "analyzer/learn.html")


def form_submit(request):
    """Handle GET (render form) and POST (analyze + persist hash)."""
    if request.method != "POST":
        return index(request)

    form = PasswordForm(request.POST)
    result = None
    reuse = False
    if form.is_valid():
        pw = form.cleaned_data["password"]
        result = strength.evaluate(pw)

        session_key = _ensure_session(request)
        digest = PasswordHistory.hash_password(pw)
        _, created = PasswordHistory.objects.get_or_create(
            password_hash=digest,
            defaults={
                "session_key": session_key,
                "strength_score": result["score"],
                "strength_label": result["label"],
                "length": len(pw),
            },
        )
        reuse = not created

    return render(
        request,
        "analyzer/index.html",
        {"form": form, "result": result, "reuse": reuse},
    )


@require_POST
def ajax_check(request):
    """Return a JSON strength evaluation for a password in the body."""
    try:
        payload = json.loads(request.body.decode("utf-8"))
        password = payload.get("password", "")
    except (ValueError, UnicodeDecodeError):
        return HttpResponseBadRequest("invalid JSON")

    if not isinstance(password, str) or len(password) > _MAX_INPUT_LEN:
        return HttpResponseBadRequest("password length out of bounds")

    return JsonResponse(strength.evaluate(password))


@require_POST
def ajax_suggest(request):
    """Return up to 5 password suggestions as JSON."""
    try:
        payload = json.loads(request.body.decode("utf-8"))
        base = payload.get("base", "") or ""
        count = int(payload.get("count", 3))
    except (ValueError, UnicodeDecodeError, TypeError):
        return HttpResponseBadRequest("invalid JSON")

    suggestions = suggester.suggest(base=base, count=count)
    return JsonResponse({"suggestions": suggestions})
