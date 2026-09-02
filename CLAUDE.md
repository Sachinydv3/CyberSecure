# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

SecureCyber is a Django 5 web app that hosts small cybersecurity utilities. It currently features the **Password Strength Analyzer**, the **Phishing Email Detector**, and the **Secure Login System**. The dashboard reserves slots for two planned tools (Hash Inspector, Breach Lookup) that currently render "coming soon" placeholders.

- **Backend:** Django 5.x, Python 3.10+
- **Database:** PostgreSQL (configured entirely via `.env`)
- **Frontend:** Vanilla HTML/CSS/JS — no bundler, no framework, served from `static/`
- **Theme:** Dark mode only (`data-theme="dark"` on `<html>`)

## Common commands

All commands assume the venv is activated and the working directory is the repo root.

```bash
source .venv/bin/activate

# Run the dev server
python manage.py runserver

# Database migrations (after model changes)
python manage.py makemigrations analyzer
python manage.py migrate

# Tests
python manage.py test analyzer                          # whole analyzer app
python manage.py test analyzer.tests.test_strength      # strength engine only
python manage.py test analyzer.tests.test_views         # view + endpoint tests
python manage.py test analyzer.tests.test_views.AnalyzerViewTests.test_ajax_check_returns_json   # single test

# ML Training
python phishing/train_model.py                           # retrain phishing model & update metrics

# Admin (optional)
python manage.py createsuperuser
```

There is no linter or formatter wired in (no `ruff`, `flake8`, `black`, `prettier`). Match the existing style — see `analyzer/strength.py` and `static/js/analyzer.js` for the in-house conventions.

## Environment setup (first run)

1. PostgreSQL with role `securecyber` and database `securecyber` (see README for `brew install postgresql@16` steps).
2. `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
3. `cp .env.example .env` and edit `DJANGO_SECRET_KEY` + `DB_PASSWORD`.
4. `python manage.py migrate`
5. `python manage.py runserver`

The README explicitly warns that re-running `startproject` / `startapp` will fail or overwrite — only run those on a fresh clone.

## Repository layout

```
securecyber/   Django project (settings, root urls, wsgi/asgi). Reads config via python-decouple.
analyzer/      Password Strength Analyzer — models, views, strength engine, suggester, tests.
dashboard/     Home page + placeholder views for future tools. Tool grid is data-driven from views.py.
templates/     base.html + per-app templates + partials (navbar, sidebar, flash, strength meter).
static/        CSS (theme/base/components/analyzer) and vanilla JS (main, analyzer, meter).
```

## Architecture — how the pieces fit

### Password Strength Analyzer (`analyzer/`)

The pipeline that turns a typed password into a UI response:

1. **`strength.evaluate(password)`** (`analyzer/strength.py`) — pure function, no Django. Returns `{length, score, label, bits, charset, checks}`. Score is 0–100 composed of length (≤40), character-class diversity (≤28), Shannon entropy (≤25, capped at 128 bits), minus penalties for common-password, sequence, repeat, keyboard-row, and digits-only patterns. Labels: `≥80 very_strong`, `≥60 strong`, `≥40 medium`, else `weak`. The 9-item `checks` list drives both the UI checklist and the test assertions.
2. **`suggester.suggest(base, count)`** (`analyzer/suggester.py`) — uses `secrets` (never `random`) to produce strong passwords. Guarantees one character from each of lowercase/uppercase/digit/symbol; `_SAFE_SYMBOLS` is curated to render safely in HTML without escaping. Optional "strengthen a base" variant gives the user a memorable anchor.
3. **`PasswordHistory` model** (`analyzer/models.py`) — stores **only SHA-256 hex digests**, scoped by `session_key`. `password_hash` is unique, which makes "have I seen this before?" a `get_or_create` constant-time lookup. Plaintext is never persisted, never logged.
4. **Views** (`analyzer/views.py`):
   - `index` / `form_submit` — server-rendered, handles no-JS fallback. Requires an explicit `consent` checkbox before writing a hash.
   - `ajax_check` (POST, JSON) — live keystroke feedback (called from `analyzer.js`, 180 ms debounce).
   - `ajax_suggest` (POST, JSON) — returns up to 5 suggestions (server clamps count to 1–5 via `_MIN_COUNT` / `_MAX_COUNT`).
   - Both AJAX endpoints reject input > 256 chars and bad JSON with `400`.
5. **Frontend** (`static/js/`) — `analyzer.js` wires the form, debounces input, posts JSON with CSRF token. `meter.js` exposes `window.SecureCyberMeter.render(data)` so `analyzer.js` stays focused on event handling. Network errors are silently swallowed; the user can still submit the form for a server-side fallback.

### Phishing Email Detector (`phishing/`)

An ML-powered tool that classifies email content as phishing or safe:

1. **ML Pipeline** (`phishing/train_model.py`) — uses `TfidfVectorizer` and `RandomForestClassifier` on a sample CSV dataset. Exports `model.joblib`, `vectorizer.joblib`, and `metrics.json` (accuracy, confusion matrix) to `phishing/ml_model/`.
2. **Inference Engine** (`phishing/detector.py`) — a singleton `PhishingDetector` that lazily loads model artifacts and provides `predict(text)` for classification.
3. **Views** (`phishing/views.py`):
   - `index` — renders the tool interface.
   - `analyze` (POST, JSON) — classifies the input text and returns the result along with pre-calculated model metrics.
4. **Frontend** (`templates/phishing/index.html`) — a clean interface for pasting email content, displaying a color-coded result badge and a performance table for the confusion matrix.

### Secure Login System (`accounts/`)

A demonstration of a secure authentication flow with multi-factor authentication:

1. **User Model** (`accounts/models.py`) — extends `AbstractUser` with `totp_secret` and `is_2fa_enabled` to support TOTP-based 2FA.
2. **Auth Flow** (`accounts/views.py`):
   - **Registration**: Creates new user accounts using standard Django auth.
   - **Two-Step Login**: Verifies password first, then checks for 2FA. If enabled, requires a 6-digit code verified via `pyotp`.
   - **2FA Management**: Allows users to enable/disable 2FA and displays a QR code for authenticator apps using `qrcode`.
3. **Frontend** (`templates/accounts/`) — custom pages for signup, login, 2FA verification, and profile management.

### Dashboard (`dashboard/`)

`views.home` builds the `tools` list (one ready, three placeholders) — the home page template renders this directly. `views.placeholder` is a single view handling all three placeholder URLs by reading the `tool` kwarg against `PLACEHOLDERS` / `DESCRIPTIONS` dicts in `dashboard/views.py`. To add a new tool: see the "Adding new tools" section below.

### Settings (`securecyber/settings.py`)

- All secrets/DB config via `python-decouple` (`config(...)`); defaults exist but are dev-only.
- Security middleware/cookies are always-on (HttpOnly, SameSite=Lax); HTTPS-redirect, HSTS, and `Secure` cookie flags activate only when `DJANGO_DEBUG=False`.
- `STATICFILES_DIRS = [BASE_DIR / "static"]` for dev; `STATIC_ROOT` is `staticfiles/` for `collectstatic`.
- `ALLOWED_HOSTS` parsed as CSV (default `127.0.0.1,localhost`).

## Adding a new tool

Per the README and the existing dashboard wiring:

1. `python manage.py startapp <tool>` (only on a fresh clone)
2. Add the AppConfig to `INSTALLED_APPS` in `securecyber/settings.py`.
3. Add URLs under `/tools/<name>/` in `dashboard/urls.py` — follow the `placeholder(..., {"tool": "<name>"})` pattern, or replace with a real view when ready.
4. Add the entry to the `tools` list in `dashboard/views.py` (`home`). Mark `ready: True` once implemented.
5. Build templates in `templates/<tool>/` extending `base.html`.

## Things to be careful about

- **Plaintext passwords are never stored.** Any new feature that touches passwords must continue to hash via `PasswordHistory.hash_password` (SHA-256 hex) before writing. Never log the raw value.
- **`session_key` scoping.** `_ensure_session` in `analyzer/views.py` forces `request.session.save()` so the key exists before we write history rows. Reuse this helper in any new password-touching view.
- **Input length cap (256).** `analyzer.views._MAX_INPUT_LEN` is enforced on AJAX endpoints; mirror it in any new endpoints to prevent trivial DoS.
- **`SECRET_KEY` default in settings.py is intentionally insecure.** It only fires if `.env` is missing — always copy `.env.example` and edit before running anywhere real.
- **`manage.py startproject`/`startapp` will overwrite existing files.** Don't run them against this checkout.
- **No migrations checked in for `analyzer`** (`analyzer/migrations/__init__.py` is empty). The README's setup steps include `makemigrations analyzer` — run that on first checkout, then commit the generated file.
