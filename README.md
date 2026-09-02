# SecureCyber

A Django-based cybersecurity web project. It hosts a suite of utilities to help users secure their digital presence. Current tools include:
- **Password Strength Analyzer**: Evaluates length, complexity, and uniqueness, suggests stronger alternatives, and prevents reuse via a PostgreSQL database.
- **Phishing Email Detector**: Uses a machine learning model (Random Forest) to classify email content as "Phishing" or "Safe" based on textual patterns.


> **Privacy note:** Passwords are never stored in plaintext. Only SHA-256 hashes are persisted, scoped by Django session.

## Stack

- **Backend:** Django 5.x (Python 3.10+)
- **Database:** PostgreSQL
- **Frontend:** Vanilla HTML / CSS / JavaScript (no framework)
- **Theme:** Dark mode

## Project layout

```
SecureCyber/
├── securecyber/    # Django project package (settings, urls, wsgi)
├── analyzer/       # Password Strength Analyzer app
├── dashboard/      # Home + future-tools landing pages
├── templates/      # Django templates (base + per-app)
├── static/         # CSS, JS, images
├── .env.example    # Environment template (copy → .env)
└── requirements.txt
```

## Setup (macOS)

### 1. PostgreSQL

Skip this section if you already have a hosted Postgres (Neon, Supabase, RDS). For local:

```bash
brew install postgresql@16
brew services start postgresql@16
createuser -s securecyber
createdb -O securecyber securecyber
```

### 2. Python environment

```bash
cd /Users/sachinkumar/Desktop/SecureCyber
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Environment

```bash
cp .env.example .env
# Edit .env and set DJANGO_SECRET_KEY to a long random string,
# plus DB_PASSWORD to match the role you created.
```

### 4. Bootstrap Django

```bash
django-admin startproject securecyber .
python manage.py startapp analyzer
python manage.py startapp dashboard
```

(The project skeleton is already provided — re-running these commands will fail/overwrite. Only run them on a fresh clone.)

### 5. Migrate & run

```bash
python manage.py makemigrations analyzer
python manage.py migrate
python manage.py createsuperuser   # optional
python manage.py runserver
```

Visit:

- http://127.0.0.1:8000/ — dashboard
- http://127.0.0.1:8000/analyzer/ — Password Strength Analyzer
- http://127.0.0.1:8000/admin/ — Django admin (if you created a superuser)

## Tests

```bash
python manage.py test analyzer
```

## How the password analyzer works

The score (0–100) is composed of:

| Component        | Max | Rule                                                 |
|------------------|-----|------------------------------------------------------|
| Length           | 40  | 16+ → 40, 12+ → 30, 8+ → 20, 6+ → 10                 |
| Character classes| 28  | +7 each: lowercase / uppercase / digit / symbol      |
| Entropy          | 25  | 80+ bits → 25, 60+ → 18, 40+ → 10, 25+ → 5           |
| Penalties        | —   | common: −35, sequence: −10, repeat 3+: −10, kbd: −8  |

Labels: `≥80 → very_strong`, `≥60 → strong`, `≥40 → medium`, else `weak`.

## Adding new tools

1. Create a new app: `python manage.py startapp <tool>`
2. Add it to `INSTALLED_APPS` in `settings.py`
3. Add URLs under `/tools/<name>/` in `dashboard/urls.py`
4. Build templates in `templates/<tool>/`

The dashboard card grid is data-driven — add your tool to the `tools` list in `dashboard/views.py`.

## Upcoming Tools
The following utilities are currently in development:
- **Hash Inspector**: Identify and crack common cryptographic hashes.
- **Breach Lookup**: Check if credentials have appeared in known data breaches.

