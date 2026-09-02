"""WSGI config for SecureCyber project."""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "securecyber.settings")

application = get_wsgi_application()
