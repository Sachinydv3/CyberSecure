"""Root URL configuration for SecureCyber."""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include(("dashboard.urls", "dashboard"), namespace="dashboard")),
    path("analyzer/", include(("analyzer.urls", "analyzer"), namespace="analyzer")),
    path("scanner/", include(("scanner.urls", "scanner"), namespace="scanner")),
    path("phishing/", include(("phishing.urls", "phishing"), namespace="phishing")),
]
