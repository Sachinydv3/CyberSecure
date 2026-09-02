from django.urls import path

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("tools/phishing/", views.placeholder, {"tool": "phishing"}, name="tool_phishing"),
    path("tools/hash/", views.placeholder, {"tool": "hash"}, name="tool_hash"),
    path("tools/breach/", views.placeholder, {"tool": "breach"}, name="tool_breach"),
]
