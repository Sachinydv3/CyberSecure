from django.urls import path

from . import views

urlpatterns = [
    path("", views.form_submit, name="analyzer_index"),
    path("learn/", views.learn, name="analyzer_learn"),
    path("ajax/check/", views.ajax_check, name="analyzer_ajax_check"),
    path("ajax/suggest/", views.ajax_suggest, name="analyzer_ajax_suggest"),
]
