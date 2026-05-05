from django.urls import path

from . import views

urlpatterns = [
    path("health/", views.health_check, name="health"),
    path("login/", views.login_view, name="login"),
]
