from django.urls import path

from . import views

urlpatterns = [
    path("public/", views.public_view, name="public"),
    path("auth/", views.auth_required_view, name="auth"),
    path("perm/", views.perm_required_view, name="perm"),
    path("staff/", views.staff_view, name="staff"),
    path("api/open/", views.api_open, name="api-open"),
    path("api/user/", views.api_user, name="api-user"),
    path("cbv/login/", views.LoginCBV.as_view(), name="cbv-login"),
    path("cbv/perm/", views.PermCBV.as_view(), name="cbv-perm"),
    path("drf/admin/", views.AdminAPIView.as_view(), name="drf-admin"),
    path("drf/anon/", views.AnonAPIView.as_view(), name="drf-anon"),
    path("health/", views.health, name="health"),
    path("login/", views.login_page, name="login"),
]
