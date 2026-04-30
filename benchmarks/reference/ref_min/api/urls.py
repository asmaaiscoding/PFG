from rest_framework.routers import DefaultRouter
from django.urls import path

from . import views

router = DefaultRouter()
router.register(r"users", views.UserViewSet, basename="users")

urlpatterns = [
    path("health/", views.HealthAPIView.as_view(), name="health"),
] + router.urls
