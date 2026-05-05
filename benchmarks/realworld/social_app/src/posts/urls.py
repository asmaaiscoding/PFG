from django.urls import path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r"", views.PostViewSet, basename="posts")

urlpatterns = [
    path("<int:pk>/comments/", views.post_comments, name="post-comments"),
    path("<int:pk>/like/", views.like_post, name="post-like"),
    path("feed/", views.feed, name="feed"),
    path("trending/", views.trending, name="trending"),
    path("moderation/hide/<int:pk>/", views.moderate_hide, name="moderate-hide"),
] + router.urls
