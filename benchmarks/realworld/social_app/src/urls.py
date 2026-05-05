from django.urls import include, path

urlpatterns = [
    path("api/posts/", include("posts.urls")),
    path("api/profiles/", include("profiles.urls")),
    path("api/messages/", include("messages.urls")),
    path("api/", include("core.urls")),
]
