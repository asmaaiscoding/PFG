from django.urls import path, re_path

from . import views

urlpatterns = [
    path("", views.index, name="blog-index"),
    path("post/<int:pk>/", views.PostDetail.as_view(), name="post-detail"),
    path("post/", views.PostCreate.as_view(), name="post-create"),
    re_path(r"^archive/(?P<year>[0-9]{4})/$", views.archive, name="archive"),
]
