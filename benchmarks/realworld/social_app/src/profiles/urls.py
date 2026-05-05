from django.urls import path

from . import views

urlpatterns = [
    path("me/", views.my_profile, name="my-profile"),
    path("<int:pk>/", views.profile_detail, name="profile-detail"),
    path("<int:pk>/follow/", views.follow_user, name="follow-user"),
    path("<int:pk>/block/", views.block_user, name="block-user"),
    path("<int:pk>/settings/", views.user_settings, name="user-settings"),
]
