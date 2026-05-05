from django.urls import path

from . import views

urlpatterns = [
    path("me/", views.my_profile, name="user-profile"),
    path("<int:pk>/", views.user_detail, name="user-detail"),
    path("<int:pk>/addresses/", views.user_addresses, name="user-addresses"),
    path("admin/list/", views.admin_list_users, name="admin-list-users"),
]
