from django.urls import path

from . import views

urlpatterns = [
    path("invoice/<int:pk>/", views.get_invoice, name="invoice"),
    path("admin/users/", views.AdminUsers.as_view(), name="admin-users"),
    path("noop/", views.noop, name="noop"),
]
