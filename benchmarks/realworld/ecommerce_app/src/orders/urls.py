from django.urls import path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r"", views.OrderViewSet, basename="orders")

urlpatterns = [
    path("<int:pk>/cancel/", views.cancel_order, name="order-cancel"),
    path("<int:pk>/refund/", views.refund_order, name="order-refund"),
    path("bulk-delete/", views.bulk_delete_orders, name="orders-bulk-delete"),
] + router.urls
