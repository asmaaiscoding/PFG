from django.urls import path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r"", views.ProductViewSet, basename="products")

urlpatterns = [
    path("<int:pk>/reviews/", views.product_reviews, name="product-reviews"),
    path("import/", views.import_products, name="product-import"),
] + router.urls
