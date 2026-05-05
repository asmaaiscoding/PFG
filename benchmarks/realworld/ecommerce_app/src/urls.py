from django.urls import include, path

urlpatterns = [
    path("api/orders/", include("orders.urls")),
    path("api/products/", include("products.urls")),
    path("api/users/", include("users.urls")),
    path("api/", include("core.urls")),
]
