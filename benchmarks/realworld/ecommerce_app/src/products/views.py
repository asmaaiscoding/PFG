from rest_framework import viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated
from rest_framework.response import Response

from . import services


class ProductViewSet(viewsets.ModelViewSet):
    """Products: list/retrieve are public, create/update/destroy require admin."""
    queryset = []
    serializer_class = None

    def get_permissions(self):
        if self.action in ["list", "retrieve"]:
            return [AllowAny()]
        return [IsAdminUser()]

    def list(self, request):
        # INTENTIONALLY_PUBLIC: product catalog is public
        products = services.list_products()
        return Response(products)

    def retrieve(self, request, pk=None):
        # INTENTIONALLY_PUBLIC: single product view is public
        product = services.get_product(pk)
        return Response(product)

    def create(self, request):
        # SAFE: admin-only create
        product = services.create_product(request.data)
        return Response(product, status=201)

    def update(self, request, pk=None):
        # SAFE: admin-only update
        product = services.update_product(pk, request.data)
        return Response(product)

    def destroy(self, request, pk=None):
        # SAFE: admin-only destroy
        services.delete_product(pk)
        return Response(status=204)


@api_view(["GET"])
@permission_classes([AllowAny])
def product_reviews(request, pk):
    """INTENTIONALLY_PUBLIC: anyone can read reviews."""
    reviews = services.get_reviews_for_product(pk)
    return Response(reviews)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def import_products(request):
    """MISSING_ROLE: any authenticated user can import products (should be admin)."""
    services.bulk_import(request.data)
    return Response({"status": "imported"})
