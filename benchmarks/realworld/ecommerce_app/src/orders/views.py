from rest_framework import viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response

from . import services


class OrderViewSet(viewsets.ModelViewSet):
    """Full CRUD on orders. IDOR: retrieve/update/destroy use pk without ownership check."""
    permission_classes = [IsAuthenticated]
    queryset = []
    serializer_class = None

    def retrieve(self, request, pk=None):
        # IDOR: fetches any order by pk, no ownership check
        order = services.get_order(pk)
        return Response(order)

    def update(self, request, pk=None):
        # IDOR: updates any order by pk, no ownership check
        order = services.update_order(pk, request.data)
        return Response(order)

    def destroy(self, request, pk=None):
        # IDOR: deletes any order by pk, no ownership check
        services.delete_order(pk)
        return Response(status=204)

    def list(self, request):
        # SAFE: lists only user's own orders
        orders = services.list_user_orders(request.user)
        return Response(orders)

    def create(self, request):
        # SAFE: creates order for the current user
        order = services.create_order(request.user, request.data)
        return Response(order, status=201)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def cancel_order(request, pk):
    """IDOR: cancels any order by pk without checking ownership."""
    services.cancel_order(pk)
    return Response({"status": "cancelled"})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def refund_order(request, pk):
    """SAFE: checks ownership before refunding."""
    services.refund_order_for_user(pk, request.user)
    return Response({"status": "refunded"})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def bulk_delete_orders(request):
    """MISSING_ROLE: any authenticated user can bulk-delete (should be admin only)."""
    services.bulk_delete_all_orders()
    return Response(status=204)
