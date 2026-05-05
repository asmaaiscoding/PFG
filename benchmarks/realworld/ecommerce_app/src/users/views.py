from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response

from . import services


@api_view(["GET", "PUT"])
@permission_classes([IsAuthenticated])
def my_profile(request):
    """SAFE: accesses only current user's data."""
    if request.method == "GET":
        profile = services.get_profile(request.user)
        return Response(profile)
    profile = services.update_profile(request.user, request.data)
    return Response(profile)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_detail(request, pk):
    """IDOR: any authenticated user can view any user's full details."""
    user = services.get_user_detail(pk)
    return Response(user)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_addresses(request, pk):
    """IDOR: any authenticated user can view any user's addresses."""
    addresses = services.get_user_addresses(pk)
    return Response(addresses)


@api_view(["GET"])
@permission_classes([IsAdminUser])
def admin_list_users(request):
    """SAFE: admin-only list all users."""
    users = services.list_all_users()
    return Response(users)
