from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from . import services


@api_view(["GET", "PUT"])
@permission_classes([IsAuthenticated])
def my_profile(request):
    """SAFE: own profile access only."""
    if request.method == "GET":
        return Response(services.get_profile(request.user))
    return Response(services.update_profile(request.user, request.data))


@api_view(["GET"])
@permission_classes([AllowAny])
def profile_detail(request, pk):
    """INTENTIONALLY_PUBLIC: public profile page."""
    return Response(services.get_public_profile(pk))


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def follow_user(request, pk):
    """SAFE: authenticated follow action."""
    services.follow(request.user, pk)
    return Response({"status": "followed"})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def block_user(request, pk):
    """SAFE: authenticated block action."""
    services.block(request.user, pk)
    return Response({"status": "blocked"})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_settings(request, pk):
    """IDOR: can view any user's private settings."""
    return Response(services.get_settings(pk))
