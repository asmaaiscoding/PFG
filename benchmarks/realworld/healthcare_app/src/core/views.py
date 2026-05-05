from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response


@api_view(["GET"])
@permission_classes([AllowAny])
def health_check(request):
    """INTENTIONALLY_PUBLIC: health endpoint."""
    return Response({"status": "ok"})


@api_view(["POST"])
@permission_classes([AllowAny])
def register(request):
    """INTENTIONALLY_PUBLIC: user registration must be public."""
    return Response({"user_id": 1}, status=201)
