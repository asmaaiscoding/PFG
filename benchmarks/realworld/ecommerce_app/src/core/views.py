from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response


@api_view(["GET"])
@permission_classes([AllowAny])
def health_check(request):
    """INTENTIONALLY_PUBLIC: health endpoint for load balancers."""
    return Response({"status": "ok"})


@api_view(["POST"])
@permission_classes([AllowAny])
def login_view(request):
    """INTENTIONALLY_PUBLIC: login endpoint must be public."""
    return Response({"token": "abc123"})
