from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from . import services


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def inbox(request):
    """SAFE: lists only the current user's messages."""
    messages = services.get_inbox(request.user)
    return Response(messages)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def message_detail(request, pk):
    """IDOR: can read any message by pk without ownership check."""
    message = services.get_message(pk)
    return Response(message)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def send_message(request):
    """SAFE: sends message as current user."""
    msg = services.send(request.user, request.data)
    return Response(msg, status=201)


@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def delete_message(request, pk):
    """IDOR: can delete any message without ownership check."""
    services.delete_message(pk)
    return Response(status=204)
