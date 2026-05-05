from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from . import services


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def record_detail(request, pk):
    """IDOR: any authenticated user can view any medical record."""
    record = services.get_record(pk)
    return Response(record)


@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def record_notes(request, pk):
    """COMBINED: can read/write notes on any record (IDOR) + no role check (should be doctor)."""
    if request.method == "GET":
        return Response(services.get_notes(pk))
    note = services.add_note(pk, request.data)
    return Response(note, status=201)


@api_view(["POST"])
def share_record(request, pk):
    """MISSING_AUTH: no authentication at all on record sharing."""
    services.share_record(pk, request.data.get("recipient"))
    return Response({"status": "shared"})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def upload_record(request):
    """SAFE: uploads record for the current user."""
    record = services.upload_for_user(request.user, request.data)
    return Response(record, status=201)
