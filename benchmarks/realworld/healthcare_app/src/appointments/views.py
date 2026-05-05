from rest_framework import viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from . import services


class AppointmentViewSet(viewsets.ModelViewSet):
    """Appointments: booking system."""
    permission_classes = [IsAuthenticated]
    queryset = []
    serializer_class = None

    def list(self, request):
        # SAFE: lists only user's own appointments
        return Response(services.list_my_appointments(request.user))

    def retrieve(self, request, pk=None):
        # IDOR: can view any appointment details
        return Response(services.get_appointment(pk))

    def create(self, request):
        # SAFE: books appointment for current user
        appt = services.book_appointment(request.user, request.data)
        return Response(appt, status=201)

    def update(self, request, pk=None):
        # SAFE: reschedule checks ownership
        appt = services.reschedule_for_user(pk, request.user, request.data)
        return Response(appt)

    def destroy(self, request, pk=None):
        # IDOR: cancels any appointment without ownership check
        services.cancel_appointment(pk)
        return Response(status=204)


@api_view(["GET"])
@permission_classes([AllowAny])
def available_slots(request):
    """INTENTIONALLY_PUBLIC: available time slots are public."""
    slots = services.get_available_slots()
    return Response(slots)
