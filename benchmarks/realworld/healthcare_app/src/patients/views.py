from rest_framework import viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response

from . import services


class PatientViewSet(viewsets.ModelViewSet):
    """Patients CRUD. Only doctors/admins should access other patients' data."""
    permission_classes = [IsAuthenticated]
    queryset = []
    serializer_class = None

    def list(self, request):
        # SAFE: returns only patients assigned to this doctor
        patients = services.list_my_patients(request.user)
        return Response(patients)

    def retrieve(self, request, pk=None):
        # IDOR: any authenticated user can view any patient's data
        patient = services.get_patient(pk)
        return Response(patient)

    def create(self, request):
        # SAFE: creates patient record for current doctor
        patient = services.register_patient(request.user, request.data)
        return Response(patient, status=201)

    def update(self, request, pk=None):
        # IDOR: any authenticated user can update any patient
        patient = services.update_patient(pk, request.data)
        return Response(patient)

    def destroy(self, request, pk=None):
        # MISSING_ROLE: should be admin only, but any authenticated user can delete
        services.delete_patient(pk)
        return Response(status=204)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def patient_prescriptions(request, pk):
    """IDOR: any authenticated user can view any patient's prescriptions."""
    prescriptions = services.get_prescriptions(pk)
    return Response(prescriptions)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def patient_lab_results(request, pk):
    """SAFE: checks that requesting user is the assigned doctor."""
    results = services.get_lab_results_for_doctor(pk, request.user)
    return Response(results)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def export_patients(request):
    """MISSING_ROLE: any authenticated user can export all patient data (should be admin)."""
    data = services.export_all_patients()
    return Response(data)
