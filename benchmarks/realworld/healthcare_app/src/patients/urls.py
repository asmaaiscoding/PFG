from django.urls import path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r"", views.PatientViewSet, basename="patients")

urlpatterns = [
    path("<int:pk>/prescriptions/", views.patient_prescriptions, name="patient-prescriptions"),
    path("<int:pk>/lab-results/", views.patient_lab_results, name="patient-lab-results"),
    path("export/", views.export_patients, name="export-patients"),
] + router.urls
