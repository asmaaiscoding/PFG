from django.urls import include, path

urlpatterns = [
    path("api/patients/", include("patients.urls")),
    path("api/appointments/", include("appointments.urls")),
    path("api/records/", include("records.urls")),
    path("api/", include("core.urls")),
]
