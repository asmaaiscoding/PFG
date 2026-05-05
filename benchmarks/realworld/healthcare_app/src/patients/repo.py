class Patient:
    objects = None  # type: ignore[assignment]


class Prescription:
    objects = None  # type: ignore[assignment]


class LabResult:
    objects = None  # type: ignore[assignment]


def patients_for_doctor(doctor):
    return Patient.objects.filter(doctor=doctor)


def patient_by_pk(pk):
    return Patient.objects.get(pk=pk)


def create_patient(doctor, data):
    return Patient.objects.create(doctor=doctor)


def update_patient_by_pk(pk, data):
    patient = Patient.objects.get(pk=pk)
    return patient


def delete_patient_by_pk(pk):
    Patient.objects.filter(pk=pk).delete()


def prescriptions_for_patient(pk):
    return Prescription.objects.filter(patient_id=pk)


def lab_results_for_patient(pk):
    return LabResult.objects.filter(patient_id=pk)


def all_patients():
    return Patient.objects.all()
