from . import repo


def list_my_patients(doctor):
    return repo.patients_for_doctor(doctor)


def get_patient(pk):
    return repo.patient_by_pk(pk)


def register_patient(doctor, data):
    return repo.create_patient(doctor, data)


def update_patient(pk, data):
    return repo.update_patient_by_pk(pk, data)


def delete_patient(pk):
    return repo.delete_patient_by_pk(pk)


def get_prescriptions(pk):
    return repo.prescriptions_for_patient(pk)


def get_lab_results_for_doctor(pk, doctor):
    patient = repo.patient_by_pk(pk)
    if patient.doctor != doctor:
        raise PermissionError("Not your patient")
    return repo.lab_results_for_patient(pk)


def export_all_patients():
    return repo.all_patients()
