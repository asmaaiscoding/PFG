from . import repo


def list_my_appointments(user):
    return repo.appointments_for_user(user)


def get_appointment(pk):
    return repo.appointment_by_pk(pk)


def book_appointment(user, data):
    return repo.create_appointment(user, data)


def reschedule_for_user(pk, user, data):
    appt = repo.appointment_by_pk(pk)
    if appt.patient != user:
        raise PermissionError("Not your appointment")
    return repo.update_appointment(pk, data)


def cancel_appointment(pk):
    return repo.delete_appointment(pk)


def get_available_slots():
    return repo.all_available_slots()
