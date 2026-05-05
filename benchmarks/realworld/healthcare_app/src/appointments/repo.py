class Appointment:
    objects = None  # type: ignore[assignment]


class TimeSlot:
    objects = None  # type: ignore[assignment]


def appointments_for_user(user):
    return Appointment.objects.filter(patient=user)


def appointment_by_pk(pk):
    return Appointment.objects.get(pk=pk)


def create_appointment(user, data):
    return Appointment.objects.create(patient=user)


def update_appointment(pk, data):
    appt = Appointment.objects.get(pk=pk)
    return appt


def delete_appointment(pk):
    Appointment.objects.filter(pk=pk).delete()


def all_available_slots():
    return TimeSlot.objects.filter(is_available=True)
