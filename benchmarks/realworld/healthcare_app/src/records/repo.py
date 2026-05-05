class MedicalRecord:
    objects = None  # type: ignore[assignment]


class Note:
    objects = None  # type: ignore[assignment]


class RecordShare:
    objects = None  # type: ignore[assignment]


def record_by_pk(pk):
    return MedicalRecord.objects.get(pk=pk)


def notes_for_record(pk):
    return Note.objects.filter(record_id=pk)


def create_note(pk, data):
    return Note.objects.create(record_id=pk)


def add_share(pk, recipient):
    return RecordShare.objects.create(record_id=pk, recipient=recipient)


def create_record(user, data):
    return MedicalRecord.objects.create(patient=user)
