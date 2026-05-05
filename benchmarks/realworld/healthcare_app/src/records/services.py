from . import repo


def get_record(pk):
    return repo.record_by_pk(pk)


def get_notes(pk):
    return repo.notes_for_record(pk)


def add_note(pk, data):
    return repo.create_note(pk, data)


def share_record(pk, recipient):
    return repo.add_share(pk, recipient)


def upload_for_user(user, data):
    return repo.create_record(user, data)
