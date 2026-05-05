from . import repo


def get_inbox(user):
    return repo.messages_for_user(user)


def get_message(pk):
    return repo.message_by_pk(pk)


def send(user, data):
    return repo.create_message(user, data)


def delete_message(pk):
    return repo.delete_message_by_pk(pk)
