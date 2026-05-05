from . import repo


def get_profile(user):
    return repo.user_by_id(user.id)


def update_profile(user, data):
    return repo.update_user(user.id, data)


def get_user_detail(pk):
    return repo.user_by_id(pk)


def get_user_addresses(pk):
    return repo.addresses_for_user(pk)


def list_all_users():
    return repo.all_users()
