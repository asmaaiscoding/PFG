from . import repo


def get_profile(user):
    return repo.profile_by_user(user)


def update_profile(user, data):
    return repo.update_profile_by_user(user, data)


def get_public_profile(pk):
    return repo.public_profile_by_pk(pk)


def follow(user, target_pk):
    return repo.add_follow(user, target_pk)


def block(user, target_pk):
    return repo.add_block(user, target_pk)


def get_settings(pk):
    return repo.settings_by_user_pk(pk)
