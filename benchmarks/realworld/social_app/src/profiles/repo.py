class Profile:
    objects = None  # type: ignore[assignment]


class Follow:
    objects = None  # type: ignore[assignment]


class Block:
    objects = None  # type: ignore[assignment]


class Settings:
    objects = None  # type: ignore[assignment]


def profile_by_user(user):
    return Profile.objects.get(user=user)


def update_profile_by_user(user, data):
    profile = Profile.objects.get(user=user)
    return profile


def public_profile_by_pk(pk):
    return Profile.objects.get(user_id=pk)


def add_follow(user, target_pk):
    return Follow.objects.create(follower=user, target_id=target_pk)


def add_block(user, target_pk):
    return Block.objects.create(blocker=user, target_id=target_pk)


def settings_by_user_pk(pk):
    return Settings.objects.get(user_id=pk)
