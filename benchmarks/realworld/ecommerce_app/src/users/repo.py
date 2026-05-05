class User:
    objects = None  # type: ignore[assignment]


class Address:
    objects = None  # type: ignore[assignment]


def user_by_id(pk):
    return User.objects.get(pk=pk)


def update_user(pk, data):
    user = User.objects.get(pk=pk)
    return user


def addresses_for_user(pk):
    return Address.objects.filter(user_id=pk)


def all_users():
    return User.objects.all()
