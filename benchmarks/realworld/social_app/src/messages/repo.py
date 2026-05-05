class Message:
    objects = None  # type: ignore[assignment]


def messages_for_user(user):
    return Message.objects.filter(recipient=user)


def message_by_pk(pk):
    return Message.objects.get(pk=pk)


def create_message(user, data):
    return Message.objects.create(sender=user)


def delete_message_by_pk(pk):
    Message.objects.filter(pk=pk).delete()
