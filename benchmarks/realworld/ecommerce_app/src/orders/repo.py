class Order:
    objects = None  # type: ignore[assignment]


def get_order_by_pk(pk):
    return Order.objects.get(pk=pk)


def update_order_by_pk(pk, data):
    order = Order.objects.get(pk=pk)
    return order


def delete_order_by_pk(pk):
    Order.objects.filter(pk=pk).delete()


def orders_for_user(user):
    return Order.objects.filter(user=user)


def insert_order(user, data):
    return Order.objects.create(user=user)


def update_order_status(pk, status):
    order = Order.objects.get(pk=pk)
    return order


def delete_all_orders():
    Order.objects.all().delete()
