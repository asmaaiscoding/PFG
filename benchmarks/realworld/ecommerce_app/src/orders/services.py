from . import repo


def get_order(pk):
    return repo.get_order_by_pk(pk)


def update_order(pk, data):
    return repo.update_order_by_pk(pk, data)


def delete_order(pk):
    return repo.delete_order_by_pk(pk)


def list_user_orders(user):
    return repo.orders_for_user(user)


def create_order(user, data):
    return repo.insert_order(user, data)


def cancel_order(pk):
    return repo.update_order_status(pk, "cancelled")


def refund_order_for_user(pk, user):
    order = repo.get_order_by_pk(pk)
    if order.user != user:
        raise PermissionError("Not your order")
    return repo.update_order_status(pk, "refunded")


def bulk_delete_all_orders():
    return repo.delete_all_orders()
