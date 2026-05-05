from . import repo


def list_products():
    return repo.all_products()


def get_product(pk):
    return repo.product_by_pk(pk)


def create_product(data):
    return repo.insert_product(data)


def update_product(pk, data):
    return repo.update_product_by_pk(pk, data)


def delete_product(pk):
    return repo.delete_product_by_pk(pk)


def get_reviews_for_product(pk):
    return repo.reviews_for_product(pk)


def bulk_import(data):
    for item in data:
        repo.insert_product(item)
