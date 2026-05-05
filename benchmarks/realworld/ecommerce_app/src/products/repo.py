class Product:
    objects = None  # type: ignore[assignment]


class Review:
    objects = None  # type: ignore[assignment]


def all_products():
    return Product.objects.all()


def product_by_pk(pk):
    return Product.objects.get(pk=pk)


def insert_product(data):
    return Product.objects.create()


def update_product_by_pk(pk, data):
    product = Product.objects.get(pk=pk)
    return product


def delete_product_by_pk(pk):
    Product.objects.filter(pk=pk).delete()


def reviews_for_product(pk):
    return Review.objects.filter(product_id=pk)
