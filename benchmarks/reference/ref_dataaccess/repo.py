"""Reference data-access patterns for the W9 extractor.

Each module-level function is a fixture for a specific ORM idiom; the
expected output (operation, target_entity, has_ownership_predicate,
ownership_predicate_type) is documented in expected_dataaccess.yaml.

These functions are NEVER executed; the extractor parses them as text.
"""

from django.http import Http404
from django.shortcuts import get_object_or_404


# Pretend Django models. We only need the names visible at module scope.
class Invoice:
    objects = None  # type: ignore[assignment]


class User:
    objects = None  # type: ignore[assignment]


class Order:
    objects = None  # type: ignore[assignment]


# --- READ patterns -------------------------------------------------------


def da_filter_by_user(request):
    return Invoice.objects.filter(user=request.user)


def da_filter_by_owner(request):
    return Invoice.objects.filter(owner=request.user)


def da_filter_by_user_id(request):
    return Invoice.objects.filter(user_id=request.user.id)


def da_filter_no_owner(request, pk):
    return Invoice.objects.filter(pk=pk)


def da_get_by_pk(request, pk):
    return Invoice.objects.get(pk=pk)


def da_all(request):
    return User.objects.all()


def da_indirect_owner(request):
    # owner via ForeignKey traversal: account__user
    return Order.objects.filter(account__user=request.user)


# --- get_object_or_404 + ownership assertion ----------------------------


def da_g404_with_assert(request, pk):
    inv = get_object_or_404(Invoice, pk=pk)
    if inv.user != request.user:
        raise Http404
    return inv


def da_g404_no_assert(request, pk):
    return get_object_or_404(Invoice, pk=pk)


# --- WRITE / UPDATE / DELETE --------------------------------------------


def da_create(request):
    return Invoice.objects.create(amount=10, user=request.user)


def da_update(request, pk):
    Invoice.objects.filter(pk=pk).update(status="paid")


def da_delete(request, pk):
    Invoice.objects.filter(pk=pk).delete()
