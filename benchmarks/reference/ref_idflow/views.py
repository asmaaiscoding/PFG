"""Reference fixtures for identifier-flow tracking (W10).

Each function takes one or more parameters that are treated as
externally-controlled sources (e.g. URL path params). The extractor must
discover which call expressions in the body receive a value transitively
derived from those sources, and through which kwarg.

Functions are NEVER executed; we parse them as text.
"""


def repo_invoice_by_pk(pk):
    pass


def service_get_invoice(pk):
    pass


# 1. direct: pk flows directly into Invoice.objects.get(pk=pk).
def flow_direct(request, pk):
    return Invoice.objects.get(pk=pk)


# 2. local rename: pk -> ident -> get.
def flow_via_local(request, pk):
    ident = pk
    return Invoice.objects.get(pk=ident)


# 3. attribute on tainted: pk.value still tainted.
def flow_via_attr(request, pk):
    return Invoice.objects.get(pk=pk.value)


# 4. binop: pk + 1 still tainted.
def flow_via_binop(request, pk):
    return Invoice.objects.get(pk=pk + 1)


# 5. call chain: pk -> service(pk) -> repo(pk) (each receives pk in arg 0).
def flow_through_calls(request, pk):
    return service_get_invoice(pk)


# 6. positional only: get(pk).
def flow_positional(request, pk):
    return Invoice.objects.get(pk)


# 7. unrelated: pk never reaches the call.
def flow_unrelated(request, pk):
    return Invoice.objects.all()


# 8. assignment from call result then re-used.
def flow_via_call_result(request, pk):
    cleaned = clean(pk)
    return Invoice.objects.filter(pk=cleaned)


# 9. multiple sources merge.
def flow_two_sources(request, pk, slug):
    return Invoice.objects.filter(pk=pk, slug=slug)


# 10. tuple unpacking propagates taint to all targets (conservative).
def flow_tuple_unpack(request, pk):
    a, b = (pk, 0)
    return Invoice.objects.filter(pk=a)


class Invoice:
    objects = None  # type: ignore[assignment]


def clean(x):
    return x
