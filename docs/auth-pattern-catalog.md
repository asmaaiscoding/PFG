# Django authorization pattern catalog (v0.1)

This document is the **specification** for the Django PFG extractor. Every pattern
listed here MUST be recognized; patterns NOT listed here are explicit non-goals
for v1 and become future work.

Phase 2 sub-tasks reference the section IDs (E.x = Endpoint, A.x = Auth, ...).

## E. Endpoint discovery

### E.1 — `urls.py` URL patterns
- `path(route, view, name=...)` from `django.urls`.
- `re_path(regex, view, name=...)`.
- `include("app.urls")` and `include((patterns, app_namespace), namespace=...)`
  → recurse into the included module.
- Route parameters captured by `<converter:name>` (e.g. `<int:id>`, `<slug:user>`)
  and by named regex groups in `re_path`.

### E.2 — Function-based views (FBV)
- Module-level `def view(request, ...)` referenced from `urls.py`.

### E.3 — Class-based views (CBV)
- `View.as_view()` reference in `urls.py`. Resolve the class; expose its
  `get`/`post`/`put`/`patch`/`delete` methods as separate endpoints (one per
  HTTP method present).
- Generic CBVs (`ListView`, `DetailView`, `CreateView`, `UpdateView`,
  `DeleteView`) — recognize the implicit method mapping.

### E.4 — Django REST Framework (DRF)
- `@api_view(["GET", "POST"])` on a function view.
- `APIView` subclasses and their `get`/`post`/... methods.
- `ViewSet` / `ModelViewSet` registered via `DefaultRouter` / `SimpleRouter`
  (`router.register(prefix, ViewSet)`). Action methods: `list`, `create`,
  `retrieve`, `update`, `partial_update`, `destroy`, plus `@action`-decorated
  custom actions.

## A. Authorization annotation

### A.1 — Decorators (FBV)
- `@login_required` (and `@login_required(login_url=...)`).
- `@permission_required("app.codename")`.
- `@user_passes_test(predicate)` — recorded as a generic `ROLE_CHECK` with the
  predicate name.
- `@staff_member_required`, `@superuser_required` (admin app helpers).

### A.2 — Mixins (CBV)
- `LoginRequiredMixin` → `requires_auth = True`.
- `PermissionRequiredMixin` + `permission_required = "app.codename"`.
- `UserPassesTestMixin`.

### A.3 — DRF permissions
- Class attribute `permission_classes = [...]` or `@permission_classes([...])`
  decorator on a function view.
- Recognized classes:
  - `AllowAny` → `requires_auth = False`, intentionally public hint.
  - `IsAuthenticated` → `requires_auth = True`, role `USER`.
  - `IsAdminUser` → `requires_auth = True`, role `ADMIN`.
  - `IsAuthenticatedOrReadOnly` → method-dependent: GET/HEAD/OPTIONS public,
    others USER.
  - `DjangoModelPermissions` / `DjangoModelPermissionsOrAnonReadOnly` → USER.
  - `DjangoObjectPermissions` → USER **plus** counts as ownership-check signal.
- Custom permission classes: detect by name; if class defines `has_object_permission`
  with a body that compares to `request.user`, treat as `OWNERSHIP_CHECK`.

### A.4 — Project-level middleware
- `MIDDLEWARE` setting includes `AuthenticationMiddleware` →
  `request.user` is available globally; this is the default and is implicitly
  assumed.
- Custom auth middleware classes whose name matches `*Auth*` /
  `*Permission*` / `*Token*` are emitted as a top-level `middleware` node and
  edged to every endpoint.

## O. Ownership / IDOR signals

### O.1 — ORM filter ownership predicates
- `Model.objects.filter(user=request.user, ...)`.
- `Model.objects.filter(owner=request.user, ...)`, with field names in
  {`user`, `owner`, `created_by`, `author`, `account__user`}. Dotted paths
  through ForeignKey are tracked with `__` separator.
- `.filter(user_id=request.user.id)` and `.filter(user_id=request.user.pk)`.
- `Q(user=request.user) | Q(...)` — recognized as ownership predicate if any
  branch is a direct user comparison.

### O.2 — Object-fetch + assertion
- `obj = get_object_or_404(Model, pk=id)` followed in the same function by
  `if obj.user != request.user: raise PermissionDenied` (or `Http404`,
  `HttpResponseForbidden`).
- `Model.objects.get(...)` followed by similar assertion.

### O.3 — Manager methods that inject the user
- `Model.objects.for_user(request.user)` and similar — heuristic: any manager
  method invocation taking `request.user` as a positional/keyword argument
  counts as ownership predicate.

## D. Data access

ORM call sites we emit as `data_access` nodes:

| Op       | Methods                                                            |
|----------|--------------------------------------------------------------------|
| READ     | `.filter`, `.get`, `.first`, `.last`, `.all`, `.exclude`, `.values`, `.values_list`, `.aggregate`, `.count`, `.exists`, `.raw` |
| WRITE    | `.create`, `.bulk_create`, `.get_or_create` (when path is "create") |
| UPDATE   | `.update`, `.update_or_create`, `Model.save()`                     |
| DELETE   | `.delete`, `.bulk_delete`                                          |

Target entity inferred from the model class on the LHS of the call chain
(`Invoice.objects.filter(...)` → `Invoice`).

## I. Identifier flow

Intra-procedural def-use:

1. Route param `id` from URL pattern enters the handler signature
   (`def view(request, id):`) or is unpacked from `kwargs`.
2. Track simple assignments `x = id`, `x = int(id)`, `x = str(id)`.
3. Track passing through function calls into helper/service functions
   (record param-name mapping at call sites; depth cap = 8).
4. Match at ORM call sites: kwarg value or `pk=`/`id=` argument.

Out of scope for v1 (future work): aliasing through containers
(`d["k"] = id`), control-flow-sensitive flow, inter-class field flow.

## Non-goals (v1)

- Django admin auto-generated views.
- Async views (treated identically to sync).
- Dynamic URL patterns generated at runtime.
- `signals` and `pre_save`/`post_save` hooks as authorization checks.
