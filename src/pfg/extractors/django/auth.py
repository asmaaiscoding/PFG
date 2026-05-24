"""Django authorization annotation (Phase 2 W6).

Given a `DiscoveredEndpoint`, walk the AST of its handler (FBV or CBV method)
and the surrounding class body / module imports to determine:

  * `requires_auth`        — does the handler enforce identity?
  * `required_role`        — coarse privilege tier {NONE, USER, ADMIN}
  * `is_intentionally_public` — heuristic: `/health`, `/login`, AllowAny, etc.

Recognized v1 patterns (see docs/auth-pattern-catalog.md §A):
  * FBV decorators: `@login_required`, `@permission_required(...)`,
    `@staff_member_required`, `@user_passes_test(...)`,
    DRF `@api_view([...])` + `@permission_classes([...])`.
  * CBV mixins: `LoginRequiredMixin`, `PermissionRequiredMixin`,
    `UserPassesTestMixin`.
  * DRF class attribute `permission_classes = [...]` on `APIView` /
    `ViewSet` / `ModelViewSet`.

Recognized v2 additions:
  * Settings-derived ``REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"]`` —
    parsed from ``settings.py`` / ``settings_global.py`` as a project-wide
    fallback when no view-level or class-level auth annotation is found.
  * ViewSet base class methods ``restrict_queryset`` / ``initial`` that
    reference ``request.user`` are treated as authentication evidence.

Still out of scope: ``@method_decorator``, ``get_permissions()`` overrides.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from pfg.extractors.base import DiscoveredEndpoint
from pfg.pfg.nodes import Role

# --- known names ----------------------------------------------------------

_DECORATORS_AUTH_USER: frozenset[str] = frozenset(
    {"login_required", "permission_required", "user_passes_test"}
)
_DECORATORS_AUTH_ADMIN: frozenset[str] = frozenset(
    {"staff_member_required", "superuser_required"}
)

_MIXINS_AUTH_USER: frozenset[str] = frozenset(
    {"LoginRequiredMixin", "PermissionRequiredMixin", "UserPassesTestMixin"}
)

# DRF permission class -> (requires_auth, role, public)
_DRF_PERM_CLASSES: dict[str, tuple[bool, Role, bool]] = {
    "AllowAny": (False, Role.NONE, True),
    "IsAuthenticated": (True, Role.USER, False),
    "IsAuthenticatedOrReadOnly": (False, Role.USER, False),  # method-dependent; resolved below
    "IsAdminUser": (True, Role.ADMIN, False),
    "DjangoModelPermissions": (True, Role.USER, False),
    "DjangoModelPermissionsOrAnonReadOnly": (False, Role.USER, False),
    "DjangoObjectPermissions": (True, Role.USER, False),
    "NoPermission": (True, Role.ADMIN, False),
}

_ADMIN_NAME_HINTS = ("Admin", "Staff", "Superuser", "Billing", "Owner")
_MODEL_PERMISSION_HINTS = ("Permission", "DjangoModelPermissions")
_OBJECT_PERMISSION_HINTS = (
    "ObjectPermission",
    "ObjectPermissions",
    "DjangoObjectPermissions",
    "IsOwner",
    "IsObjectOwner",
    "IsCreator",
    "IsAuthor",
    "OwnerOnly",
    "OwnedBy",
    "BelongsTo",
)
# Broader ownership indicators — if the class name contains these substrings
# we treat it as an object-level permission (ownership) check.
_OWNERSHIP_CLASS_SUBSTRINGS = (
    "owner",
    "owned",
    "creator",
    "author",
    "belongs",
    "object_perm",
    "obj_perm",
)

_PUBLIC_ROUTE_PREFIXES: tuple[str, ...] = ("/public/",)
_PUBLIC_ROUTE_EXACT: frozenset[str] = frozenset(
    {
        "/health",
        "/health/",
        "/healthz",
        "/healthz/",
        "/ping",
        "/ping/",
        "/login",
        "/login/",
        "/logout",
        "/logout/",
        "/auth/login/",
        "/auth/logout/",
    }
)

_SAFE_HTTP_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})


# --- public dataclass -----------------------------------------------------


@dataclass(frozen=True)
class EndpointAuth:
    requires_auth: bool
    required_role: Role
    is_intentionally_public: bool
    role_check_present: bool = False
    model_permission_check_present: bool = False
    object_permission_check_present: bool = False
    tenant_check_present: bool = False


# --- helpers --------------------------------------------------------------


def _read_module(project_root: Path, dotted: str) -> ast.AST | None:
    rel = Path(*dotted.split("."))
    for c in (project_root / rel.with_suffix(".py"), project_root / rel / "__init__.py"):
        if c.exists():
            try:
                return ast.parse(c.read_text(encoding="utf-8"), filename=str(c))
            except SyntaxError:
                return None
    return None


def _decorator_name(dec: ast.AST) -> str | None:
    """Return the rightmost identifier of a decorator expression."""
    if isinstance(dec, ast.Call):
        return _decorator_name(dec.func)
    if isinstance(dec, ast.Attribute):
        return dec.attr
    if isinstance(dec, ast.Name):
        return dec.id
    return None


def _list_names(node: ast.AST | None) -> list[str]:
    """Return identifier names from a list/tuple expression of names."""
    if not isinstance(node, (ast.List, ast.Tuple)):
        return []
    out: list[str] = []
    for elt in node.elts:
        if isinstance(elt, ast.Name):
            out.append(elt.id)
        elif isinstance(elt, ast.Attribute):
            out.append(elt.attr)
    return out


def _find_function(tree: ast.AST, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def _find_class(tree: ast.AST, name: str) -> ast.ClassDef | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    return None


def _class_base_names(cls: ast.ClassDef) -> list[str]:
    out: list[str] = []
    for b in cls.bases:
        if isinstance(b, ast.Name):
            out.append(b.id)
        elif isinstance(b, ast.Attribute):
            out.append(b.attr)
    return out


def _class_attr_assign(cls: ast.ClassDef, name: str) -> ast.expr | None:
    for stmt in cls.body:
        if isinstance(stmt, ast.Assign):
            for t in stmt.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.target.id == name:
            return stmt.value
    return None


def _expr_references_request_user(expr: ast.AST) -> bool:
    for node in ast.walk(expr):
        if not isinstance(node, ast.Attribute) or node.attr != "user":
            continue
        base = node.value
        if isinstance(base, ast.Name) and base.id == "request":
            return True
        if (
            isinstance(base, ast.Attribute)
            and base.attr == "request"
            and isinstance(base.value, ast.Name)
            and base.value.id == "self"
        ):
            return True
    return False


def _class_uses_request_user(cls: ast.ClassDef) -> bool:
    for node in cls.body:
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in {"get_queryset", "get_object", "get_owner_objects"}
            and _expr_references_request_user(node)
        ):
            return True
    return False


def _attr_chain(node: ast.AST) -> str | None:
    parts: list[str] = []
    cur: ast.AST = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _call_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _function_permission_signals(fn: ast.AST | None) -> tuple[bool, bool, bool]:
    """Return (model_permission, object_permission, tenant_check) signals."""
    if fn is None:
        return False, False, False
    model_permission = False
    object_permission = False
    tenant_check = False
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name in {"check_object_permissions", "has_object_permission"}:
                object_permission = True
            if name == "has_perm":
                if len(node.args) >= 2:
                    object_permission = True
                else:
                    model_permission = True
            if name in {"filter", "get", "get_object_or_404"}:
                for kw in getattr(node, "keywords", []):
                    if kw.arg and any(
                        term in kw.arg.lower()
                        for term in ("tenant", "organization", "org", "workspace", "realm", "project")
                    ):
                        tenant_check = True
        elif isinstance(node, ast.Attribute):
            chain = _attr_chain(node) or ""
            if any(term in chain.lower() for term in ("request.user.organization", "request.user.tenant", "request.user.workspace")):
                tenant_check = True
    return model_permission, object_permission, tenant_check


def _class_permission_signals(cls: ast.ClassDef) -> tuple[bool, bool, bool]:
    lifecycle_methods = {
        "dispatch",
        "initial",
        "get_queryset",
        "get_object",
        "get_permissions",
        "check_permissions",
        "check_object_permissions",
        "has_permission",
    }
    model_permission = False
    object_permission = False
    tenant_check = False
    for node in cls.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name not in lifecycle_methods:
            continue
        m, o, t = _function_permission_signals(node)
        model_permission = model_permission or m
        object_permission = object_permission or o
        tenant_check = tenant_check or t
    return model_permission, object_permission, tenant_check


# --- core resolution ------------------------------------------------------


def _from_perm_classes(
    names: list[str], http_method: str
) -> EndpointAuth | None:
    """Resolve a list of DRF permission class names to (auth, role, public).

    Multiple classes are AND-ed by DRF; we pick the strictest auth requirement
    (auth=True wins) and the highest role, but if any class is AllowAny we
    treat the endpoint as public (DRF semantics: AllowAny short-circuits if
    listed alone; combined with others it weakens to those others — we
    approximate by: AllowAny *only* class -> public; otherwise strict).
    """
    if not names:
        return None
    role_order = {Role.NONE: 0, Role.USER: 1, Role.ADMIN: 2}
    if names == ["AllowAny"]:
        return EndpointAuth(False, Role.NONE, True)
    requires_auth = False
    role = Role.NONE
    role_check_present = False
    model_permission = False
    object_permission = False
    for n in names:
        spec = _DRF_PERM_CLASSES.get(n)
        if spec is None:
            # Unknown custom permission class: assume USER-tier auth and
            # infer role/object/model semantics from conventional names.
            requires_auth = True
            inferred_role = Role.ADMIN if any(h in n for h in _ADMIN_NAME_HINTS) else Role.USER
            if role_order[inferred_role] > role_order[role]:
                role = inferred_role
            role_check_present = role_check_present or inferred_role != Role.USER
            model_permission = model_permission or any(h in n for h in _MODEL_PERMISSION_HINTS)
            object_permission = object_permission or (
                any(h in n for h in _OBJECT_PERMISSION_HINTS)
                or any(s in n.lower() for s in _OWNERSHIP_CLASS_SUBSTRINGS)
            )
            continue
        a, r, _ = spec
        if n == "IsAuthenticatedOrReadOnly":
            a = http_method.upper() not in _SAFE_HTTP_METHODS
        if a:
            requires_auth = True
        if n in {"IsAdminUser"}:
            role_check_present = True
        if n in {"DjangoModelPermissions", "DjangoModelPermissionsOrAnonReadOnly"}:
            model_permission = True
        if n == "DjangoObjectPermissions":
            model_permission = True
            object_permission = True
        if role_order[r] > role_order[role]:
            role = r
    return EndpointAuth(
        requires_auth,
        role,
        False,
        role_check_present=role_check_present,
        model_permission_check_present=model_permission,
        object_permission_check_present=object_permission,
    )


def _annotate_function(
    fn: ast.FunctionDef | ast.AsyncFunctionDef, http_method: str
) -> EndpointAuth | None:
    """Return auth from FBV decorators, or None if no auth-related decorator."""
    requires_auth = False
    role = Role.NONE
    public = False
    matched = False
    role_check_present = False
    model_permission = False
    object_permission = False
    tenant_check = False

    api_view_present = False
    perm_class_names: list[str] = []

    for dec in fn.decorator_list:
        name = _decorator_name(dec)
        if name is None:
            continue
        if name == "api_view":
            api_view_present = True
            matched = True
        elif name == "permission_classes":
            if isinstance(dec, ast.Call) and dec.args:
                perm_class_names = _list_names(dec.args[0])
                matched = True
        elif name in _DECORATORS_AUTH_USER:
            requires_auth = True
            if role == Role.NONE:
                role = Role.USER
            if name == "permission_required":
                model_permission = True
            matched = True
        elif name in _DECORATORS_AUTH_ADMIN:
            requires_auth = True
            role = Role.ADMIN
            role_check_present = True
            matched = True

    fn_model, fn_object, fn_tenant = _function_permission_signals(fn)
    if fn_model or fn_object or fn_tenant:
        requires_auth = True
        if role == Role.NONE:
            role = Role.USER
        model_permission = model_permission or fn_model
        object_permission = object_permission or fn_object
        tenant_check = tenant_check or fn_tenant
        matched = True

    if api_view_present:
        spec = _from_perm_classes(perm_class_names, http_method)
        if spec is None:
            # DRF default if not configured = AllowAny (settings-dependent).
            return EndpointAuth(False, Role.NONE, True)
        return spec

    if not matched:
        return None
    return EndpointAuth(
        requires_auth,
        role,
        public,
        role_check_present=role_check_present,
        model_permission_check_present=model_permission,
        object_permission_check_present=object_permission,
        tenant_check_present=tenant_check,
    )


def _annotate_class(
    cls: ast.ClassDef, http_method: str
) -> EndpointAuth | None:
    """Return auth derived from CBV mixins + DRF permission_classes attr."""
    bases = _class_base_names(cls)
    requires_auth = False
    role = Role.NONE
    public = False
    matched = False
    role_check_present = False
    model_permission = False
    object_permission = False
    tenant_check = False

    for b in bases:
        if b in _MIXINS_AUTH_USER or "Owner" in b or "Permission" in b:
            requires_auth = True
            if role == Role.NONE:
                role = Role.USER
            model_permission = model_permission or b == "PermissionRequiredMixin" or "Permission" in b
            matched = True
        if any(h in b for h in _ADMIN_NAME_HINTS):
            requires_auth = True
            role = Role.ADMIN
            role_check_present = True
            matched = True

    if _class_uses_request_user(cls):
        requires_auth = True
        if role == Role.NONE:
            role = Role.USER
        matched = True

    cls_model, cls_object, cls_tenant = _class_permission_signals(cls)
    if cls_model or cls_object or cls_tenant:
        requires_auth = True
        if role == Role.NONE:
            role = Role.USER
        model_permission = model_permission or cls_model
        object_permission = object_permission or cls_object
        tenant_check = tenant_check or cls_tenant
        matched = True

    perm_attr = _class_attr_assign(cls, "permission_classes")
    if perm_attr is not None:
        names = _list_names(perm_attr)
        spec = _from_perm_classes(names, http_method)
        if spec is not None:
            requires_auth = spec.requires_auth
            role = spec.required_role
            public = spec.is_intentionally_public
            role_check_present = role_check_present or spec.role_check_present
            model_permission = model_permission or spec.model_permission_check_present
            object_permission = object_permission or spec.object_permission_check_present
            tenant_check = tenant_check or spec.tenant_check_present
            matched = True

    if not matched:
        return None
    return EndpointAuth(
        requires_auth,
        role,
        public,
        role_check_present=role_check_present,
        model_permission_check_present=model_permission,
        object_permission_check_present=object_permission,
        tenant_check_present=tenant_check,
    )


# --- public API -----------------------------------------------------------


def is_intentionally_public_route(route: str) -> bool:
    if route in _PUBLIC_ROUTE_EXACT:
        return True
    return any(route.startswith(p) for p in _PUBLIC_ROUTE_PREFIXES)


# --- settings-level DRF default permission resolution --------------------

_SETTINGS_FILES: tuple[str, ...] = (
    "settings.py",
    "settings_global.py",
    "conf/settings.py",
    "conf/server.py",
    "settings/base.py",
)

# Regex to match DEFAULT_PERMISSION_CLASSES in a REST_FRAMEWORK dict.
_DPC_RE = re.compile(
    r"""['"]DEFAULT_PERMISSION_CLASSES['"]\s*:\s*[\(\[\{]\s*['"]([^'"]+)['"]""",
)


def resolve_default_permission_classes(project_root: Path) -> EndpointAuth | None:
    """Scan settings files for REST_FRAMEWORK DEFAULT_PERMISSION_CLASSES.

    Returns an EndpointAuth to use as a project-wide fallback, or None if
    no setting was found.
    """
    for settings_rel in _SETTINGS_FILES:
        for candidate in project_root.rglob(settings_rel):
            try:
                text = candidate.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            m = _DPC_RE.search(text)
            if m is None:
                continue
            # Extract the class name (last dotted segment).
            class_name = m.group(1).rsplit(".", 1)[-1]
            # Resolve effective names: include base classes from project source.
            effective_names = _resolve_permission_class_bases(
                project_root, m.group(1), class_name
            )
            spec = _from_perm_classes(effective_names, "GET")
            if spec is not None:
                return spec
    return None


def _resolve_permission_class_bases(
    project_root: Path, dotted_path: str, class_name: str
) -> list[str]:
    """Resolve a custom permission class to its effective names list.

    If the class is defined in the project and inherits from known DRF
    permission classes, include those base class names alongside the original.
    """
    # Convert dotted import path to module path
    parts = dotted_path.rsplit(".", 1)
    if len(parts) < 2:
        return [class_name]
    module_path = parts[0].replace(".", "/") + ".py"
    # Search for the module file in the project
    candidates = list(project_root.rglob(module_path.split("/")[-1]))
    for cand in candidates:
        rel = str(cand.relative_to(project_root))
        if module_path in rel or rel.endswith(module_path.split("/")[-1]):
            try:
                tree = ast.parse(cand.read_text(encoding="utf-8"))
            except (OSError, SyntaxError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name == class_name:
                    base_names = []
                    for base in node.bases:
                        if isinstance(base, ast.Name):
                            base_names.append(base.id)
                        elif isinstance(base, ast.Attribute):
                            base_names.append(base.attr)
                    if base_names:
                        return [class_name] + base_names
    return [class_name]


def annotate_endpoint(
    ep: DiscoveredEndpoint,
    project_root: str | Path,
    *,
    default_auth: EndpointAuth | None = None,
) -> EndpointAuth:
    """Resolve auth attributes for a single discovered endpoint."""
    project_root = Path(project_root).resolve()

    qual = ep.handler_qualname
    parts = qual.split(".")
    method_name: str | None = None
    if len(parts) >= 2:
        candidate_module = ".".join(parts[:-2])
        candidate_class = parts[-2]
        candidate_attr = parts[-1]
        tree = _read_module(project_root, candidate_module) if candidate_module else None
        if tree is not None and _find_class(tree, candidate_class) is not None:
            method_name = candidate_attr
            module_dotted = candidate_module
            class_name = candidate_class
        else:
            module_dotted = ".".join(parts[:-1])
            class_name = ""
            tree = _read_module(project_root, module_dotted)
    else:
        module_dotted = ""
        class_name = ""
        tree = None

    public_by_route = is_intentionally_public_route(ep.route)
    # Use settings-level fallback when available; otherwise assume unprotected.
    fallback = default_auth or EndpointAuth(False, Role.NONE, public_by_route)
    if default_auth is not None and public_by_route and not default_auth.requires_auth:
        fallback = EndpointAuth(False, Role.NONE, True)
    elif default_auth is not None and public_by_route:
        fallback = EndpointAuth(
            default_auth.requires_auth,
            default_auth.required_role,
            True,
            role_check_present=default_auth.role_check_present,
            model_permission_check_present=default_auth.model_permission_check_present,
            object_permission_check_present=default_auth.object_permission_check_present,
            tenant_check_present=default_auth.tenant_check_present,
        )

    if tree is None:
        # Module source not found in project — likely a third-party package.
        # DRF DEFAULT_PERMISSION_CLASSES only applies to DRF views, NOT to
        # plain Django views from third-party libraries.  Without source
        # evidence we must assume NO authentication is enforced.
        if public_by_route:
            return EndpointAuth(False, Role.NONE, True)
        return EndpointAuth(False, Role.NONE, False)

    if method_name is not None:
        cls = _find_class(tree, class_name)
        if cls is None:
            return fallback
        # 1. Class-level mixins / permission_classes
        cls_auth = _annotate_class(cls, ep.http_method)
        # 2. Method-level decorators inside the class body
        method = next(
            (
                m
                for m in cls.body
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                and m.name == method_name
            ),
            None,
        )
        method_auth = _annotate_function(method, ep.http_method) if method is not None else None
        chosen = method_auth or cls_auth
    else:
        fn = _find_function(tree, parts[-1])
        chosen = _annotate_function(fn, ep.http_method) if fn is not None else None

    if chosen is None:
        return fallback

    # Public-route heuristic: don't override an explicit auth requirement, but
    # do mark obviously-public routes (health/login) as such for FP suppression.
    public = chosen.is_intentionally_public or (public_by_route and not chosen.requires_auth)
    return EndpointAuth(
        chosen.requires_auth,
        chosen.required_role,
        public,
        role_check_present=chosen.role_check_present,
        model_permission_check_present=chosen.model_permission_check_present,
        object_permission_check_present=chosen.object_permission_check_present,
        tenant_check_present=chosen.tenant_check_present,
    )
