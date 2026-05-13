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

Out of scope for v1: settings-derived `DEFAULT_PERMISSION_CLASSES`, custom
permission classes (always treated as USER unless they look like ownership
checks — handled by ownership extractor in W9), `@method_decorator`,
`get_permissions()` overrides.
"""

from __future__ import annotations

import ast
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
}

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


# --- core resolution ------------------------------------------------------


def _from_perm_classes(
    names: list[str], http_method: str
) -> tuple[bool, Role, bool] | None:
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
        return False, Role.NONE, True
    requires_auth = False
    role = Role.NONE
    for n in names:
        spec = _DRF_PERM_CLASSES.get(n)
        if spec is None:
            # Unknown custom permission class: assume USER-tier auth.
            requires_auth = True
            if role_order[role] < role_order[Role.USER]:
                role = Role.USER
            continue
        a, r, _ = spec
        if n == "IsAuthenticatedOrReadOnly":
            a = http_method.upper() not in _SAFE_HTTP_METHODS
        if a:
            requires_auth = True
        if role_order[r] > role_order[role]:
            role = r
    return requires_auth, role, False


def _annotate_function(
    fn: ast.FunctionDef | ast.AsyncFunctionDef, http_method: str
) -> EndpointAuth | None:
    """Return auth from FBV decorators, or None if no auth-related decorator."""
    requires_auth = False
    role = Role.NONE
    public = False
    matched = False

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
            matched = True
        elif name in _DECORATORS_AUTH_ADMIN:
            requires_auth = True
            role = Role.ADMIN
            matched = True

    if api_view_present:
        spec = _from_perm_classes(perm_class_names, http_method)
        if spec is None:
            # DRF default if not configured = AllowAny (settings-dependent).
            return EndpointAuth(False, Role.NONE, True)
        a, r, p = spec
        return EndpointAuth(a, r, p)

    if not matched:
        return None
    return EndpointAuth(requires_auth, role, public)


def _annotate_class(
    cls: ast.ClassDef, http_method: str
) -> EndpointAuth | None:
    """Return auth derived from CBV mixins + DRF permission_classes attr."""
    bases = _class_base_names(cls)
    requires_auth = False
    role = Role.NONE
    public = False
    matched = False

    for b in bases:
        if b in _MIXINS_AUTH_USER or "Owner" in b or "Permission" in b:
            requires_auth = True
            if role == Role.NONE:
                role = Role.USER
            matched = True

    if _class_uses_request_user(cls):
        requires_auth = True
        if role == Role.NONE:
            role = Role.USER
        matched = True

    perm_attr = _class_attr_assign(cls, "permission_classes")
    if perm_attr is not None:
        names = _list_names(perm_attr)
        spec = _from_perm_classes(names, http_method)
        if spec is not None:
            a, r, p = spec
            requires_auth = a
            role = r
            public = p
            matched = True

    if not matched:
        return None
    return EndpointAuth(requires_auth, role, public)


# --- public API -----------------------------------------------------------


def is_intentionally_public_route(route: str) -> bool:
    if route in _PUBLIC_ROUTE_EXACT:
        return True
    return any(route.startswith(p) for p in _PUBLIC_ROUTE_PREFIXES)


def annotate_endpoint(ep: DiscoveredEndpoint, project_root: str | Path) -> EndpointAuth:
    """Resolve auth attributes for a single discovered endpoint."""
    project_root = Path(project_root).resolve()

    qual = ep.handler_qualname
    parts = qual.split(".")
    method_name: str | None = None
    if len(parts) >= 2:
        # Determine if this is a CBV method or an FBV by reading the module.
        # Convention: handler_qualname for CBV ends with `.<http_method>` or
        # `.<viewset_action>`; the segment before it is the class name.
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
    fallback = EndpointAuth(False, Role.NONE, public_by_route)

    if tree is None:
        return fallback

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
    return EndpointAuth(chosen.requires_auth, chosen.required_role, public)
