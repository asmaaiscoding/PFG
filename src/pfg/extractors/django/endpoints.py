"""Django endpoint discovery (Phase 2 W5).

Pure-AST analysis of a Django project source tree:
  1. find all `urls.py` files,
  2. parse `urlpatterns` (path/re_path/include + DRF router.register),
  3. resolve view expressions to handler qualnames,
  4. emit one DiscoveredEndpoint per (method, route).

No Django runtime is required.

Recognized v1 patterns:
  * `path("p/", view)`, `re_path(r"^...$", view)`, `include("app.urls")`,
    `include("app.urls", namespace=...)`,
    `include((patterns_var, "app"), namespace=...)` is NOT supported (future).
  * Function-based views referenced as `views.func` or `func`.
  * Class-based views via `Cls.as_view()`. HTTP methods inferred from defined
    methods (`get`, `post`, `put`, `patch`, `delete`).
  * DRF `DefaultRouter`/`SimpleRouter` with `.register(prefix, ViewSetCls)`.
    ViewSet/ModelViewSet → standard set: list/retrieve/create/update/
    partial_update/destroy.

Out-of-scope for v1: Django Admin auto-routes, generic-CBV implicit method
mapping (ListView, DetailView, etc.), dynamic urlpatterns generation,
`include` of a tuple with app_namespace.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from pfg.extractors.base import DiscoveredEndpoint

# --- constants ------------------------------------------------------------

_HTTP_METHODS: tuple[str, ...] = ("get", "post", "put", "patch", "delete")

# DRF action -> (HTTP method, suffix appended to router prefix)
_VIEWSET_ACTIONS: tuple[tuple[str, str, str], ...] = (
    ("list", "GET", ""),
    ("create", "POST", ""),
    ("retrieve", "GET", "{pk}/"),
    ("update", "PUT", "{pk}/"),
    ("partial_update", "PATCH", "{pk}/"),
    ("destroy", "DELETE", "{pk}/"),
)

_PATH_CONVERTER_RE = re.compile(r"<(?:[a-zA-Z_][a-zA-Z0-9_]*:)?([a-zA-Z_][a-zA-Z0-9_]*)>")
_RE_NAMED_GROUP_RE = re.compile(r"\(\?P<([a-zA-Z_][a-zA-Z0-9_]*)>[^)]*\)")
_RE_STRIP = re.compile(r"^\^|\$$")


# --- helpers --------------------------------------------------------------


def _const_str(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _attr_chain(node: ast.AST) -> list[str] | None:
    """`a.b.c` -> ['a','b','c']; returns None if not a pure attribute chain."""
    parts: list[str] = []
    cur: ast.AST = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return list(reversed(parts))
    return None


def _normalize_path_route(route: str) -> tuple[str, list[str]]:
    """Convert a `path()` route template to {name} placeholders + param list."""
    params: list[str] = []

    def _replace(m: re.Match[str]) -> str:
        params.append(m.group(1))
        return "{" + m.group(1) + "}"

    normalized = _PATH_CONVERTER_RE.sub(_replace, route)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized, params


def _normalize_re_route(pattern: str) -> tuple[str, list[str]]:
    """Convert a `re_path()` regex to {name} placeholders + param list (best-effort)."""
    pattern = _RE_STRIP.sub("", pattern)
    params: list[str] = []

    def _replace(m: re.Match[str]) -> str:
        params.append(m.group(1))
        return "{" + m.group(1) + "}"

    normalized = _RE_NAMED_GROUP_RE.sub(_replace, pattern)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized, params


def _join_routes(prefix: str, route: str) -> str:
    if not prefix:
        return route if route.startswith("/") else "/" + route
    if not prefix.startswith("/"):
        prefix = "/" + prefix
    if route.startswith("/"):
        route = route[1:]
    if prefix.endswith("/") and route.startswith("/"):
        return prefix + route[1:]
    if not prefix.endswith("/") and route and not route.startswith("/"):
        return prefix + "/" + route
    return prefix + route


# --- module index ---------------------------------------------------------


@dataclass
class _ModuleIndex:
    """What the parser knows about a parsed `urls.py` module."""

    path: Path
    package: str  # dotted name relative to project root, e.g. "blog"
    tree: ast.AST
    # alias -> source dotted path. Examples:
    #   {"views": "blog.views"}   from `from . import views`
    #   {"path": "django.urls.path"}  from `from django.urls import path`
    #   {"UserViewSet": "blog.views.UserViewSet"}  from `from .views import UserViewSet`
    aliases: dict[str, str]


def _module_dotted(project_root: Path, file_path: Path) -> str:
    """`blog/urls.py` under root → `blog.urls`."""
    rel = file_path.resolve().relative_to(project_root.resolve())
    parts = list(rel.with_suffix("").parts)
    return ".".join(parts)


def _resolve_relative_import(current_pkg: str, module: str | None, level: int) -> str:
    """Resolve a `from .X import Y` import to its absolute dotted path."""
    if level == 0:
        return module or ""
    base_parts = current_pkg.split(".")
    # drop `level` trailing components (level=1 -> drop the module file itself)
    base = base_parts[:-level] if level <= len(base_parts) else []
    if module:
        base = base + module.split(".")
    return ".".join(base)


def _build_alias_map(tree: ast.AST, current_pkg: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for stmt in ast.walk(tree):
        if isinstance(stmt, ast.ImportFrom):
            src = _resolve_relative_import(current_pkg, stmt.module, stmt.level)
            for alias in stmt.names:
                local = alias.asname or alias.name
                if alias.name == "*":
                    continue
                aliases[local] = f"{src}.{alias.name}" if src else alias.name
        elif isinstance(stmt, ast.Import):
            for alias in stmt.names:
                local = alias.asname or alias.name.split(".")[0]
                aliases[local] = (alias.asname and alias.name) or alias.name
    return aliases


# --- views-module class probing ------------------------------------------


def _read_module(project_root: Path, dotted: str) -> ast.AST | None:
    """Find the file for a dotted path and parse it. Returns None if missing."""
    rel = Path(*dotted.split("."))
    candidates = [project_root / rel.with_suffix(".py"), project_root / rel / "__init__.py"]
    for c in candidates:
        if c.exists():
            try:
                return ast.parse(c.read_text(encoding="utf-8"), filename=str(c))
            except SyntaxError:
                return None
    return None


def _find_class(tree: ast.AST, name: str) -> ast.ClassDef | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    return None


def _class_bases(cls: ast.ClassDef) -> list[str]:
    out: list[str] = []
    for b in cls.bases:
        chain = _attr_chain(b)
        if chain:
            out.append(".".join(chain))
    return out


def _is_drf_viewset(class_qualname: str, project_root: Path) -> bool:
    """Heuristic: class name ends with ViewSet, or its base list includes one."""
    pkg, _, name = class_qualname.rpartition(".")
    if not pkg:
        return name.endswith("ViewSet")
    tree = _read_module(project_root, pkg)
    if tree is None:
        return name.endswith("ViewSet")
    cls = _find_class(tree, name)
    if cls is None:
        return name.endswith("ViewSet")
    bases = _class_bases(cls)
    return any(b.endswith("ViewSet") or b.endswith("ModelViewSet") for b in bases) or name.endswith("ViewSet")


def _cbv_methods(class_qualname: str, project_root: Path) -> list[str]:
    """Return the lowercase HTTP methods this CBV defines (`get`, `post`, ...)."""
    pkg, _, name = class_qualname.rpartition(".")
    if not pkg:
        return []
    tree = _read_module(project_root, pkg)
    if tree is None:
        return []
    cls = _find_class(tree, name)
    if cls is None:
        return []
    methods = [
        node.name
        for node in cls.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in _HTTP_METHODS
    ]
    return methods


# --- view expression resolution ------------------------------------------


def _resolve_view_expr(
    expr: ast.AST, mod: _ModuleIndex
) -> tuple[str | None, bool]:
    """Resolve a view expression in `urls.py` to a handler qualname.

    Returns (qualname, is_class_based).
    For class-based views, qualname is the class qualname (without method).
    """
    # views.foo  or  views.Foo.as_view()
    target = expr
    is_class = False
    if isinstance(expr, ast.Call):
        func = expr.func
        # `Cls.as_view()` -> we want the class part
        if isinstance(func, ast.Attribute) and func.attr == "as_view":
            target = func.value
            is_class = True
        else:
            target = func

    chain = _attr_chain(target)
    if chain is None:
        return None, is_class

    head, *rest = chain
    # If head is an alias to a module/class, expand it.
    if head in mod.aliases:
        resolved = mod.aliases[head]
        full = ".".join([resolved, *rest]) if rest else resolved
    else:
        full = ".".join(chain)

    return full, is_class


# --- pattern parsing ------------------------------------------------------


@dataclass
class _Router:
    name: str
    registrations: list[tuple[str, str]]  # (prefix, viewset_qualname)


def _collect_routers(mod: _ModuleIndex) -> dict[str, _Router]:
    """Find DefaultRouter/SimpleRouter instantiations and .register() calls."""
    routers: dict[str, _Router] = {}
    assert isinstance(mod.tree, ast.Module)
    for stmt in mod.tree.body:
        # router = DefaultRouter()
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            call = stmt.value
            if isinstance(call, ast.Call):
                chain = _attr_chain(call.func)
                if chain and chain[-1] in {"DefaultRouter", "SimpleRouter"}:
                    routers[stmt.targets[0].id] = _Router(stmt.targets[0].id, [])
        # router.register("prefix", ViewSet)
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            call = stmt.value
            if isinstance(call.func, ast.Attribute) and call.func.attr == "register":
                base = call.func.value
                if isinstance(base, ast.Name) and base.id in routers and call.args:
                    prefix = _const_str(call.args[0])
                    if prefix is None:
                        # also handle r"users" raw strings (still ast.Constant)
                        continue
                    if len(call.args) >= 2:
                        qual, _ = _resolve_view_expr(call.args[1], mod)
                        if qual:
                            routers[base.id].registrations.append((prefix, qual))
    return routers


def _emit_router_endpoints(
    router: _Router, prefix: str, project_root: Path, source_file: Path
) -> list[DiscoveredEndpoint]:
    out: list[DiscoveredEndpoint] = []
    for r_prefix, viewset_qual in router.registrations:
        # Each registration mounts at `<prefix>/<r_prefix>/`
        base_route = _join_routes(prefix, r_prefix.rstrip("/") + "/")
        for action, method, suffix in _VIEWSET_ACTIONS:
            full_route = _join_routes(base_route, suffix)
            params: list[str] = []
            if "{pk}" in full_route:
                params = ["pk"]
            out.append(
                DiscoveredEndpoint(
                    http_method=method,
                    route=full_route,
                    route_params=tuple(params),
                    handler_qualname=f"{viewset_qual}.{action}",
                    source_location=f"{source_file}:0",
                )
            )
    return out


def _parse_urls_module(
    project_root: Path,
    file_path: Path,
    prefix: str,
    visited: set[Path],
) -> list[DiscoveredEndpoint]:
    file_path = file_path.resolve()
    if file_path in visited:
        return []
    visited.add(file_path)

    if not file_path.exists():
        return []

    src = file_path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(src, filename=str(file_path))
    except SyntaxError:
        return []

    package = _module_dotted(project_root, file_path).rsplit(".", 1)[0]  # blog.urls -> blog
    aliases = _build_alias_map(tree, _module_dotted(project_root, file_path))
    mod = _ModuleIndex(file_path, package, tree, aliases)
    routers = _collect_routers(mod)

    out: list[DiscoveredEndpoint] = []

    # urlpatterns may be `urlpatterns = [...]` or `urlpatterns = [...] + router.urls`.
    assert isinstance(tree, ast.Module)
    pattern_lists: list[ast.List] = []
    router_concat: set[str] = set()
    for stmt in tree.body:
        if not (isinstance(stmt, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "urlpatterns" for t in stmt.targets
        )):
            continue
        val = stmt.value
        # collect any Lists in the rhs (handles `[...] + router.urls + [...]`).
        for sub in ast.walk(val):
            if isinstance(sub, ast.List):
                pattern_lists.append(sub)
            if isinstance(sub, ast.Attribute) and sub.attr == "urls":
                base = sub.value
                if isinstance(base, ast.Name) and base.id in routers:
                    router_concat.add(base.id)

    # Default behaviour: if a router exists at all and no explicit concat, still emit.
    for rname, router in routers.items():
        if router.registrations and (rname in router_concat or not router_concat):
            out.extend(_emit_router_endpoints(router, prefix, project_root, file_path))

    for plist in pattern_lists:
        for elt in plist.elts:
            out.extend(_parse_pattern_call(elt, prefix, mod, project_root, visited))

    return out


def _parse_pattern_call(
    expr: ast.AST,
    prefix: str,
    mod: _ModuleIndex,
    project_root: Path,
    visited: set[Path],
) -> list[DiscoveredEndpoint]:
    if not isinstance(expr, ast.Call):
        return []
    chain = _attr_chain(expr.func)
    if chain is None:
        return []
    fname = chain[-1]
    if fname not in {"path", "re_path"}:
        return []
    if not expr.args or len(expr.args) < 2:
        return []
    route_arg = _const_str(expr.args[0])
    if route_arg is None:
        return []
    if fname == "path":
        local_route, params = _normalize_path_route(route_arg)
    else:
        local_route, params = _normalize_re_route(route_arg)
    full_route = _join_routes(prefix, local_route.lstrip("/"))

    second = expr.args[1]
    # include(...)?
    if isinstance(second, ast.Call):
        sub_chain = _attr_chain(second.func)
        if sub_chain and sub_chain[-1] == "include":
            return _handle_include(second, full_route, project_root, visited)

    # Regular view reference.
    qual, is_class = _resolve_view_expr(second, mod)
    if qual is None:
        return []

    if is_class:
        # Decide: DRF APIView/ViewSet or generic CBV.
        if _is_drf_viewset(qual, project_root):
            # `Cls.as_view({...})` style is rare in URL conf; ViewSets are
            # normally registered via routers. Skip here.
            methods = _cbv_methods(qual, project_root)
        else:
            methods = _cbv_methods(qual, project_root)
        out: list[DiscoveredEndpoint] = []
        loc = f"{mod.path}:{getattr(expr, 'lineno', 0)}"
        for m in methods:
            out.append(
                DiscoveredEndpoint(
                    http_method=m.upper(),
                    route=full_route,
                    route_params=tuple(params),
                    handler_qualname=f"{qual}.{m}",
                    source_location=loc,
                )
            )
        return out

    # FBV: assume GET unless route uses an obvious DRF @api_view decorator (future).
    return [
        DiscoveredEndpoint(
            http_method="GET",
            route=full_route,
            route_params=tuple(params),
            handler_qualname=qual,
            source_location=f"{mod.path}:{getattr(expr, 'lineno', 0)}",
        )
    ]


def _handle_include(
    call: ast.Call, prefix: str, project_root: Path, visited: set[Path]
) -> list[DiscoveredEndpoint]:
    if not call.args:
        return []
    arg = call.args[0]
    dotted = _const_str(arg)
    if dotted is None:
        return []
    rel = Path(*dotted.split("."))
    candidates = [project_root / rel.with_suffix(".py"), project_root / rel / "__init__.py"]
    for c in candidates:
        if c.exists():
            return _parse_urls_module(project_root, c, prefix, visited)
    return []


# --- public API -----------------------------------------------------------


def discover_endpoints(project_root: str | Path) -> list[DiscoveredEndpoint]:
    """Discover all HTTP endpoints in a Django project source tree.

    `project_root` should be the directory that contains the root `urls.py`
    (or contains the package(s) that hold `urls.py`). The function recursively
    walks `include()` calls.
    """
    root = Path(project_root).resolve()
    # Find all urls.py files; the one that is NOT included by any other is a
    # root. Simpler: parse them all but only emit endpoints reachable from the
    # top-level `urls.py` if it exists; else emit each as standalone.
    top = root / "urls.py"
    visited: set[Path] = set()
    if top.exists():
        endpoints = _parse_urls_module(root, top, "", visited)
    else:
        endpoints = []
        for urls_py in sorted(root.rglob("urls.py")):
            endpoints.extend(_parse_urls_module(root, urls_py, "", visited))

    # Stable order.
    endpoints.sort(key=lambda e: (e.http_method, e.route, e.handler_qualname))
    return endpoints
