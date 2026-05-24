"""PFG assembly orchestrator (Phase 2 W11).

Combines the W5-W10 Django sub-extractors into a complete `PFG`:

  * endpoints       : discover_endpoints()
  * auth + role     : annotate_endpoint()
  * call graph      : build_call_graph()
  * data access     : detect_data_accesses() per project function
  * identifier flow : track_identifier_flow() per endpoint handler

Deterministic ID scheme (so re-runs produce identical PFGs):

  endpoint::<METHOD>::<route>
  service::<dotted.qualname>
  data::<dotted.qualname>::<lineno>::<idx>

Service nodes are emitted for every project-defined function reachable from
an endpoint that is *not* itself a data-access leaf. Data-access nodes
attach to whichever service contains the ORM call.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from pfg.extractors.django.auth import annotate_endpoint, resolve_default_permission_classes
from pfg.extractors.django.callgraph import build_call_graph
from pfg.extractors.django.dataaccess import DataAccess, detect_data_accesses
from pfg.extractors.django.endpoints import discover_endpoints
from pfg.extractors.django.idflow import FlowSink, track_identifier_flow
from pfg.pfg.graph import PFG

# --- ID helpers -----------------------------------------------------------

_EXTERNAL_DATA_ACCESS: dict[str, tuple[str, str]] = {
    "db_file_storage.views.get_file": ("READ", "FileProxy"),
}


def _safe(s: str) -> str:
    """Sanitize a string into the schema-allowed id form ``[A-Za-z_][A-Za-z0-9_]*``."""
    out = "".join(c if c.isalnum() else "_" for c in s)
    if not out or not (out[0].isalpha() or out[0] == "_"):
        out = "_" + out
    return out


def _endpoint_id(method: str, route: str) -> str:
    return _safe(f"endpoint__{method}__{route}")


def _service_id(qual: str) -> str:
    return _safe(f"service__{qual}")


def _data_id(qual: str, da: DataAccess, idx: int) -> str:
    return _safe(f"data__{qual}__L{da.lineno}__{idx}")


def _external_data_id(qual: str, idx: int) -> str:
    return _safe(f"data__{qual}__external__{idx}")


# --- helpers --------------------------------------------------------------


def _resolve_function(project_root: Path, qual: str) -> tuple[ast.AST, ast.FunctionDef | ast.AsyncFunctionDef] | None:
    """Locate the AST FunctionDef for a project qualname."""
    parts = qual.split(".")
    for i in range(len(parts) - 1, 0, -1):
        rel = Path(*parts[:i])
        for cand in (project_root / rel.with_suffix(".py"), project_root / rel / "__init__.py"):
            if not cand.exists():
                continue
            try:
                tree = ast.parse(cand.read_text(encoding="utf-8"), filename=str(cand))
            except SyntaxError:
                continue
            rest = parts[i:]
            if len(rest) == 1:
                for n in ast.walk(tree):
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == rest[0]:
                        return tree, n
            elif len(rest) == 2:
                for n in ast.walk(tree):
                    if isinstance(n, ast.ClassDef) and n.name == rest[0]:
                        for body in n.body:
                            if isinstance(body, (ast.FunctionDef, ast.AsyncFunctionDef)) and body.name == rest[1]:
                                return tree, body
    return None


def _reachable_functions(seeds: list[str], edges: list[tuple[str, str]]) -> set[str]:
    """All qualnames reachable from seeds via the call edges."""
    succ: dict[str, list[str]] = {}
    for c, e in edges:
        succ.setdefault(c, []).append(e)
    seen: set[str] = set()
    stack = list(seeds)
    while stack:
        q = stack.pop()
        if q in seen:
            continue
        seen.add(q)
        for n in succ.get(q, []):
            stack.append(n)
    return seen


def _reachable_from(seed: str, edges: list[tuple[str, str]]) -> set[str]:
    return _reachable_functions([seed], edges)


def _attr_chain(node: ast.AST) -> list[str] | None:
    parts: list[str] = []
    cur: ast.AST = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return list(reversed(parts))
    return None


def _function_references_request_user(fn: ast.AST) -> bool:
    for node in ast.walk(fn):
        if not isinstance(node, ast.Attribute) or node.attr != "user":
            continue
        base = node.value
        if isinstance(base, ast.Name) and base.id in {"request", "user"}:
            return True
        if (
            isinstance(base, ast.Attribute)
            and base.attr == "request"
            and isinstance(base.value, ast.Name)
            and base.value.id == "self"
        ):
            return True
    return False


def _function_has_tenant_scope(fn: ast.AST) -> bool:
    tenant_terms = ("tenant", "organization", "org", "workspace", "realm", "project")
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.keyword)
            and node.arg
            and any(term in node.arg.lower() for term in tenant_terms)
        ):
            return True
        if isinstance(node, ast.Attribute):
            chain = _attr_chain(node)
            text = ".".join(chain).lower() if chain else node.attr.lower()
            if any(term in text for term in tenant_terms) and "request" in text:
                return True
    return False


def _function_has_object_permission_check(fn: ast.AST) -> bool:
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name: str | None = None
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        if name in {"check_object_permissions", "has_object_permission"}:
            return True
        if name == "has_perm" and len(node.args) >= 2:
            return True
    return False


def _function_calls_self_get_object(fn: ast.AST) -> bool:
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "get_object"
            and isinstance(func.value, ast.Name)
            and func.value.id == "self"
        ):
            return True
    return False


def _function_has_ownership_guard(fn: ast.AST) -> bool:
    """Detect FBV ownership patterns like `obj.user != request.user` or
    `filter(user=request.user)` inside a function body."""
    for node in ast.walk(fn):
        # Pattern 1: comparison involving request.user and an object attribute
        # e.g. `if set_obj.get_owner_object().user != request.user:`
        if isinstance(node, ast.Compare):
            all_parts = [node.left] + list(node.comparators)
            has_request_user = False
            has_obj_user = False
            for part in all_parts:
                src = ast.dump(part)
                if "request" in src and "user" in src:
                    has_request_user = True
                elif "user" in src or "owner" in src or "author" in src:
                    has_obj_user = True
            if has_request_user and has_obj_user:
                return True
        # Pattern 2: ORM filter(user=request.user) or get(user=request.user)
        if isinstance(node, ast.Call):
            func = node.func
            func_name = None
            if isinstance(func, ast.Attribute):
                func_name = func.attr
            if func_name in ("filter", "get", "exclude", "get_object_or_404"):
                for kw in node.keywords:
                    if kw.arg and ("user" in kw.arg or "owner" in kw.arg or "author" in kw.arg):
                        # Check if value references request.user
                        val_src = ast.dump(kw.value)
                        if "request" in val_src and "user" in val_src:
                            return True
    return False


def _class_get_queryset_uses_user(tree: ast.AST, class_name: str) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or node.name != class_name:
            continue
        for body in node.body:
            if (
                isinstance(body, (ast.FunctionDef, ast.AsyncFunctionDef))
                and body.name == "get_queryset"
                and (_function_references_request_user(body) or _function_filters_by_request(body))
            ):
                return True
    return False


def _function_filters_by_request(fn: ast.AST) -> bool:
    """True if the function uses self.request.* (beyond .user) as a filter
    argument — indicates request-scoped queryset (e.g., self.request.event)."""
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr not in ("filter", "get", "exclude"):
            continue
        # Check keyword args: value references self.request.*
        for kw in node.keywords:
            val_src = ast.dump(kw.value)
            if "self" in val_src and "request" in val_src:
                return True
        # Check positional args too (Q objects etc)
        for arg in node.args:
            arg_src = ast.dump(arg)
            if "self" in arg_src and "request" in arg_src:
                return True
    return False


def _class_get_queryset_has_tenant_scope(tree: ast.AST, class_name: str) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or node.name != class_name:
            continue
        for body in node.body:
            if (
                isinstance(body, (ast.FunctionDef, ast.AsyncFunctionDef))
                and body.name in {"get_queryset", "get_object"}
                and _function_has_tenant_scope(body)
            ):
                return True
    return False


def _resolve_class_module(
    project_root: Path, qual: str
) -> tuple[ast.AST, str] | None:
    """Resolve the module AST tree and class name from a qualname.

    Works even when the method (last segment) is inherited and not present
    in user source — we only need the class definition.
    """
    parts = qual.split(".")
    if len(parts) < 3:
        return None
    class_name = parts[-2]
    for i in range(len(parts) - 2, 0, -1):
        rel = Path(*parts[:i])
        for cand in (
            project_root / rel.with_suffix(".py"),
            project_root / rel / "__init__.py",
        ):
            if not cand.exists():
                continue
            try:
                tree = ast.parse(cand.read_text(encoding="utf-8"), filename=str(cand))
            except SyntaxError:
                continue
            for n in ast.walk(tree):
                if isinstance(n, ast.ClassDef) and n.name == class_name:
                    return tree, class_name
    return None


# --- model relationship analysis ------------------------------------------

_TENANT_MODEL_NAMES = frozenset({
    "organization", "organisation", "org", "tenant",
    "workspace", "realm", "project", "team", "company",
    "account",
})

_FK_FIELD_TYPES = frozenset({
    "ForeignKey", "OneToOneField",
})


def _scan_tenant_scoped_models(project_root: Path) -> set[str]:
    """Scan Django model definitions to find models with FK to tenant-scoped models.

    Returns a set of model class names that are transitively tenant-scoped
    (i.e., they have a ForeignKey to a model whose name matches tenant terms).
    """
    # First pass: find directly tenant-scoped models (by name)
    direct_tenant: set[str] = set()
    # Track FK relationships: child_model -> set of parent_model names
    fk_targets: dict[str, set[str]] = {}

    for models_file in project_root.rglob("models.py"):
        try:
            tree = ast.parse(models_file.read_text(encoding="utf-8"), filename=str(models_file))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            model_name = node.name
            # Check if model name itself is tenant-scoped
            if model_name.lower() in _TENANT_MODEL_NAMES:
                direct_tenant.add(model_name)
            # Look for FK/O2O fields pointing to tenant models
            for stmt in node.body:
                if not isinstance(stmt, ast.Assign):
                    continue
                if not isinstance(stmt.value, ast.Call):
                    continue
                call = stmt.value
                func_name = None
                if isinstance(call.func, ast.Attribute):
                    func_name = call.func.attr
                elif isinstance(call.func, ast.Name):
                    func_name = call.func.id
                if func_name not in _FK_FIELD_TYPES:
                    continue
                # Get the FK target model name (first positional arg)
                if not call.args:
                    continue
                target_arg = call.args[0]
                target_name = None
                if isinstance(target_arg, ast.Constant) and isinstance(target_arg.value, str):
                    # "app.ModelName" or "ModelName"
                    target_name = target_arg.value.rsplit(".", 1)[-1]
                elif isinstance(target_arg, ast.Name):
                    target_name = target_arg.id
                elif isinstance(target_arg, ast.Attribute):
                    target_name = target_arg.attr
                if target_name:
                    fk_targets.setdefault(model_name, set()).add(target_name)

    # Second pass: transitively resolve tenant-scoped models (1 level deep)
    tenant_scoped: set[str] = set(direct_tenant)
    for model_name, targets in fk_targets.items():
        for target in targets:
            if target.lower() in _TENANT_MODEL_NAMES or target in direct_tenant:
                tenant_scoped.add(model_name)
                break

    return tenant_scoped


def _scan_object_permission_classes(project_root: Path) -> set[str]:
    """Scan project for DRF permission classes that define has_object_permission.

    Returns a set of class names that implement object-level permission checks.
    """
    obj_perm_classes: set[str] = set()
    for py_file in project_root.rglob("*.py"):
        if "migrations" in py_file.parts or "test" in py_file.name.lower():
            continue
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            # Check if this class defines has_object_permission method
            has_hop = any(
                isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
                and stmt.name == "has_object_permission"
                for stmt in node.body
            )
            if has_hop:
                obj_perm_classes.add(node.name)
    return obj_perm_classes


def _handler_ownership_check_present(project_root: Path, qual: str) -> bool:
    resolved = _resolve_function(project_root, qual)
    if resolved is not None:
        tree, fn = resolved
        if _function_calls_self_get_object(fn):
            return True
        # FBV ownership guard: obj.user != request.user or filter(user=request.user)
        if _function_has_ownership_guard(fn):
            return True
        parts = qual.split(".")
        if len(parts) >= 3:
            class_name = parts[-2]
            if _class_get_queryset_uses_user(tree, class_name) and _function_calls_self_get_object(fn):
                return True
        # Handler found in source but doesn't use get_object() — custom action
        # that bypasses the queryset pipeline (e.g. Model.objects.get(pk=pk)).
        return False

    # Handler method not found in user source — likely inherited from a DRF
    # mixin/base class (retrieve, list, update, partial_update, destroy).
    # These standard methods go through get_queryset()/get_object().  If the
    # viewset overrides get_queryset() to scope queries to request.user,
    # ownership is enforced for all inherited handlers.
    resolved_class = _resolve_class_module(project_root, qual)
    if resolved_class is not None:
        tree, class_name = resolved_class
        if _class_get_queryset_uses_user(tree, class_name):
            return True

    return False


def _handler_tenant_check_present(project_root: Path, qual: str) -> bool:
    resolved = _resolve_function(project_root, qual)
    if resolved is not None:
        tree, fn = resolved
        if _function_has_tenant_scope(fn):
            return True
        parts = qual.split(".")
        return len(parts) >= 3 and _class_get_queryset_has_tenant_scope(tree, parts[-2])

    resolved_class = _resolve_class_module(project_root, qual)
    if resolved_class is not None:
        tree, class_name = resolved_class
        return _class_get_queryset_has_tenant_scope(tree, class_name)
    return False


def _handler_object_permission_check_present(project_root: Path, qual: str) -> bool:
    resolved = _resolve_function(project_root, qual)
    if resolved is not None:
        _, fn = resolved
        return _function_has_object_permission_check(fn)
    return False


def _handler_uses_obj_perm_class(
    project_root: Path, qual: str, obj_perm_classes: set[str]
) -> bool:
    """Check if the handler's view class uses a permission_classes containing
    a class from obj_perm_classes (which define has_object_permission)."""
    if not obj_perm_classes:
        return False
    resolved_class = _resolve_class_module(project_root, qual)
    if resolved_class is None:
        return False
    tree, class_name = resolved_class
    cls = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            cls = node
            break
    if cls is None:
        return False
    # Look for permission_classes = [...] attribute
    for stmt in cls.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name) and target.id == "permission_classes":
                    # Extract class names from the list/tuple
                    val = stmt.value
                    if isinstance(val, (ast.List, ast.Tuple)):
                        for elt in val.elts:
                            name = None
                            if isinstance(elt, ast.Name):
                                name = elt.id
                            elif isinstance(elt, ast.Attribute):
                                name = elt.attr
                            if name and name in obj_perm_classes:
                                return True
    return False


# --- main entry -----------------------------------------------------------


def build_pfg(
    project_root: str | Path,
    *,
    application: str | None = None,
) -> PFG:
    """Run the full Django pipeline and return an in-memory `PFG`."""
    root = Path(project_root).resolve()
    app_name = application or root.name

    discovered = discover_endpoints(root)

    # Resolve project-wide DRF DEFAULT_PERMISSION_CLASSES from settings.
    default_auth = resolve_default_permission_classes(root)

    # Scan model definitions for tenant-scoped relationships.
    tenant_scoped_models = _scan_tenant_scoped_models(root)

    # Scan for custom permission classes with has_object_permission.
    obj_perm_classes = _scan_object_permission_classes(root)

    # If the default permission class defines has_object_permission, upgrade
    # default_auth to reflect that (handles cases like WgerPermission which
    # inherits from BasePermission but defines has_object_permission directly).
    if default_auth is not None and not default_auth.object_permission_check_present:
        from pfg.extractors.django.auth import EndpointAuth as _EA
        _dpc_re = __import__("re").compile(
            r"""['"]DEFAULT_PERMISSION_CLASSES['"]\s*:\s*[\(\[\{](?:\s*#[^\n]*)?\s*['"]([^'"]+)['"]"""
        )
        _settings_names = ("settings.py", "settings_global.py", "conf/settings.py", "conf/server.py", "settings/base.py")
        # Try named settings files first, then all .py files as fallback
        _found = False
        for settings_rel in _settings_names:
            for candidate in root.rglob(settings_rel):
                try:
                    text = candidate.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                m = _dpc_re.search(text)
                if m is not None:
                    cls_name = m.group(1).rsplit(".", 1)[-1]
                    if cls_name in obj_perm_classes:
                        default_auth = _EA(
                            default_auth.requires_auth,
                            default_auth.required_role,
                            default_auth.is_intentionally_public,
                            role_check_present=default_auth.role_check_present,
                            model_permission_check_present=default_auth.model_permission_check_present,
                            object_permission_check_present=True,
                            tenant_check_present=default_auth.tenant_check_present,
                        )
                    _found = True
                    break
            if _found:
                break
        if not _found:
            _SKIP_DIRS = {"migrations", "tests", "test", "docs", "locale", "locales", "node_modules", ".tox"}
            for py_file in root.rglob("*.py"):
                if any(part in _SKIP_DIRS for part in py_file.parts):
                    continue
                try:
                    text = py_file.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                m = _dpc_re.search(text)
                if m is not None:
                    cls_name = m.group(1).rsplit(".", 1)[-1]
                    if cls_name in obj_perm_classes:
                        default_auth = _EA(
                            default_auth.requires_auth,
                            default_auth.required_role,
                            default_auth.is_intentionally_public,
                            role_check_present=default_auth.role_check_present,
                            model_permission_check_present=default_auth.model_permission_check_present,
                            object_permission_check_present=True,
                            tenant_check_present=default_auth.tenant_check_present,
                        )
                    break

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen_node_ids: set[str] = set()

    def add_node(node: dict[str, Any]) -> None:
        if node["id"] in seen_node_ids:
            return
        seen_node_ids.add(node["id"])
        nodes.append(node)

    seen_edges: set[tuple[str, str, str, str | None]] = set()

    def add_edge(src: str, dst: str, etype: str, param: str | None = None) -> None:
        key = (src, dst, etype, param)
        if key in seen_edges:
            return
        seen_edges.add(key)
        e: dict[str, Any] = {"src": src, "dst": dst, "type": etype}
        if param is not None:
            e["param"] = param
        edges.append(e)

    # Pass 1: endpoints.
    seeds: list[str] = []
    endpoint_ids_by_handler: dict[str, list[str]] = {}
    for ep in discovered:
        auth = annotate_endpoint(ep, root, default_auth=default_auth)
        # Check if handler's view uses a custom obj-perm class
        has_obj_perm = (
            auth.object_permission_check_present
            or _handler_object_permission_check_present(root, ep.handler_qualname)
            or _handler_uses_obj_perm_class(root, ep.handler_qualname, obj_perm_classes)
        )
        eid = _endpoint_id(ep.http_method, ep.route)
        add_node(
            {
                "id": eid,
                "type": "endpoint",
                "attrs": {
                    "http_method": ep.http_method,
                    "route": ep.route,
                    "route_params": list(ep.route_params),
                    "requires_auth": auth.requires_auth,
                    "required_role": auth.required_role,
                    "ownership_check_present": _handler_ownership_check_present(root, ep.handler_qualname),
                    "role_check_present": auth.role_check_present,
                    "model_permission_check_present": auth.model_permission_check_present,
                    "object_permission_check_present": has_obj_perm,
                    "tenant_check_present": auth.tenant_check_present
                    or _handler_tenant_check_present(root, ep.handler_qualname),
                    "is_intentionally_public": auth.is_intentionally_public,
                    "source_location": ep.source_location,
                },
            }
        )
        if ep.handler_qualname not in seeds:
            seeds.append(ep.handler_qualname)
        endpoint_ids_by_handler.setdefault(ep.handler_qualname, []).append(eid)

    # Pass 2: call graph.
    call_edges = build_call_graph(root, seeds)
    raw_edges = [(e.caller, e.callee) for e in call_edges]
    reachable = _reachable_functions(seeds, raw_edges)

    # Pass 3: service nodes for every reachable handler/function.
    for qual in sorted(reachable):
        sid = _service_id(qual)
        add_node(
            {
                "id": sid,
                "type": "service",
                "attrs": {
                    "name": qual,
                    "performs_data_access": False,
                    "performs_mutation": False,
                },
            }
        )

    # Pass 4: endpoint -> service call edge for the handler itself.
    for handler, endpoint_ids in endpoint_ids_by_handler.items():
        if handler in reachable:
            for eid in endpoint_ids:
                add_edge(eid, _service_id(handler), "call")

    # Pass 5: callgraph edges as service->service call edges.
    for c, e in raw_edges:
        add_edge(_service_id(c), _service_id(e), "call")

    # Pass 6: data-access nodes per reachable function + idflow per endpoint.
    da_by_qual: dict[str, list[tuple[str, DataAccess]]] = {}
    for qual in sorted(reachable):
        external = _EXTERNAL_DATA_ACCESS.get(qual)
        if external is not None:
            operation, target_entity = external
            did = _external_data_id(qual, 0)
            add_node(
                {
                    "id": did,
                    "type": "data_access",
                    "attrs": {
                        "operation": operation,
                        "target_entity": target_entity,
                        "has_ownership_predicate": False,
                        "ownership_predicate_type": "NONE",
                        "has_tenant_predicate": False,
                        "requires_tenant_isolation": False,
                        "requires_object_permission": False,
                        "has_object_permission_check": False,
                        "user_controlled_params_in_query": [],
                    },
                }
            )
            add_edge(_service_id(qual), did, "call")
            for n in nodes:
                if n["id"] == _service_id(qual):
                    n["attrs"]["performs_data_access"] = True
            continue
        resolved = _resolve_function(root, qual)
        if resolved is None:
            continue
        _, fn = resolved
        accesses = detect_data_accesses(fn)
        for idx, da in enumerate(accesses):
            did = _data_id(qual, da, idx)
            # Determine tenant isolation requirement from model relationships
            requires_tenant = da.requires_tenant_isolation or (
                da.target_entity in tenant_scoped_models
            )
            add_node(
                {
                    "id": did,
                    "type": "data_access",
                    "attrs": {
                        "operation": da.operation,
                        "target_entity": da.target_entity,
                        "has_ownership_predicate": da.has_ownership_predicate,
                        "ownership_predicate_type": da.ownership_predicate_type,
                        "has_tenant_predicate": da.has_tenant_predicate,
                        "requires_tenant_isolation": requires_tenant,
                        "requires_object_permission": da.requires_object_permission,
                        "has_object_permission_check": da.has_object_permission_check,
                        "user_controlled_params_in_query": [],
                    },
                }
            )
            add_edge(_service_id(qual), did, "call")
            da_by_qual.setdefault(qual, []).append((did, da))
            # Mark service as performing data access / mutation.
            for n in nodes:
                if n["id"] == _service_id(qual):
                    n["attrs"]["performs_data_access"] = True
                    if da.operation in {"WRITE", "UPDATE", "DELETE"}:
                        n["attrs"]["performs_mutation"] = True

    # Pass 7: identifier flow edges from each endpoint's route params.
    # Strategy: track flow inside the handler; whenever a sink callee maps to
    # a known reachable qualname, add an identifier_flow edge from the
    # endpoint to that service. If the flow lands on an ORM kwarg, the data
    # access node also gets the kwarg recorded in its
    # user_controlled_params_in_query.
    for ep in discovered:
        if not ep.route_params:
            continue
        eid = _endpoint_id(ep.http_method, ep.route)
        resolved = _resolve_function(root, ep.handler_qualname)
        if resolved is None:
            continue
        _, fn = resolved
        sinks = track_identifier_flow(fn, list(ep.route_params))
        # Build a quick lookup of reachable callee names by their last segment.
        callee_targets = _build_callee_targets(reachable, sinks)
        for sink in sinks:
            target_qual = callee_targets.get(sink.callee)
            if target_qual is None:
                continue
            data_targets = _data_access_ids_reachable_from(target_qual, raw_edges, da_by_qual)
            if data_targets:
                for did in data_targets:
                    add_edge(eid, did, "identifier_flow", param=sink.source)
                    _annotate_dataaccess_user_param_by_id(nodes, did, sink.source)
                    _annotate_dataaccess_context(nodes, eid, did, ep)
                    if _endpoint_param_is_tenant_scoped(ep, sink.source):
                        add_edge(eid, did, "tenant_flow", param=sink.source)
            else:
                add_edge(eid, _service_id(target_qual), "identifier_flow", param=sink.source)
            # If sink hits a data access with matching kwarg, annotate it.
            _annotate_dataaccess_user_param(nodes, da_by_qual, target_qual, sink)

        # Direct ORM calls inside a route handler do not resolve to a project
        # qualname. If the route parameter is used as an ORM kwarg in the
        # handler, attach the flow to data-access nodes in that same handler.
        for sink in sinks:
            if not _looks_like_orm_sink(sink) or sink.arg_kind != "kwarg":
                continue
            for did, _ in da_by_qual.get(ep.handler_qualname, []):
                add_edge(eid, did, "identifier_flow", param=sink.source)
                _annotate_dataaccess_user_param_by_id(nodes, did, sink.source)
                _annotate_dataaccess_context(nodes, eid, did, ep)
                if _endpoint_param_is_tenant_scoped(ep, sink.source):
                    add_edge(eid, did, "tenant_flow", param=sink.source)

    # Pass 8: Propagate endpoint-level ownership/permission signals to data
    # access nodes. When a ViewSet overrides get_queryset() to filter by
    # request.user, the endpoint has ownership_check_present=True — but
    # individual data-access nodes in the call graph don't know this. We
    # propagate the signal so validators correctly suppress false positives.
    _propagate_endpoint_permissions_to_data(nodes, edges)

    pfg = PFG.model_validate(
        {
            "schema_version": "1.0",
            "application": app_name,
            "framework": "django",
            "nodes": nodes,
            "edges": edges,
        }
    )
    from pfg.pfg.features import enrich_endpoint_features
    enrich_endpoint_features(pfg)
    return pfg


def _build_callee_targets(reachable: set[str], sinks: list[FlowSink]) -> dict[str, str]:
    """Map a sink's `callee` (as written in source) to a reachable qualname.

    The sink stores the dotted *expression* used at the call site (e.g.
    ``services.fetch_invoice``). We map that to the canonical project
    qualname by matching on the trailing segments.
    """
    by_tail: dict[str, list[str]] = {}
    for q in reachable:
        parts = q.split(".")
        for i in range(1, min(len(parts), 4) + 1):
            tail = ".".join(parts[-i:])
            by_tail.setdefault(tail, []).append(q)
    out: dict[str, str] = {}
    for s in sinks:
        cands = by_tail.get(s.callee)
        if not cands:
            # Fallback: last segment only.
            last = s.callee.rsplit(".", 1)[-1]
            cands = by_tail.get(last)
        if cands and len(cands) == 1:
            out[s.callee] = cands[0]
    return out


def _annotate_dataaccess_user_param(
    nodes: list[dict[str, Any]],
    da_by_qual: dict[str, list[tuple[str, DataAccess]]],
    target_qual: str,
    sink: FlowSink,
) -> None:
    if sink.arg_kind != "kwarg" or sink.arg_name is None:
        return
    for did, da in da_by_qual.get(target_qual, []):
        _annotate_dataaccess_user_param_by_id(nodes, did, sink.source)
        # silence unused-var lint; later we can match against per-call kwarg metadata.
        _ = da


def _annotate_dataaccess_user_param_by_id(
    nodes: list[dict[str, Any]],
    data_access_id: str,
    param_name: str,
) -> None:
    for n in nodes:
        if n["id"] != data_access_id:
            continue
        params = n["attrs"]["user_controlled_params_in_query"]
        if param_name not in params:
            params.append(param_name)
        return


_TENANT_ROUTE_TERMS = (
    "tenant",
    "organization",
    "organisation",
    "org",
    "workspace",
    "realm",
    "project",
)


def _endpoint_param_is_tenant_scoped(ep: object, param_name: str) -> bool:
    params = [str(p).lower() for p in getattr(ep, "route_params", ())]
    pname = param_name.lower()
    if any(term in pname for term in _TENANT_ROUTE_TERMS):
        return True
    return any(term in p for p in params for term in _TENANT_ROUTE_TERMS)


def _target_entity_is_tenant_scoped(target_entity: str) -> bool:
    lowered = target_entity.lower()
    return any(term in lowered for term in _TENANT_ROUTE_TERMS)


def _annotate_dataaccess_context(
    nodes: list[dict[str, Any]],
    endpoint_id: str,
    data_access_id: str,
    ep: object,
) -> None:
    endpoint_node = next((n for n in nodes if n["id"] == endpoint_id), None)
    data_node = next((n for n in nodes if n["id"] == data_access_id), None)
    if endpoint_node is None or data_node is None:
        return
    ep_attrs = endpoint_node["attrs"]
    da_attrs = data_node["attrs"]

    if _endpoint_param_is_tenant_scoped(ep, "") or _target_entity_is_tenant_scoped(da_attrs.get("target_entity", "")):
        da_attrs["requires_tenant_isolation"] = True
        if ep_attrs.get("tenant_check_present"):
            da_attrs["has_tenant_predicate"] = True

    if ep_attrs.get("model_permission_check_present"):
        da_attrs["requires_object_permission"] = True
    if ep_attrs.get("object_permission_check_present"):
        da_attrs["has_object_permission_check"] = True


def _data_access_ids_reachable_from(
    qual: str,
    raw_edges: list[tuple[str, str]],
    da_by_qual: dict[str, list[tuple[str, DataAccess]]],
) -> list[str]:
    out: list[str] = []
    for q in sorted(_reachable_from(qual, raw_edges)):
        out.extend(did for did, _ in da_by_qual.get(q, []))
    return out


def _looks_like_orm_sink(sink: FlowSink) -> bool:
    parts = sink.callee.split(".")
    return len(parts) >= 3 and parts[-2] == "objects"


def _propagate_endpoint_permissions_to_data(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> None:
    """Propagate endpoint-level ownership/permission signals to data_access nodes.

    When a ViewSet has get_queryset() filtering by request.user, the endpoint
    gets ownership_check_present=True. All data_access nodes reachable via
    call edges from that endpoint should inherit has_ownership_predicate=True,
    since the scoped queryset effectively enforces ownership on all lookups.

    Similarly, if the endpoint has object_permission_check_present=True (from
    DRF permission_classes like DjangoObjectPermissions or IsOwner), propagate
    has_object_permission_check=True to reachable data nodes.
    """
    # Build call adjacency for BFS
    call_adj: dict[str, list[str]] = {}
    for e in edges:
        etype = e.get("type", "")
        if etype == "call":
            call_adj.setdefault(e["src"], []).append(e["dst"])

    # Index nodes by id
    node_by_id: dict[str, dict[str, Any]] = {n["id"]: n for n in nodes}

    for ep_node in nodes:
        if ep_node.get("type") != "endpoint":
            continue
        ep_attrs = ep_node["attrs"]
        has_ownership = ep_attrs.get("ownership_check_present", False)
        has_obj_perm = ep_attrs.get("object_permission_check_present", False)
        if not has_ownership and not has_obj_perm:
            continue

        # BFS from endpoint via call edges
        visited: set[str] = set()
        stack = [ep_node["id"]]
        while stack:
            nid = stack.pop()
            if nid in visited:
                continue
            visited.add(nid)
            for neighbor in call_adj.get(nid, []):
                stack.append(neighbor)

        # Propagate to reachable data_access nodes
        for nid in visited:
            n = node_by_id.get(nid)
            if n is None or n.get("type") != "data_access":
                continue
            da_attrs = n["attrs"]
            if has_ownership:
                da_attrs["has_ownership_predicate"] = True
                if da_attrs.get("ownership_predicate_type", "NONE") == "NONE":
                    da_attrs["ownership_predicate_type"] = "INDIRECT"
            if has_obj_perm:
                da_attrs["has_object_permission_check"] = True
