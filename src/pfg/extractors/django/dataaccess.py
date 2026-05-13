"""Django data-access + ownership predicate extractor (Phase 2 W9).

Detects Django ORM call sites within a function/method AST and classifies:

  - operation:        READ / WRITE / UPDATE / DELETE
  - target_entity:    the Django model class name (LHS of `.objects`)
  - ownership flag:   whether the call has a kwarg whose value references
                      ``request.user`` (direct or indirect via FK traversal)

Recognized patterns:

  Cls.objects.<method>(...)            -- direct manager
  Cls.objects.<m1>(...).<m2>(...)      -- chained queryset (each call counted)
  get_object_or_404(Cls, ...)          -- treated as READ Cls; ownership is
                                          inferred from a subsequent compare
                                          against request.user in the body.

Ownership predicate detection:
  - DIRECT   when a kwarg's value references ``request.user`` (or
              ``self.request.user``) and the kwarg name contains no ``__``.
  - INDIRECT when the same value reference is found and the kwarg name
              contains a Django FK traversal (``__``).
  - NONE     otherwise.

Out of scope (v1): aggregations, .raw / .extra, custom managers like
``for_user``, alias chains crossing assignments, decorators that inject
ownership, and inter-procedural reasoning.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

# Sets aligned with pfg.nodes.OperationType so callers can map directly.
_READ_METHODS = frozenset(
    {
        "all",
        "filter",
        "exclude",
        "get",
        "first",
        "last",
        "count",
        "exists",
        "values",
        "values_list",
        "aggregate",
        "annotate",
        "earliest",
        "latest",
        "in_bulk",
        "select_related",
        "prefetch_related",
        "only",
        "defer",
        "raw",
    }
)
_WRITE_METHODS = frozenset({"create", "bulk_create", "get_or_create", "update_or_create"})
_UPDATE_METHODS = frozenset({"update", "bulk_update", "save"})
_DELETE_METHODS = frozenset({"delete"})

_ALL_ORM_METHODS = _READ_METHODS | _WRITE_METHODS | _UPDATE_METHODS | _DELETE_METHODS

_G404_FUNCS = frozenset({"get_object_or_404", "get_list_or_404"})
_OWNER_PARAM_NAMES = frozenset({"user", "owner", "account", "tenant", "organization", "org"})


@dataclass(frozen=True)
class DataAccess:
    """A single ORM access discovered in a function body."""

    operation: str  # "READ" | "WRITE" | "UPDATE" | "DELETE"
    target_entity: str
    has_ownership_predicate: bool
    ownership_predicate_type: str  # "DIRECT" | "INDIRECT" | "NONE"
    lineno: int


# --- helpers --------------------------------------------------------------


def _classify(method: str) -> str | None:
    if method in _READ_METHODS:
        return "READ"
    if method in _WRITE_METHODS:
        return "WRITE"
    if method in _UPDATE_METHODS:
        return "UPDATE"
    if method in _DELETE_METHODS:
        return "DELETE"
    return None


def _references_request_user(expr: ast.AST) -> bool:
    """True if `expr` syntactically contains ``request.user`` or ``self.request.user``."""
    for node in ast.walk(expr):
        if not isinstance(node, ast.Attribute):
            continue
        if node.attr != "user":
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


def _references_owner_param(expr: ast.AST, owner_param_names: set[str]) -> bool:
    for node in ast.walk(expr):
        if isinstance(node, ast.Name) and node.id in owner_param_names:
            return True
    return False


def _ownership_from_kwargs(call: ast.Call, owner_param_names: set[str]) -> tuple[bool, str]:
    """Inspect ``call.keywords`` for an ownership-predicate kwarg."""
    indirect_seen = False
    for kw in call.keywords:
        if kw.arg is None:  # **kwargs
            continue
        if not (
            _references_request_user(kw.value)
            or _references_owner_param(kw.value, owner_param_names)
        ):
            continue
        if "__" in kw.arg:
            indirect_seen = True
            continue
        return True, "DIRECT"
    if indirect_seen:
        return True, "INDIRECT"
    return False, "NONE"


def _orm_target_entity(call: ast.Call) -> str | None:
    """For `<Name>.objects.<method>(...)` chains, return `<Name>`.

    Walks down through nested calls (queryset chains) until it finds the
    `<Name>.objects` head.
    """
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None
    method = func.attr
    if method not in _ALL_ORM_METHODS:
        return None
    cur: ast.AST = func.value
    # Peel chained queryset calls.
    while isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
        cur = cur.func.value
    # Now `cur` should be `<Name>.objects` for ORM access.
    if (
        isinstance(cur, ast.Attribute)
        and cur.attr == "objects"
        and isinstance(cur.value, ast.Name)
    ):
        return cur.value.id
    return None


def _g404_target(call: ast.Call) -> str | None:
    """If `call` is `get_object_or_404(Model, ...)`, return the model name."""
    func = call.func
    name: str | None = None
    if isinstance(func, ast.Name):
        name = func.id
    elif isinstance(func, ast.Attribute):
        name = func.attr
    if name not in _G404_FUNCS:
        return None
    if not call.args:
        return None
    first = call.args[0]
    if isinstance(first, ast.Name):
        return first.id
    if isinstance(first, ast.Attribute):
        return first.attr
    return None


def _g404_assignment_targets(stmt: ast.AST) -> list[str]:
    """Local variable names bound to a get_object_or_404 result in `stmt`."""
    if not isinstance(stmt, ast.Assign):
        return []
    if not isinstance(stmt.value, ast.Call):
        return []
    if _g404_target(stmt.value) is None:
        return []
    out: list[str] = []
    for tgt in stmt.targets:
        if isinstance(tgt, ast.Name):
            out.append(tgt.id)
    return out


def _function_compares_var_with_request_user(fn: ast.AST, varname: str) -> bool:
    """Detect ``<varname>.<attr> == request.user`` (or !=) anywhere in `fn`."""
    for node in ast.walk(fn):
        if not isinstance(node, ast.Compare):
            continue
        operands = [node.left, *node.comparators]
        has_var_attr = False
        has_request_user = False
        for op in operands:
            if (
                isinstance(op, ast.Attribute)
                and isinstance(op.value, ast.Name)
                and op.value.id == varname
            ):
                has_var_attr = True
            if _references_request_user(op):
                has_request_user = True
        if has_var_attr and has_request_user:
            return True
    return False


# --- public API -----------------------------------------------------------


def detect_data_accesses(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[DataAccess]:
    """Return all ORM data accesses inside the body of `fn`, in source order."""
    owner_param_names = {
        arg.arg
        for arg in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
        if arg.arg in _OWNER_PARAM_NAMES or arg.arg.endswith("_user")
    }

    # Pre-compute g404 variable names that are later validated against request.user.
    g404_validated: set[str] = set()
    for stmt in ast.walk(fn):
        for var in _g404_assignment_targets(stmt):
            if _function_compares_var_with_request_user(fn, var):
                g404_validated.add(var)

    # Collect with a (lineno, end_col_offset) sort key so that for chained
    # `.filter(...).update(...)` the inner call (smaller end column) ranks first.
    collected: list[tuple[tuple[int, int], DataAccess]] = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        sort_key = (node.lineno, node.end_col_offset or 0)

        # Path 1: <Cls>.objects.<orm_method>(...) chain.
        target = _orm_target_entity(node)
        if target is not None:
            method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
            op = _classify(method)
            if op is None:
                continue
            owned, otype = _ownership_from_kwargs(node, owner_param_names)
            collected.append(
                (
                    sort_key,
                    DataAccess(
                        operation=op,
                        target_entity=target,
                        has_ownership_predicate=owned,
                        ownership_predicate_type=otype,
                        lineno=node.lineno,
                    ),
                )
            )
            continue

        # Path 2: get_object_or_404(Model, ...).
        g_target = _g404_target(node)
        if g_target is not None:
            owned, otype = _ownership_from_kwargs(node, owner_param_names)
            if not owned:
                assigned_to = _enclosing_assignment_target(fn, node)
                if assigned_to is not None and assigned_to in g404_validated:
                    owned, otype = True, "DIRECT"
            collected.append(
                (
                    sort_key,
                    DataAccess(
                        operation="READ",
                        target_entity=g_target,
                        has_ownership_predicate=owned,
                        ownership_predicate_type=otype,
                        lineno=node.lineno,
                    ),
                )
            )

    collected.sort(key=lambda t: t[0])
    return [d for _, d in collected]


def _enclosing_assignment_target(fn: ast.AST, call: ast.Call) -> str | None:
    """Find the local Name target if `call` is the RHS of an Assign in `fn`."""
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and node.value is call:
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    return tgt.id
    return None
