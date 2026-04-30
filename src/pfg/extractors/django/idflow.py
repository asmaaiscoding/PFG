"""Identifier flow tracker (Phase 2 W10).

Intra-procedural taint propagation from a set of *source* parameter names
through local assignments to *sink* call arguments. Designed to feed
identifier_flow edges in the PFG.

Algorithm
---------
1. Initialize the tainted set with the source names.
2. Walk the function body in source order; for each statement:
     - Assign / AugAssign / AnnAssign:
         if any source-side Name reads a tainted symbol, mark every Name
         target tainted (tuple/list unpacking is treated conservatively:
         all unpacked targets are tainted if the RHS is tainted).
3. While walking, every `Call` whose arguments contain tainted Name reads
   produces a `FlowSink` entry, recording the originating source name,
   callee dotted expression, and which argument carried the taint.

We *do not* attempt to remove taint at sanitizer boundaries in v1 — the
PFG layer can attach guard nodes downstream if needed.

Limitations (v1):
  - No SSA / control-flow merging beyond simple statement order.
  - No alias analysis through containers (lists/dicts).
  - Subscript/attribute writes do not taint the base.
  - Augmented assignment uses the LHS name as the only target.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

# --- public dataclass -----------------------------------------------------


@dataclass(frozen=True)
class FlowSink:
    """A single tainted argument site discovered in a function body."""

    source: str
    callee: str
    arg_kind: str  # "kwarg" | "positional"
    arg_name: str | None
    arg_index: int | None
    lineno: int


# --- helpers --------------------------------------------------------------


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


def _names_read(expr: ast.AST) -> set[str]:
    """All bare Name reads occurring inside `expr` (Load context)."""
    out: set[str] = set()
    for node in ast.walk(expr):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            out.add(node.id)
    return out


def _name_targets(target: ast.AST) -> list[str]:
    """Recursively collect Name ids assigned by `target` (Store context)."""
    out: list[str] = []
    if isinstance(target, ast.Name):
        out.append(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            out.extend(_name_targets(elt))
    elif isinstance(target, ast.Starred):
        out.extend(_name_targets(target.value))
    # Attribute / Subscript writes do not produce a fresh local name.
    return out


def _sources_for_expr(
    expr: ast.AST, tainted: dict[str, set[str]]
) -> set[str]:
    """Origin source names whose taint reaches `expr`."""
    reads = _names_read(expr)
    origins: set[str] = set()
    for name in reads:
        origins |= tainted.get(name, set())
    return origins


# --- public API -----------------------------------------------------------


def track_identifier_flow(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    sources: list[str],
) -> list[FlowSink]:
    """Return all flow sinks reachable from `sources` inside `fn`.

    `sources` are the names of function parameters or other in-scope
    identifiers that should be treated as initially tainted.
    """
    # Map each currently-tainted symbol to the set of original source names
    # that produced its taint (so we can attribute sinks to a source).
    tainted: dict[str, set[str]] = {s: {s} for s in sources if _has_param(fn, s)}
    sinks: list[FlowSink] = []

    for stmt in fn.body:
        _process_statement(stmt, tainted, sinks)

    sinks.sort(key=lambda s: (s.lineno, s.source, s.arg_name or "", s.arg_index or -1))
    return sinks


def _has_param(fn: ast.FunctionDef | ast.AsyncFunctionDef, name: str) -> bool:
    args = fn.args
    every = (
        list(args.posonlyargs)
        + list(args.args)
        + list(args.kwonlyargs)
        + ([args.vararg] if args.vararg else [])
        + ([args.kwarg] if args.kwarg else [])
    )
    return any(a is not None and a.arg == name for a in every)


def _process_statement(
    stmt: ast.AST,
    tainted: dict[str, set[str]],
    sinks: list[FlowSink],
) -> None:
    """Walk one statement: emit sinks for any contained Call, then propagate
    taint through assignments. Compound statements are recursed into."""
    # 1) Sinks for any Call expressions inside the statement (incl. RHS).
    for node in ast.walk(stmt):
        if isinstance(node, ast.Call):
            _emit_call_sinks(node, tainted, sinks)

    # 2) Taint propagation for assignment-like statements.
    if isinstance(stmt, ast.Assign):
        origins = _sources_for_expr(stmt.value, tainted)
        if origins:
            for target in stmt.targets:
                for name in _name_targets(target):
                    tainted[name] = tainted.get(name, set()) | origins
        else:
            # Re-bind clears taint for plain Names.
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    tainted.pop(target.id, None)
        return
    if isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
        origins = _sources_for_expr(stmt.value, tainted)
        if isinstance(stmt.target, ast.Name):
            if origins:
                tainted[stmt.target.id] = tainted.get(stmt.target.id, set()) | origins
            else:
                tainted.pop(stmt.target.id, None)
        return
    if isinstance(stmt, ast.AugAssign):
        origins = _sources_for_expr(stmt.value, tainted)
        if isinstance(stmt.target, ast.Name) and origins:
            tainted[stmt.target.id] = tainted.get(stmt.target.id, set()) | origins
        return

    # 3) Recurse into compound statements so nested statements propagate.
    for child in ast.iter_child_nodes(stmt):
        if isinstance(child, ast.AST) and _is_statement_like(child):
            _process_statement(child, tainted, sinks)
        elif isinstance(child, list):
            for sub in child:
                if isinstance(sub, ast.AST):
                    _process_statement(sub, tainted, sinks)


def _is_statement_like(node: ast.AST) -> bool:
    return isinstance(
        node,
        (
            ast.If,
            ast.For,
            ast.AsyncFor,
            ast.While,
            ast.With,
            ast.AsyncWith,
            ast.Try,
            ast.TryStar,
            ast.Assign,
            ast.AnnAssign,
            ast.AugAssign,
            ast.Expr,
            ast.Return,
            ast.Raise,
        ),
    )


def _emit_call_sinks(
    call: ast.Call,
    tainted: dict[str, set[str]],
    sinks: list[FlowSink],
) -> None:
    callee = _attr_chain(call.func)
    if callee is None:
        return
    for idx, arg in enumerate(call.args):
        if isinstance(arg, ast.Starred):
            continue
        origins = _sources_for_expr(arg, tainted)
        for src in sorted(origins):
            sinks.append(
                FlowSink(
                    source=src,
                    callee=callee,
                    arg_kind="positional",
                    arg_name=None,
                    arg_index=idx,
                    lineno=call.lineno,
                )
            )
    for kw in call.keywords:
        if kw.arg is None:
            continue
        origins = _sources_for_expr(kw.value, tainted)
        for src in sorted(origins):
            sinks.append(
                FlowSink(
                    source=src,
                    callee=callee,
                    arg_kind="kwarg",
                    arg_name=kw.arg,
                    arg_index=None,
                    lineno=call.lineno,
                )
            )
