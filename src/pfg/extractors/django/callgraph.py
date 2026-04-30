"""Django call graph extractor (Phase 2 W7-W8).

AST-based intra-project call graph construction. Starting from each handler
qualname, recursively resolve calls within the project and produce edges.

Resolution strategy (best-effort, intra-procedural, no full type inference):

  1. Build a per-module alias map from imports:
        from . import services         -> "services" -> "<pkg>.services"
        from .services import fetch    -> "fetch"    -> "<pkg>.services.fetch"
        from app import mod as m       -> "m"        -> "app.mod"
  2. For each function or method body, walk all `ast.Call` nodes.
  3. For each call expression `Foo.bar()` or `mod.fn()` or `fn()`:
       - peel an outer `.attr` chain to `(head, attrs...)`
       - if `head` resolves via the alias map, expand it
       - the resulting qualname is the callee
     Class instantiations followed by a method call (`Service().run()`) are
     NOT chased (out of scope for v1).
  4. Edges are kept only if the callee qualname maps to a function/method
     defined inside the project (i.e. the file exists and the symbol is found).

Depth is bounded by `max_depth` (default 8) measured in transitive call levels
from the seed handler.

Out-of-scope for v1: dynamic dispatch via instance variables, decorators that
wrap callees, `getattr`-based calls, calls through containers/lambdas.
"""

from __future__ import annotations

import ast
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

# --- module cache ---------------------------------------------------------


@dataclass
class _Module:
    dotted: str
    path: Path
    tree: ast.Module
    aliases: dict[str, str] = field(default_factory=dict)


def _module_dotted(project_root: Path, file_path: Path) -> str:
    rel = file_path.resolve().relative_to(project_root.resolve())
    parts = list(rel.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _resolve_relative(current_pkg: str, module: str | None, level: int) -> str:
    if level == 0:
        return module or ""
    base = current_pkg.split(".")
    base = base[:-level] if level <= len(base) else []
    if module:
        base = base + module.split(".")
    return ".".join(base)


def _build_aliases(tree: ast.Module, current_pkg: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.ImportFrom):
            src = _resolve_relative(current_pkg, stmt.module, stmt.level)
            for alias in stmt.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                aliases[local] = f"{src}.{alias.name}" if src else alias.name
        elif isinstance(stmt, ast.Import):
            for alias in stmt.names:
                local = alias.asname or alias.name.split(".")[0]
                target = (alias.asname and alias.name) or alias.name
                aliases[local] = target
    return aliases


class _ProjectIndex:
    """Lazy parser+cache for project modules."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self._modules: dict[str, _Module] = {}
        self._symbol_cache: dict[str, bool] = {}

    def get(self, dotted: str) -> _Module | None:
        if not dotted:
            return None
        if dotted in self._modules:
            return self._modules[dotted]
        rel = Path(*dotted.split("."))
        for cand in (self.root / rel.with_suffix(".py"), self.root / rel / "__init__.py"):
            if cand.exists():
                try:
                    tree = ast.parse(cand.read_text(encoding="utf-8"), filename=str(cand))
                except SyntaxError:
                    return None
                if not isinstance(tree, ast.Module):
                    return None
                cur_pkg = _module_dotted(self.root, cand)
                m = _Module(dotted=cur_pkg, path=cand, tree=tree, aliases=_build_aliases(tree, cur_pkg))
                self._modules[cur_pkg] = m
                if cur_pkg != dotted:
                    self._modules[dotted] = m
                return m
        return None

    def resolve_qualname(self, qual: str) -> tuple[_Module, ast.AST] | None:
        """Return (module, node) for a function/method qualname inside the project."""
        parts = qual.split(".")
        # Try every prefix as a module path; the remainder must be a class+method or function.
        for i in range(len(parts) - 1, 0, -1):
            mod = self.get(".".join(parts[:i]))
            if mod is None:
                continue
            rest = parts[i:]
            if len(rest) == 1:
                fn = _find_function(mod.tree, rest[0])
                if fn is not None:
                    return mod, fn
            elif len(rest) == 2:
                cls = _find_class(mod.tree, rest[0])
                if cls is None:
                    continue
                for body in cls.body:
                    if isinstance(body, (ast.FunctionDef, ast.AsyncFunctionDef)) and body.name == rest[1]:
                        return mod, body
        return None

    def is_project_qualname(self, qual: str) -> bool:
        if qual in self._symbol_cache:
            return self._symbol_cache[qual]
        result = self.resolve_qualname(qual) is not None
        self._symbol_cache[qual] = result
        return result


# --- AST helpers ----------------------------------------------------------


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


def _resolve_call(call: ast.Call, mod: _Module) -> str | None:
    """Map a call expression to a candidate dotted qualname (or None)."""
    chain = _attr_chain(call.func)
    if chain is None:
        return None
    head, *rest = chain
    if head in mod.aliases:
        base = mod.aliases[head]
        return ".".join([base, *rest]) if rest else base
    if not rest:
        # Bare name — could be a function in the same module.
        return f"{mod.dotted}.{head}" if mod.dotted else head
    # Unaliased dotted: assume a module accessible by that prefix.
    return ".".join(chain)


# --- public API -----------------------------------------------------------


@dataclass(frozen=True)
class CallEdge:
    caller: str
    callee: str


def build_call_graph(
    project_root: str | Path,
    seeds: list[str],
    *,
    max_depth: int = 8,
) -> list[CallEdge]:
    """Return all intra-project call edges reachable from seed qualnames.

    Each seed is a function/method qualname (e.g. `views.get_invoice` or
    `app.views.PostDetail.get`) relative to `project_root`.
    """
    index = _ProjectIndex(Path(project_root).resolve())
    edges: set[tuple[str, str]] = set()
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque((s, 0) for s in seeds)

    while queue:
        qual, depth = queue.popleft()
        if qual in visited:
            continue
        visited.add(qual)
        if depth >= max_depth:
            continue
        resolved = index.resolve_qualname(qual)
        if resolved is None:
            continue
        mod, fn_node = resolved
        for call in ast.walk(fn_node):
            if not isinstance(call, ast.Call):
                continue
            callee_qual = _resolve_call(call, mod)
            if callee_qual is None:
                continue
            if not index.is_project_qualname(callee_qual):
                continue
            edge = (qual, callee_qual)
            if edge in edges:
                continue
            edges.add(edge)
            queue.append((callee_qual, depth + 1))

    return [CallEdge(c, e) for c, e in sorted(edges)]
