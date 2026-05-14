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


def _class_get_queryset_uses_user(tree: ast.AST, class_name: str) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or node.name != class_name:
            continue
        for body in node.body:
            if (
                isinstance(body, (ast.FunctionDef, ast.AsyncFunctionDef))
                and body.name == "get_queryset"
                and _function_references_request_user(body)
            ):
                return True
    return False


def _handler_ownership_check_present(project_root: Path, qual: str) -> bool:
    resolved = _resolve_function(project_root, qual)
    if resolved is None:
        return False
    tree, fn = resolved
    if _function_calls_self_get_object(fn):
        return True
    parts = qual.split(".")
    if len(parts) >= 3:
        class_name = parts[-2]
        if _class_get_queryset_uses_user(tree, class_name) and _function_calls_self_get_object(fn):
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
            add_node(
                {
                    "id": did,
                    "type": "data_access",
                    "attrs": {
                        "operation": da.operation,
                        "target_entity": da.target_entity,
                        "has_ownership_predicate": da.has_ownership_predicate,
                        "ownership_predicate_type": da.ownership_predicate_type,
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
