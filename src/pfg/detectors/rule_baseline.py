"""Pure-Python rule-based detector over the PFG.

This is the mandatory baseline (Phase 1, Gate G1) that the GNN models must
beat on synthetic data. It also serves as the fallback detection path if the
GNN underperforms (Gate G3 pivot).

Rules:
  R1 MISSING_AUTH:  endpoint with requires_auth=False that reaches a
                    data-access node (excluding intentionally-public endpoints).
  R2 MISSING_ROLE:  endpoint reaches a data-access op on a privileged entity
                    (admin-only, e.g. WRITE/DELETE on shared entities) without
                    a role check that elevates the privilege level.
  R3 IDOR:          §3.3 of the paper — endpoint has a route param, an
                    identifier_flow edge connects it (transitively) to a
                    data-access node, the op is on an ownership-bearing entity,
                    and no node on any call-edge path performs an ownership
                    check (no middleware OWNERSHIP_CHECK and the data-access
                    has_ownership_predicate=False).
  R4 TENANT_ISOLATION_FAILURE:
                    tenant/workspace/org-scoped data is reachable but neither
                    the endpoint/path nor data-access node enforces tenant
                    scoping.
  R5 OBJECT_LEVEL_PERMISSION_BYPASS:
                    model-level permission evidence exists, but route-param
                    object access lacks an object-level permission check.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass

from pfg.pfg.graph import PFG
from pfg.pfg.nodes import (
    DataAccessAttrs,
    EdgeType,
    EndpointAttrs,
    GuardType,
    MiddlewareAttrs,
    Node,
    NodeType,
    OperationType,
    Role,
    VulnSubtype,
)

_TENANT_TERMS = {
    "tenant",
    "organization",
    "organisation",
    "org",
    "workspace",
    "realm",
    "project",
    "account",
}


@dataclass(frozen=True)
class Finding:
    endpoint_id: str
    subtype: VulnSubtype
    data_access_id: str | None
    explanation: str

    def to_dict(self) -> dict[str, str | None]:
        return {
            "endpoint_id": self.endpoint_id,
            "subtype": self.subtype.value,
            "data_access_id": self.data_access_id,
            "explanation": self.explanation,
        }


# -- helpers ---------------------------------------------------------------


def _reachable_via(
    pfg: PFG, start: str, edge_types: Iterable[EdgeType]
) -> set[str]:
    """All nodes reachable from start using only edges of the given type(s)."""
    types = {t.value for t in edge_types}
    seen: set[str] = {start}
    q: deque[str] = deque([start])
    while q:
        cur = q.popleft()
        for e in pfg.edges:
            if e.src == cur and e.type in types and e.dst not in seen:
                seen.add(e.dst)
                q.append(e.dst)
    return seen


def _all_paths(
    pfg: PFG, src: str, dst: str, max_depth: int = 8
) -> list[list[str]]:
    """Enumerate all simple paths from src to dst over call edges, up to depth."""
    paths: list[list[str]] = []
    call_succ: dict[str, list[str]] = {}
    for e in pfg.edges:
        if e.type == EdgeType.CALL.value:
            call_succ.setdefault(e.src, []).append(e.dst)

    def dfs(cur: str, path: list[str]) -> None:
        if len(path) > max_depth:
            return
        if cur == dst:
            paths.append(list(path))
            return
        for nxt in call_succ.get(cur, []):
            if nxt in path:  # avoid cycles
                continue
            path.append(nxt)
            dfs(nxt, path)
            path.pop()

    dfs(src, [src])
    return paths


def _path_has_ownership_check(pfg: PFG, path: list[str]) -> bool:
    idx = pfg.node_index()
    for nid in path:
        n = idx.get(nid)
        if n is None:
            continue
        if n.type == NodeType.MIDDLEWARE.value and isinstance(n.attrs, MiddlewareAttrs):
            gt = n.attrs.guard_type
            gt_v = gt.value if hasattr(gt, "value") else gt
            if gt_v == GuardType.OWNERSHIP_CHECK.value:
                return True
        if (
            n.type == NodeType.ENDPOINT.value
            and isinstance(n.attrs, EndpointAttrs)
            and n.attrs.ownership_check_present
        ):
            return True
    return False


def _path_has_guard(pfg: PFG, path: list[str], guard_type: GuardType) -> bool:
    idx = pfg.node_index()
    wanted = guard_type.value
    for nid in path:
        n = idx.get(nid)
        if n is None:
            continue
        if n.type == NodeType.MIDDLEWARE.value and isinstance(n.attrs, MiddlewareAttrs):
            gt = n.attrs.guard_type
            gt_v = gt.value if hasattr(gt, "value") else gt
            if gt_v == wanted:
                return True
    return False


def _path_has_tenant_check(pfg: PFG, path: list[str]) -> bool:
    idx = pfg.node_index()
    for nid in path:
        n = idx.get(nid)
        if n is None:
            continue
        if (
            n.type == NodeType.ENDPOINT.value
            and isinstance(n.attrs, EndpointAttrs)
            and n.attrs.tenant_check_present
        ):
            return True
        if _path_has_guard(pfg, [nid], GuardType.TENANT_CHECK):
            return True
    return False


def _path_has_object_permission_check(pfg: PFG, path: list[str]) -> bool:
    idx = pfg.node_index()
    for nid in path:
        n = idx.get(nid)
        if n is None:
            continue
        if (
            n.type == NodeType.ENDPOINT.value
            and isinstance(n.attrs, EndpointAttrs)
            and n.attrs.object_permission_check_present
        ):
            return True
        if _path_has_guard(pfg, [nid], GuardType.OBJECT_PERMISSION_CHECK):
            return True
    return False


def _looks_tenant_scoped(ep_attrs: EndpointAttrs, da_attrs: DataAccessAttrs) -> bool:
    param_and_entity = " ".join(
        [
            *ep_attrs.route_params,
            da_attrs.target_entity,
            *da_attrs.user_controlled_params_in_query,
        ]
    ).lower()
    return da_attrs.requires_tenant_isolation or any(
        term in param_and_entity for term in _TENANT_TERMS
    )


def _path_has_role_check(pfg: PFG, path: list[str], required: Role) -> bool:
    """True if the path enforces at least `required` role."""
    idx = pfg.node_index()
    role_order = {r.value: i for i, r in enumerate([Role.NONE, Role.USER, Role.MODERATOR, Role.ADMIN, Role.SUPERADMIN])}
    for nid in path:
        n = idx.get(nid)
        if n is None:
            continue
        if n.type == NodeType.MIDDLEWARE.value and isinstance(n.attrs, MiddlewareAttrs):
            gt = n.attrs.guard_type
            gt_v = gt.value if hasattr(gt, "value") else gt
            if gt_v == GuardType.ROLE_CHECK.value:
                return True
        if n.type == NodeType.ENDPOINT.value and isinstance(n.attrs, EndpointAttrs):
            ep_role = n.attrs.required_role
            ep_role_v = ep_role.value if hasattr(ep_role, "value") else ep_role
            if role_order.get(ep_role_v, 0) >= role_order.get(required.value, 0):
                return True
    return False


# -- rules -----------------------------------------------------------------


def _is_intentionally_public(ep: Node) -> bool:
    return isinstance(ep.attrs, EndpointAttrs) and ep.attrs.is_intentionally_public


def _is_admin_path(attrs: EndpointAttrs) -> bool:
    """Admin paths are protected by middleware the extractor may not detect."""
    route_lower = attrs.route.lower()
    return route_lower.startswith("/admin") or "/_util/" in route_lower


def _ep_attrs(ep: Node) -> EndpointAttrs:
    assert isinstance(ep.attrs, EndpointAttrs)
    return ep.attrs


def _da_attrs(da: Node) -> DataAccessAttrs:
    assert isinstance(da.attrs, DataAccessAttrs)
    return da.attrs


def detect_missing_auth(pfg: PFG) -> list[Finding]:
    out: list[Finding] = []
    for ep in pfg.endpoints():
        attrs = _ep_attrs(ep)
        if attrs.requires_auth or _is_intentionally_public(ep):
            continue
        if _is_admin_path(attrs):
            continue
        # reaches any data-access via call edges?
        reached = _reachable_via(pfg, ep.id, [EdgeType.CALL])
        idx = pfg.node_index()
        das = [n for n in reached if idx[n].type == NodeType.DATA_ACCESS.value]
        if not das:
            continue
        # Require stronger evidence: at least one data-access must be a mutation
        # OR access a non-trivial entity (not just serving static content).
        mutation_ops = {OperationType.WRITE.value, OperationType.UPDATE.value, OperationType.DELETE.value}
        has_mutation = any(
            isinstance(idx[n].attrs, DataAccessAttrs)
            and (idx[n].attrs.operation if isinstance(idx[n].attrs.operation, str)
                 else idx[n].attrs.operation.value) in mutation_ops
            for n in das
        )
        if not has_mutation:
            # For READ-only: only flag if route has user-controlled params or
            # the entity looks sensitive (not a framework/static resource).
            has_user_params = any(
                isinstance(idx[n].attrs, DataAccessAttrs)
                and idx[n].attrs.user_controlled_params_in_query
                for n in das
            )
            _FRAMEWORK_ROUTE_PARTS = {"media", "static", "jsi18n", "favicon", "robots"}
            route_lower = attrs.route.lower()
            is_framework = any(part in route_lower for part in _FRAMEWORK_ROUTE_PARTS)
            if is_framework and not has_user_params:
                continue
        out.append(
            Finding(
                endpoint_id=ep.id,
                subtype=VulnSubtype.MISSING_AUTH,
                data_access_id=das[0],
                explanation=(
                    f"Endpoint {attrs.route} requires no authentication but "
                    f"reaches data-access node(s): {sorted(das)}"
                ),
            )
        )
    return out


def detect_missing_role(pfg: PFG) -> list[Finding]:
    """Flag endpoints that perform privileged ops (WRITE/DELETE on shared entities)
    without a role gate of at least USER. Heuristic: any mutation reachable from
    an endpoint with required_role == NONE."""
    out: list[Finding] = []
    idx = pfg.node_index()
    privileged_ops = {OperationType.WRITE.value, OperationType.DELETE.value, OperationType.UPDATE.value}
    for ep in pfg.endpoints():
        attrs = _ep_attrs(ep)
        if _is_intentionally_public(ep) or _is_admin_path(attrs):
            continue
        ep_role = attrs.required_role
        ep_role_v = ep_role.value if hasattr(ep_role, "value") else ep_role
        if ep_role_v != Role.NONE.value or attrs.role_check_present:
            continue  # has *some* role; missing-auth rule covers requires_auth=False separately
        if not attrs.requires_auth:
            continue  # MISSING_AUTH already covers this
        reached = _reachable_via(pfg, ep.id, [EdgeType.CALL])
        for nid in reached:
            n = idx[nid]
            if n.type != NodeType.DATA_ACCESS.value:
                continue
            da = _da_attrs(n)
            op_v = da.operation if isinstance(da.operation, str) else da.operation.value
            if op_v in privileged_ops:
                out.append(
                    Finding(
                        endpoint_id=ep.id,
                        subtype=VulnSubtype.MISSING_ROLE,
                        data_access_id=nid,
                        explanation=(
                            f"Authenticated endpoint {attrs.route} performs "
                            f"{op_v} on {da.target_entity} without a role check."
                        ),
                    )
                )
                break
    return out


def detect_idor(pfg: PFG) -> list[Finding]:
    """§3.3: route param flows to a data-access on an ownership-bearing entity
    with no ownership check on the call path."""
    out: list[Finding] = []
    idx = pfg.node_index()
    mutation_ops = {OperationType.WRITE.value, OperationType.UPDATE.value, OperationType.DELETE.value}
    for ep in pfg.endpoints():
        attrs = _ep_attrs(ep)
        if _is_intentionally_public(ep) or _is_admin_path(attrs):
            continue
        if not attrs.route_params:
            continue
        # Data-access nodes consuming the route param via identifier_flow.
        flow_targets = _reachable_via(pfg, ep.id, [EdgeType.IDENTIFIER_FLOW])
        for nid in flow_targets:
            if nid == ep.id:
                continue
            n = idx[nid]
            if n.type != NodeType.DATA_ACCESS.value:
                continue
            da = _da_attrs(n)
            # Only flag mutations or READ with explicit user_controlled_params.
            op_v = da.operation if isinstance(da.operation, str) else da.operation.value
            if op_v not in mutation_ops:
                # For READ-only: require user_controlled_params AND auth
                # (unauthenticated reads without ownership are common/intentional).
                if not da.user_controlled_params_in_query:
                    continue
                if not attrs.requires_auth:
                    continue
            if _looks_tenant_scoped(attrs, da):
                continue
            if da.requires_object_permission or attrs.model_permission_check_present:
                continue
            if da.has_ownership_predicate:
                continue
            # Need a call-graph path from ep -> data_access.
            paths = _all_paths(pfg, ep.id, nid, max_depth=8)
            if not paths:
                # Identifier flow exists but no call path; still suspicious.
                out.append(
                    Finding(
                        endpoint_id=ep.id,
                        subtype=VulnSubtype.IDOR,
                        data_access_id=nid,
                        explanation=(
                            f"Route param {attrs.route_params} of {attrs.route} flows to "
                            f"{da.operation} on {da.target_entity} with no ownership predicate."
                        ),
                    )
                )
                continue
            # IDOR if NO path has an ownership check.
            if not any(_path_has_ownership_check(pfg, p) for p in paths):
                out.append(
                    Finding(
                        endpoint_id=ep.id,
                        subtype=VulnSubtype.IDOR,
                        data_access_id=nid,
                        explanation=(
                            f"Route param {attrs.route_params} of {attrs.route} reaches "
                            f"{da.operation} on {da.target_entity} via "
                            f"{len(paths)} call path(s); none enforce ownership."
                        ),
                    )
                )
    return out


def detect_tenant_isolation_failure(pfg: PFG) -> list[Finding]:
    """Tenant/org/workspace-scoped data reachable without tenant scoping."""
    out: list[Finding] = []
    idx = pfg.node_index()
    for ep in pfg.endpoints():
        attrs = _ep_attrs(ep)
        if _is_intentionally_public(ep) or _is_admin_path(attrs) or attrs.tenant_check_present:
            continue
        reached = _reachable_via(pfg, ep.id, [EdgeType.CALL])
        for nid in reached:
            n = idx[nid]
            if n.type != NodeType.DATA_ACCESS.value:
                continue
            da = _da_attrs(n)
            # Require explicit tenant isolation flag — keyword matching alone
            # produces too many false positives.
            if not da.requires_tenant_isolation:
                continue
            if da.has_tenant_predicate:
                continue
            paths = _all_paths(pfg, ep.id, nid, max_depth=8)
            if paths and any(_path_has_tenant_check(pfg, p) for p in paths):
                continue
            out.append(
                Finding(
                    endpoint_id=ep.id,
                    subtype=VulnSubtype.TENANT_ISOLATION_FAILURE,
                    data_access_id=nid,
                    explanation=(
                        f"Endpoint {attrs.route} reaches tenant-scoped "
                        f"{da.target_entity} without a tenant predicate."
                    ),
                )
            )
            break
    return out


def detect_object_level_permission_bypass(pfg: PFG) -> list[Finding]:
    """Model-level permission is present but object-level authorization is absent."""
    out: list[Finding] = []
    idx = pfg.node_index()
    for ep in pfg.endpoints():
        attrs = _ep_attrs(ep)
        if _is_intentionally_public(ep) or _is_admin_path(attrs):
            continue
        if not attrs.route_params or not attrs.model_permission_check_present:
            continue
        if attrs.object_permission_check_present:
            continue
        flow_targets = _reachable_via(pfg, ep.id, [EdgeType.IDENTIFIER_FLOW])
        for nid in flow_targets:
            if nid == ep.id:
                continue
            n = idx[nid]
            if n.type != NodeType.DATA_ACCESS.value:
                continue
            da = _da_attrs(n)
            if _looks_tenant_scoped(attrs, da):
                continue
            if da.has_object_permission_check or da.has_ownership_predicate:
                continue
            paths = _all_paths(pfg, ep.id, nid, max_depth=8)
            if paths and any(_path_has_object_permission_check(pfg, p) for p in paths):
                continue
            if not da.requires_object_permission and not attrs.model_permission_check_present:
                continue
            out.append(
                Finding(
                    endpoint_id=ep.id,
                    subtype=VulnSubtype.OBJECT_LEVEL_PERMISSION_BYPASS,
                    data_access_id=nid,
                    explanation=(
                        f"Endpoint {attrs.route} has model-level permission evidence "
                        f"but route param {attrs.route_params} reaches {da.target_entity} "
                        "without object-level permission enforcement."
                    ),
                )
            )
            break
    return out


def detect_all(pfg: PFG) -> list[Finding]:
    """Run all rules; return findings deduplicated by (endpoint_id, subtype)."""
    found: dict[tuple[str, str], Finding] = {}
    for f in (
        *detect_missing_auth(pfg),
        *detect_missing_role(pfg),
        *detect_idor(pfg),
        *detect_tenant_isolation_failure(pfg),
        *detect_object_level_permission_bypass(pfg),
    ):
        key = (f.endpoint_id, f.subtype.value)
        found.setdefault(key, f)
    return list(found.values())
