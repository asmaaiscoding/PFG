"""Pure-Python rule-based detector over the PFG.

This is the mandatory baseline (Phase 1, Gate G1) that the GNN models must
beat on synthetic data. It also serves as the fallback detection path if the
GNN underperforms (Gate G3 pivot).

Three rules:
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
        # reaches any data-access via call edges?
        reached = _reachable_via(pfg, ep.id, [EdgeType.CALL])
        idx = pfg.node_index()
        das = [n for n in reached if idx[n].type == NodeType.DATA_ACCESS.value]
        if das:
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
        if _is_intentionally_public(ep):
            continue
        ep_role = attrs.required_role
        ep_role_v = ep_role.value if hasattr(ep_role, "value") else ep_role
        if ep_role_v != Role.NONE.value:
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
    for ep in pfg.endpoints():
        attrs = _ep_attrs(ep)
        if _is_intentionally_public(ep):
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


def detect_all(pfg: PFG) -> list[Finding]:
    """Run all rules; return findings deduplicated by (endpoint_id, subtype)."""
    found: dict[tuple[str, str], Finding] = {}
    for f in (*detect_missing_auth(pfg), *detect_missing_role(pfg), *detect_idor(pfg)):
        key = (f.endpoint_id, f.subtype.value)
        found.setdefault(key, f)
    return list(found.values())
