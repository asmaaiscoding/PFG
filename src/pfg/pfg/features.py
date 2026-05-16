"""Feature encoding for PFG nodes and edges.

Do not reorder existing indices within a model family. The concat order is
part of the model checkpoint contract and is stored with saved checkpoints.

Node feature vector (36 dims total):
  [0:4]   node_type  one-hot {endpoint, middleware, service, data_access}
  [4:9]   http_method one-hot {GET, POST, PUT, DELETE, PATCH}, all-zero if N/A
  [9]     requires_auth binary
  [10:15] required_role one-hot {NONE, USER, MOD, ADMIN, SUPERADMIN}
  [15]    ownership_check_present binary (endpoint-level)
  [16:19] guard_type one-hot {AUTH, ROLE, OWNERSHIP}, all-zero if not a guard
  [19:23] op_type one-hot {READ, WRITE, UPDATE, DELETE}, all-zero if N/A
  [23]    has_ownership_predicate binary (data-access only)
  [24]    has_route_params binary (endpoint-level)
  [25]    reachable_data_count normalized float (min(count,5)/5)
  [26]    has_id_flow binary (endpoint has identifier_flow edges)
  [27]    unprotected_data_reachable binary (reachable data_access w/o ownership)
  [28]    role_check_present binary (endpoint-level)
  [29]    model_permission_check_present binary (endpoint-level)
  [30]    object_permission_check_present binary (endpoint-level)
  [31]    tenant_check_present binary (endpoint-level)
  [32]    has_tenant_scope binary (endpoint-level)
  [33]    unscoped_tenant_data_reachable binary (endpoint-level)
  [34]    object_permission_data_reachable binary (endpoint-level)
  [35]    data_access tenant/object guard signal:
          0.33 has_tenant_predicate, 0.66 has_object_permission_check,
          1.0 both; 0.0 otherwise

Edge feature vector (3 dims):
  [0] call
  [1] identifier_flow
  [2] tenant_flow
"""

from __future__ import annotations

from typing import Final

from pfg.pfg.nodes import (
    DataAccessAttrs,
    EdgeType,
    EndpointAttrs,
    GuardType,
    HttpMethod,
    MiddlewareAttrs,
    Node,
    NodeType,
    OperationType,
    Role,
)

NODE_FEATURE_DIM: Final[int] = 36
EDGE_FEATURE_DIM: Final[int] = 3

_NODE_TYPES: Final[tuple[str, ...]] = (
    NodeType.ENDPOINT.value,
    NodeType.MIDDLEWARE.value,
    NodeType.SERVICE.value,
    NodeType.DATA_ACCESS.value,
)
_HTTP_METHODS: Final[tuple[str, ...]] = (
    HttpMethod.GET.value,
    HttpMethod.POST.value,
    HttpMethod.PUT.value,
    HttpMethod.DELETE.value,
    HttpMethod.PATCH.value,
)
_ROLES: Final[tuple[str, ...]] = (
    Role.NONE.value,
    Role.USER.value,
    Role.MODERATOR.value,
    Role.ADMIN.value,
    Role.SUPERADMIN.value,
)
_GUARD_TYPES: Final[tuple[str, ...]] = (
    GuardType.AUTHENTICATION.value,
    GuardType.ROLE_CHECK.value,
    GuardType.OWNERSHIP_CHECK.value,
)
_OPS: Final[tuple[str, ...]] = (
    OperationType.READ.value,
    OperationType.WRITE.value,
    OperationType.UPDATE.value,
    OperationType.DELETE.value,
)


def _onehot(values: tuple[str, ...], v: str | None) -> list[float]:
    if v is None:
        return [0.0] * len(values)
    return [1.0 if x == v else 0.0 for x in values]


def encode_node(node: Node) -> list[float]:
    """Return the 36-dim feature vector for a single node."""
    feats: list[float] = []
    feats += _onehot(_NODE_TYPES, node.type)

    http_method: str | None = None
    requires_auth = 0.0
    role: str | None = None
    ownership_check_present = 0.0
    guard_type: str | None = None
    op: str | None = None
    has_ownership_predicate = 0.0

    has_route_params = 0.0
    reachable_data_count = 0.0
    has_id_flow = 0.0
    unprotected_data_reachable = 0.0
    role_check_present = 0.0
    model_permission_check_present = 0.0
    object_permission_check_present = 0.0
    tenant_check_present = 0.0
    has_tenant_scope = 0.0
    unscoped_tenant_data_reachable = 0.0
    object_permission_data_reachable = 0.0
    tenant_object_guard_signal = 0.0

    attrs = node.attrs
    if isinstance(attrs, EndpointAttrs):
        http_method = attrs.http_method if isinstance(attrs.http_method, str) else attrs.http_method.value
        requires_auth = 1.0 if attrs.requires_auth else 0.0
        role = attrs.required_role if isinstance(attrs.required_role, str) else attrs.required_role.value
        ownership_check_present = 1.0 if attrs.ownership_check_present else 0.0
        has_route_params = 1.0 if attrs.has_route_params else 0.0
        reachable_data_count = min(float(attrs.reachable_data_count), 5.0) / 5.0
        has_id_flow = 1.0 if attrs.has_id_flow else 0.0
        unprotected_data_reachable = 1.0 if attrs.unprotected_data_reachable else 0.0
        role_check_present = 1.0 if attrs.role_check_present else 0.0
        model_permission_check_present = 1.0 if attrs.model_permission_check_present else 0.0
        object_permission_check_present = 1.0 if attrs.object_permission_check_present else 0.0
        tenant_check_present = 1.0 if attrs.tenant_check_present else 0.0
        has_tenant_scope = 1.0 if attrs.has_tenant_scope else 0.0
        unscoped_tenant_data_reachable = 1.0 if attrs.unscoped_tenant_data_reachable else 0.0
        object_permission_data_reachable = 1.0 if attrs.object_permission_data_reachable else 0.0
    elif isinstance(attrs, MiddlewareAttrs):
        guard_type = attrs.guard_type if isinstance(attrs.guard_type, str) else attrs.guard_type.value
    elif isinstance(attrs, DataAccessAttrs):
        op = attrs.operation if isinstance(attrs.operation, str) else attrs.operation.value
        has_ownership_predicate = 1.0 if attrs.has_ownership_predicate else 0.0
        if attrs.has_tenant_predicate and attrs.has_object_permission_check:
            tenant_object_guard_signal = 1.0
        elif attrs.has_object_permission_check:
            tenant_object_guard_signal = 0.66
        elif attrs.has_tenant_predicate:
            tenant_object_guard_signal = 0.33

    feats += _onehot(_HTTP_METHODS, http_method)
    feats.append(requires_auth)
    feats += _onehot(_ROLES, role)
    feats.append(ownership_check_present)
    feats += _onehot(_GUARD_TYPES, guard_type)
    feats += _onehot(_OPS, op)
    feats.append(has_ownership_predicate)
    feats.append(has_route_params)
    feats.append(reachable_data_count)
    feats.append(has_id_flow)
    feats.append(unprotected_data_reachable)
    feats.append(role_check_present)
    feats.append(model_permission_check_present)
    feats.append(object_permission_check_present)
    feats.append(tenant_check_present)
    feats.append(has_tenant_scope)
    feats.append(unscoped_tenant_data_reachable)
    feats.append(object_permission_data_reachable)
    feats.append(tenant_object_guard_signal)

    assert len(feats) == NODE_FEATURE_DIM, f"node feature dim mismatch: {len(feats)}"
    return feats


def encode_edge(edge_type: str | EdgeType) -> list[float]:
    v = edge_type.value if isinstance(edge_type, EdgeType) else edge_type
    return [
        1.0 if v == EdgeType.CALL.value else 0.0,
        1.0 if v == EdgeType.IDENTIFIER_FLOW.value else 0.0,
        1.0 if v == EdgeType.TENANT_FLOW.value else 0.0,
    ]


# ---------------------------------------------------------------------------
# Derived structural feature enrichment
# ---------------------------------------------------------------------------

def enrich_endpoint_features(pfg: object) -> None:
    """Compute structural features for endpoint nodes using PFG topology.

    Must be called after PFG is fully built (all nodes + edges present).
    Mutates endpoint attrs in-place.
    """
    from pfg.pfg.graph import PFG  # local import to avoid circular

    assert isinstance(pfg, PFG)

    nodes_by_id = {n.id: n for n in pfg.nodes}

    # Build adjacency (directed, by edge type)
    call_adj: dict[str, list[str]] = {}
    id_flow_srcs: set[str] = set()
    for e in pfg.edges:
        etype = e.type.value if hasattr(e.type, "value") else e.type
        if etype == EdgeType.CALL.value:
            call_adj.setdefault(e.src, []).append(e.dst)
        elif etype == EdgeType.IDENTIFIER_FLOW.value:
            id_flow_srcs.add(e.src)

    for node in pfg.nodes:
        if not isinstance(node.attrs, EndpointAttrs):
            continue
        a = node.attrs

        # has_route_params
        a.has_route_params = bool(a.route_params)

        # has_id_flow: endpoint has outgoing identifier_flow edge
        a.has_id_flow = node.id in id_flow_srcs

        # BFS via call edges to find reachable data_access nodes
        visited: set[str] = set()
        stack = [node.id]
        reachable_da: list[DataAccessAttrs] = []
        while stack:
            nid = stack.pop()
            if nid in visited:
                continue
            visited.add(nid)
            n = nodes_by_id.get(nid)
            if n and isinstance(n.attrs, DataAccessAttrs):
                reachable_da.append(n.attrs)
            for neighbor in call_adj.get(nid, []):
                stack.append(neighbor)

        a.reachable_data_count = len(reachable_da)
        a.unprotected_data_reachable = any(
            not da.has_ownership_predicate for da in reachable_da
        )
        a.has_tenant_scope = any(
            da.requires_tenant_isolation or da.has_tenant_predicate for da in reachable_da
        )
        a.unscoped_tenant_data_reachable = any(
            da.requires_tenant_isolation and not da.has_tenant_predicate
            for da in reachable_da
        )
        a.object_permission_data_reachable = any(
            da.requires_object_permission and not da.has_object_permission_check
            for da in reachable_da
        )
