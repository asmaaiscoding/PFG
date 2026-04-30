"""Frozen feature encoding for PFG nodes and edges.

DO NOT REORDER. The concat order is part of the model checkpoint contract.

Node feature vector (24 dims total):
  [0:4]   node_type  one-hot {endpoint, middleware, service, data_access}
  [4:9]   http_method one-hot {GET, POST, PUT, DELETE, PATCH}, all-zero if N/A
  [9]     requires_auth binary
  [10:15] required_role one-hot {NONE, USER, MOD, ADMIN, SUPERADMIN}
  [15]    ownership_check_present binary (endpoint-level)
  [16:19] guard_type one-hot {AUTH, ROLE, OWNERSHIP}, all-zero if not a guard
  [19:23] op_type one-hot {READ, WRITE, UPDATE, DELETE}, all-zero if N/A
  [23]    has_ownership_predicate binary (data-access only)

Edge feature vector (2 dims):
  [0] call
  [1] identifier_flow
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

NODE_FEATURE_DIM: Final[int] = 24
EDGE_FEATURE_DIM: Final[int] = 2

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
    """Return the 24-dim feature vector for a single node."""
    feats: list[float] = []
    feats += _onehot(_NODE_TYPES, node.type)

    http_method: str | None = None
    requires_auth = 0.0
    role: str | None = None
    ownership_check_present = 0.0
    guard_type: str | None = None
    op: str | None = None
    has_ownership_predicate = 0.0

    attrs = node.attrs
    if isinstance(attrs, EndpointAttrs):
        http_method = attrs.http_method if isinstance(attrs.http_method, str) else attrs.http_method.value
        requires_auth = 1.0 if attrs.requires_auth else 0.0
        role = attrs.required_role if isinstance(attrs.required_role, str) else attrs.required_role.value
        ownership_check_present = 1.0 if attrs.ownership_check_present else 0.0
    elif isinstance(attrs, MiddlewareAttrs):
        guard_type = attrs.guard_type if isinstance(attrs.guard_type, str) else attrs.guard_type.value
    elif isinstance(attrs, DataAccessAttrs):
        op = attrs.operation if isinstance(attrs.operation, str) else attrs.operation.value
        has_ownership_predicate = 1.0 if attrs.has_ownership_predicate else 0.0

    feats += _onehot(_HTTP_METHODS, http_method)
    feats.append(requires_auth)
    feats += _onehot(_ROLES, role)
    feats.append(ownership_check_present)
    feats += _onehot(_GUARD_TYPES, guard_type)
    feats += _onehot(_OPS, op)
    feats.append(has_ownership_predicate)

    assert len(feats) == NODE_FEATURE_DIM, f"node feature dim mismatch: {len(feats)}"
    return feats


def encode_edge(edge_type: str | EdgeType) -> list[float]:
    v = edge_type.value if isinstance(edge_type, EdgeType) else edge_type
    return [
        1.0 if v == EdgeType.CALL.value else 0.0,
        1.0 if v == EdgeType.IDENTIFIER_FLOW.value else 0.0,
    ]
