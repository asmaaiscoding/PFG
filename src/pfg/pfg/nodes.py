"""Pydantic models for PFG nodes, edges, labels.

Mirrors `schemas/pfg-1.0.json`. Schema is the source of truth; these models
exist for ergonomic Python access and runtime validation.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

# --- enums --------------------------------------------------------------


class NodeType(StrEnum):
    ENDPOINT = "endpoint"
    MIDDLEWARE = "middleware"
    SERVICE = "service"
    DATA_ACCESS = "data_access"


class HttpMethod(StrEnum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"


class Role(StrEnum):
    NONE = "NONE"
    USER = "USER"
    MODERATOR = "MODERATOR"
    ADMIN = "ADMIN"
    SUPERADMIN = "SUPERADMIN"


class GuardType(StrEnum):
    AUTHENTICATION = "AUTHENTICATION"
    ROLE_CHECK = "ROLE_CHECK"
    OWNERSHIP_CHECK = "OWNERSHIP_CHECK"
    TENANT_CHECK = "TENANT_CHECK"
    OBJECT_PERMISSION_CHECK = "OBJECT_PERMISSION_CHECK"


class GuardPosition(StrEnum):
    BEFORE_HANDLER = "BEFORE_HANDLER"
    INLINE = "INLINE"


class OperationType(StrEnum):
    READ = "READ"
    WRITE = "WRITE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"


class OwnershipPredicateType(StrEnum):
    DIRECT = "DIRECT"
    INDIRECT = "INDIRECT"
    NONE = "NONE"


class EdgeType(StrEnum):
    CALL = "call"
    IDENTIFIER_FLOW = "identifier_flow"
    TENANT_FLOW = "tenant_flow"


class LabelKind(StrEnum):
    SAFE = "SAFE"
    VULNERABLE = "VULNERABLE"
    INTENTIONALLY_PUBLIC = "INTENTIONALLY_PUBLIC"


class VulnSubtype(StrEnum):
    MISSING_AUTH = "MISSING_AUTH"
    MISSING_ROLE = "MISSING_ROLE"
    IDOR = "IDOR"
    TENANT_ISOLATION_FAILURE = "TENANT_ISOLATION_FAILURE"
    OBJECT_LEVEL_PERMISSION_BYPASS = "OBJECT_LEVEL_PERMISSION_BYPASS"
    COMBINED = "COMBINED"


# --- attribute models ---------------------------------------------------


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)


class EndpointAttrs(_Base):
    http_method: HttpMethod
    route: str
    route_params: list[str] = Field(default_factory=list)
    requires_auth: bool
    required_role: Role
    ownership_check_present: bool = False
    role_check_present: bool = False
    model_permission_check_present: bool = False
    object_permission_check_present: bool = False
    tenant_check_present: bool = False
    is_intentionally_public: bool = False
    source_location: str | None = None
    # Derived structural features (computed post-build via enrich_endpoint_features).
    has_route_params: bool = False
    reachable_data_count: int = 0
    has_id_flow: bool = False
    unprotected_data_reachable: bool = False
    has_tenant_scope: bool = False
    unscoped_tenant_data_reachable: bool = False
    object_permission_data_reachable: bool = False


class MiddlewareAttrs(_Base):
    guard_type: GuardType
    condition: str | None = None
    position: GuardPosition | None = None
    source_location: str | None = None


class ServiceAttrs(_Base):
    name: str | None = None
    inherited_privilege: Role | None = None
    performs_data_access: bool = False
    performs_mutation: bool = False
    source_location: str | None = None


class DataAccessAttrs(_Base):
    operation: OperationType
    target_entity: str
    has_ownership_predicate: bool
    ownership_predicate_type: OwnershipPredicateType = OwnershipPredicateType.NONE
    has_tenant_predicate: bool = False
    requires_tenant_isolation: bool = False
    requires_object_permission: bool = False
    has_object_permission_check: bool = False
    user_controlled_params_in_query: list[str] = Field(default_factory=list)
    source_location: str | None = None


# --- node / edge / label ------------------------------------------------


class _NodeBase(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)
    id: str
    type: NodeType


class EndpointNode(_NodeBase):
    type: Literal[NodeType.ENDPOINT] = NodeType.ENDPOINT
    attrs: EndpointAttrs


class MiddlewareNode(_NodeBase):
    type: Literal[NodeType.MIDDLEWARE] = NodeType.MIDDLEWARE
    attrs: MiddlewareAttrs


class ServiceNode(_NodeBase):
    type: Literal[NodeType.SERVICE] = NodeType.SERVICE
    attrs: ServiceAttrs


class DataAccessNode(_NodeBase):
    type: Literal[NodeType.DATA_ACCESS] = NodeType.DATA_ACCESS
    attrs: DataAccessAttrs


Node = Annotated[
    EndpointNode | MiddlewareNode | ServiceNode | DataAccessNode,
    Field(discriminator="type"),
]


class Edge(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)
    src: str
    dst: str
    type: EdgeType
    param: str | None = None


class Label(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)
    label: LabelKind
    subtype: VulnSubtype | None = None
    cwe: str | None = None
    notes: str | None = None
