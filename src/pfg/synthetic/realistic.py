"""Realistic synthetic PFG generator for pure-synthetic training.

Generates full mini-app PFGs that mimic the topology of real Django apps
extracted by ``pfg.extractors.django.build``:

  * 30-80 endpoints per app sharing a pool of services and data-access nodes
  * Shared service chains of depth 1-4 (endpoint → handler → repo → ORM)
  * Middleware guard nodes on protected paths
  * identifier_flow edges from route-param endpoints to data-access leaves
  * Configurable vulnerability density (~30-40% of endpoints)

Each app is converted to N samples (one per endpoint) exactly like
``pfg.training.corpus.samples_from_pfg`` does for real data.
"""

from __future__ import annotations

import random
from typing import Any

from pfg.pfg.graph import PFG
from pfg.pfg.nodes import Label, LabelKind, VulnSubtype
from pfg.synthetic.generator import Sample

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
_READ_METHODS = ("GET",)
_WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
_ENTITIES = (
    "User", "Invoice", "Order", "Comment", "Post", "Document",
    "Booking", "Product", "Payment", "Ticket", "Report", "Session",
    "Profile", "Notification", "Message", "Setting", "Token", "Log",
)
_PARAM_NAMES = ("pk", "id", "slug", "uid", "uuid", "obj_id")
_TENANT_PARAM_NAMES = ("workspace_slug", "organization_id", "tenant_id", "project_id", "realm_id")
_OPERATIONS_READ = ("READ",)
_OPERATIONS_WRITE = ("WRITE", "UPDATE", "DELETE")
_ROLES = ("NONE", "USER", "ADMIN")
_ROUTE_PREFIXES = (
    "api/v1", "api/v2", "api", "app", "v1", "v2", "admin/api",
)
_ROUTE_SEGMENTS = (
    "users", "invoices", "orders", "comments", "posts", "documents",
    "bookings", "products", "payments", "tickets", "reports", "sessions",
    "profiles", "notifications", "messages", "settings", "tokens", "logs",
)
_PUBLIC_ROUTES = (
    "/health/", "/healthz/", "/ping/", "/login/", "/logout/",
    "/auth/login/", "/auth/logout/", "/public/docs/", "/public/static/",
)


def _sid(s: str) -> str:
    """Schema-safe identifier."""
    out = "".join(c if c.isalnum() else "_" for c in s)
    if not out or not (out[0].isalpha() or out[0] == "_"):
        out = "_" + out
    return out


# ---------------------------------------------------------------------------
# Mini-app builder
# ---------------------------------------------------------------------------


class _AppBuilder:
    """Builds a single synthetic app PFG with labelled endpoints."""

    def __init__(
        self,
        rng: random.Random,
        app_idx: int,
        n_endpoints: int,
        vuln_ratio: float,
    ):
        self.rng = rng
        self.app_idx = app_idx
        self.app_name = f"synthetic_app_{app_idx}"
        self.n_endpoints = n_endpoints
        self.vuln_ratio = vuln_ratio

        self.nodes: list[dict[str, Any]] = []
        self.edges: list[dict[str, Any]] = []
        self.seen_ids: set[str] = set()
        self.seen_edges: set[tuple[str, str, str]] = set()

        # Label storage: endpoint_id -> Label
        self.labels: dict[str, Label] = {}

        # Shared pools
        self._service_pool: list[str] = []
        self._data_pool: list[tuple[str, str]] = []  # (data_id, entity)

    def _add_node(self, node: dict[str, Any]) -> None:
        if node["id"] not in self.seen_ids:
            self.seen_ids.add(node["id"])
            self.nodes.append(node)

    def _add_edge(self, src: str, dst: str, etype: str, param: str | None = None) -> None:
        key = (src, dst, etype)
        if key not in self.seen_edges:
            self.seen_edges.add(key)
            e: dict[str, Any] = {"src": src, "dst": dst, "type": etype}
            if param is not None:
                e["param"] = param
            self.edges.append(e)

    # --- shared infrastructure ---

    def _build_service_pool(self) -> None:
        """Create shared services (handlers, repos) that endpoints route through."""
        n_services = self.rng.randint(8, max(10, self.n_endpoints // 3))
        for i in range(n_services):
            layer = self.rng.choice(["handler", "service", "repo", "utils", "manager"])
            entity = self.rng.choice(_ENTITIES)
            name = f"{entity.lower()}_{layer}_{i}"
            sid = _sid(f"service__{self.app_name}__{name}")
            is_da = layer == "repo"
            is_mut = layer == "repo" and self.rng.random() < 0.5
            self._add_node({
                "id": sid,
                "type": "service",
                "attrs": {
                    "name": f"{self.app_name}.{name}",
                    "performs_data_access": is_da,
                    "performs_mutation": is_mut,
                },
            })
            self._service_pool.append(sid)

    def _build_data_pool(self) -> None:
        """Create shared data-access nodes."""
        n_data = self.rng.randint(6, max(8, self.n_endpoints // 4))
        for i in range(n_data):
            entity = self.rng.choice(_ENTITIES)
            op = self.rng.choice(["READ", "WRITE", "UPDATE", "DELETE"])
            did = _sid(f"data__{self.app_name}__{entity}__op{i}")
            self._add_node({
                "id": did,
                "type": "data_access",
                "attrs": {
                    "operation": op,
                    "target_entity": entity,
                    "has_ownership_predicate": False,  # default; may be overwritten
                    "ownership_predicate_type": "NONE",
                    "user_controlled_params_in_query": [],
                },
            })
            self._data_pool.append((did, entity))

        # Wire some repo-layer services to data nodes
        repo_services = [s for s in self._service_pool if "repo" in s]
        for rsid in repo_services:
            # Each repo connects to 1-3 data nodes
            targets = self.rng.sample(
                self._data_pool, k=min(self.rng.randint(1, 3), len(self._data_pool))
            )
            for did, _ in targets:
                self._add_edge(rsid, did, "call")

        # Wire some services to other services (handler → service → repo chain)
        non_repo = [s for s in self._service_pool if "repo" not in s]
        for sid in non_repo:
            # Chain to a repo service
            if repo_services and self.rng.random() < 0.7:
                target = self.rng.choice(repo_services)
                self._add_edge(sid, target, "call")

    def _pick_service_chain(self) -> list[str]:
        """Pick a chain of 1-3 services from the pool."""
        depth = self.rng.randint(1, min(3, len(self._service_pool)))
        return self.rng.sample(self._service_pool, k=depth)

    def _reachable_data(self, start_services: list[str]) -> list[str]:
        """Find data-access nodes reachable from a set of services via call edges."""
        succ: dict[str, list[str]] = {}
        for e in self.edges:
            if e["type"] == "call":
                succ.setdefault(e["src"], []).append(e["dst"])
        data_ids = {d[0] for d in self._data_pool}
        seen: set[str] = set()
        stack = list(start_services)
        result: list[str] = []
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            if cur in data_ids:
                result.append(cur)
            for nxt in succ.get(cur, []):
                stack.append(nxt)
        return result

    # --- endpoint generation ---

    def _gen_route(self, idx: int, with_param: bool) -> tuple[str, list[str]]:
        prefix = self.rng.choice(_ROUTE_PREFIXES)
        seg = self.rng.choice(_ROUTE_SEGMENTS)
        if with_param:
            param = self.rng.choice(_PARAM_NAMES)
            return f"/{prefix}/{seg}/{{{param}}}/", [param]
        return f"/{prefix}/{seg}/", []

    def _gen_tenant_route(self, idx: int) -> tuple[str, list[str]]:
        prefix = self.rng.choice(_ROUTE_PREFIXES)
        seg = self.rng.choice(["workspaces", "organizations", "tenants", "projects", "realms"])
        child = self.rng.choice(_ROUTE_SEGMENTS)
        param = self.rng.choice(_TENANT_PARAM_NAMES)
        return f"/{prefix}/{seg}/{{{param}}}/{child}/", [param]

    def _make_endpoint(
        self,
        idx: int,
        *,
        vuln_type: str | None,
    ) -> None:
        """Create one endpoint with its service chain and label."""
        rng = self.rng

        # Decide topology
        with_param = vuln_type in (
            "IDOR",
            "TENANT_ISOLATION_FAILURE",
            "OBJECT_LEVEL_PERMISSION_BYPASS",
            "COMBINED",
        ) or (
            vuln_type is None and rng.random() < 0.3
        )
        method = rng.choice(_WRITE_METHODS if vuln_type in ("MISSING_ROLE", "COMBINED") else _HTTP_METHODS)
        route, params = self._gen_route(idx, with_param)

        # Auth features depend on vuln type
        if vuln_type == "MISSING_AUTH":
            requires_auth = False
            role = "NONE"
            is_public = False
            ownership_check = False
        elif vuln_type == "MISSING_ROLE":
            requires_auth = True
            role = "NONE"  # should have a role but doesn't
            is_public = False
            ownership_check = False
        elif vuln_type == "IDOR":
            requires_auth = True
            # IDOR typically occurs in authenticated endpoints that DO have
            # role/auth checks but LACK ownership checks. Bias toward having
            # a role_check to match real-world patterns (e.g. wger ViewSets
            # with IsAuthenticated but no get_object() override).
            role = rng.choice(["USER", "USER", "USER", "ADMIN", "NONE"])
            is_public = False
            ownership_check = False  # key: no ownership check
        elif vuln_type == "TENANT_ISOLATION_FAILURE":
            route, params = self._gen_tenant_route(idx)
            requires_auth = True
            role = "USER"
            is_public = False
            ownership_check = True
            # Variant: some TENANT vulns DON'T use tenant routes but access
            # tenant-scoped data via generic API endpoints (like weblate/sentry)
            if rng.random() < 0.4:
                route, params = self._gen_route(idx, True)  # generic route with pk
                ownership_check = False
        elif vuln_type == "OBJECT_LEVEL_PERMISSION_BYPASS":
            requires_auth = True
            role = "USER"
            is_public = False
            ownership_check = False
        elif vuln_type == "COMBINED":
            requires_auth = False
            role = "NONE"
            is_public = False
            ownership_check = False
        else:
            # SAFE — several sub-patterns
            safe_variant = rng.choice([
                "auth_with_ownership",   # fully protected
                "auth_no_data",          # auth but no data access
                "public_route",          # intentionally public
                "auth_role",             # has role requirement
                "auth_basic",            # basic auth, no params
                "auth_with_params",      # has params + ownership (hard negative for IDOR)
            ])
            if safe_variant == "public_route":
                route = rng.choice(_PUBLIC_ROUTES)
                params = []
                with_param = False
                requires_auth = False
                role = "NONE"
                is_public = True
                ownership_check = False
            elif safe_variant in ("auth_with_ownership", "auth_with_params"):
                requires_auth = True
                role = rng.choice(["USER", "ADMIN"])
                is_public = False
                ownership_check = True
                with_param = True
                if not params:
                    route, params = self._gen_route(idx, True)
            elif safe_variant == "auth_no_data":
                requires_auth = True
                role = rng.choice(["USER", "ADMIN"])
                is_public = False
                ownership_check = False
            elif safe_variant == "auth_role":
                requires_auth = True
                role = rng.choice(["ADMIN", "MODERATOR"])
                is_public = False
                ownership_check = False
            else:  # auth_basic
                requires_auth = True
                role = rng.choice(["NONE", "USER"])
                is_public = False
                ownership_check = False

        eid = _sid(f"endpoint__{method}__{route}__{self.app_name}_{idx}")
        self._add_node({
            "id": eid,
            "type": "endpoint",
            "attrs": {
                "http_method": method,
                "route": route,
                "route_params": params,
                "requires_auth": requires_auth,
                "required_role": role,
                "ownership_check_present": ownership_check,
                "role_check_present": role != "NONE",
                "model_permission_check_present": vuln_type == "OBJECT_LEVEL_PERMISSION_BYPASS",
                "object_permission_check_present": False,
                "tenant_check_present": False,
                "is_intentionally_public": is_public,
            },
        })

        # Service chain — IDOR/COMBINED use a private chain to avoid
        # inheriting tenant/object-permission signals from shared data nodes.
        if vuln_type in ("IDOR", "COMBINED"):
            # Create a private 2-service chain for IDOR isolation
            handler_sid = _sid(f"service__handler__{self.app_name}_{idx}")
            repo_sid = _sid(f"service__repo__{self.app_name}_{idx}")
            self._add_node({"id": handler_sid, "type": "service", "attrs": {"name": f"handler_{idx}"}})
            self._add_node({"id": repo_sid, "type": "service", "attrs": {"name": f"repo_{idx}"}})
            self._add_edge(eid, handler_sid, "call")
            self._add_edge(handler_sid, repo_sid, "call")
            chain = [handler_sid, repo_sid]
            reachable_data = []  # will be populated by dedicated node below
        else:
            chain = self._pick_service_chain()
            if chain:
                self._add_edge(eid, chain[0], "call")
                for i in range(len(chain) - 1):
                    self._add_edge(chain[i], chain[i + 1], "call")
            # Find reachable data-access nodes
            reachable_data = self._reachable_data(chain)
        # For vulns that need data access, ensure we have some
        # (skip IDOR/COMBINED — they create dedicated isolated nodes below)
        if vuln_type in (
            "MISSING_AUTH",
            "MISSING_ROLE",
            "TENANT_ISOLATION_FAILURE",
            "OBJECT_LEVEL_PERMISSION_BYPASS",
        ) and not reachable_data and self._data_pool and chain:
            did, _ = rng.choice(self._data_pool)
            self._add_edge(chain[-1], did, "call")
            reachable_data = [did]

        # IDOR-style vulnerable flows: route identifier reaches data without
        # the subtype-specific guard.
        if vuln_type in ("IDOR", "COMBINED") and params:
            # For pure IDOR/COMBINED, use a dedicated data node to avoid
            # shared-pool contamination (safe endpoints may later overwrite
            # has_ownership_predicate on shared nodes).
            entity = rng.choice(_ENTITIES)
            op = rng.choice(["READ", "WRITE", "UPDATE", "DELETE"])
            dedicated_did = _sid(f"data__{self.app_name}__idor_{entity}__ep{idx}")
            self._add_node({
                "id": dedicated_did,
                "type": "data_access",
                "attrs": {
                    "operation": op,
                    "target_entity": entity,
                    "has_ownership_predicate": False,
                    "ownership_predicate_type": "NONE",
                    "user_controlled_params_in_query": [params[0]],
                },
            })
            # Wire into service chain so it's reachable via call edges
            if chain:
                self._add_edge(chain[-1], dedicated_did, "call")
            else:
                self._add_edge(eid, dedicated_did, "call")
            self._add_edge(eid, dedicated_did, "identifier_flow", param=params[0])
        elif vuln_type in (
            "TENANT_ISOLATION_FAILURE",
            "OBJECT_LEVEL_PERMISSION_BYPASS",
        ) and params:
            # Create dedicated data node if no reachable_data exists
            if not reachable_data:
                tenant_entities = ["Organization", "Workspace", "Tenant", "Project"]
                entity = rng.choice(tenant_entities) if vuln_type == "TENANT_ISOLATION_FAILURE" else rng.choice(_ENTITIES)
                op = rng.choice(["READ", "WRITE"])
                dedicated_did = _sid(f"data__{self.app_name}__{vuln_type.lower()}_{entity}__ep{idx}")
                self._add_node({
                    "id": dedicated_did,
                    "type": "data_access",
                    "attrs": {
                        "operation": op,
                        "target_entity": entity,
                        "has_ownership_predicate": False,
                        "ownership_predicate_type": "NONE",
                        "user_controlled_params_in_query": [params[0]],
                    },
                })
                if chain:
                    self._add_edge(chain[-1], dedicated_did, "call")
                else:
                    self._add_edge(eid, dedicated_did, "call")
                reachable_data = [dedicated_did]
            for did in reachable_data[:2]:
                self._add_edge(eid, did, "identifier_flow", param=params[0])
                for n in self.nodes:
                    if n["id"] == did:
                        if vuln_type == "TENANT_ISOLATION_FAILURE":
                            # Two sub-variants for TENANT:
                            # A) requires_tenant_isolation flag is True (explicit)
                            # B) entity/param name signals tenant scope (heuristic)
                            use_flag = rng.random() < 0.6
                            if use_flag:
                                n["attrs"]["has_ownership_predicate"] = True
                                n["attrs"]["ownership_predicate_type"] = "DIRECT"
                                n["attrs"]["requires_tenant_isolation"] = True
                                n["attrs"]["has_tenant_predicate"] = False
                            else:
                                # Name-heuristic variant: entity name contains
                                # tenant terms but flag is NOT set.
                                tenant_entities = [
                                    "Organization", "Workspace", "Tenant",
                                    "Project", "Realm", "Account",
                                ]
                                n["attrs"]["target_entity"] = rng.choice(tenant_entities)
                                n["attrs"]["has_ownership_predicate"] = False
                                n["attrs"]["ownership_predicate_type"] = "NONE"
                                n["attrs"]["requires_tenant_isolation"] = False
                                n["attrs"]["has_tenant_predicate"] = False
                            self._add_edge(eid, did, "tenant_flow", param=params[0])
                        elif vuln_type == "OBJECT_LEVEL_PERMISSION_BYPASS":
                            n["attrs"]["has_ownership_predicate"] = False
                            n["attrs"]["ownership_predicate_type"] = "NONE"
                            n["attrs"]["requires_object_permission"] = True
                            n["attrs"]["has_object_permission_check"] = False
                        if params[0] not in n["attrs"]["user_controlled_params_in_query"]:
                            n["attrs"]["user_controlled_params_in_query"].append(params[0])

        # Safe with params + ownership: add identifier_flow but WITH ownership
        if vuln_type is None and ownership_check and with_param and params and reachable_data:
            for did in reachable_data[:2]:
                self._add_edge(eid, did, "identifier_flow", param=params[0])
                for n in self.nodes:
                    if n["id"] == did:
                        n["attrs"]["has_ownership_predicate"] = True
                        n["attrs"]["ownership_predicate_type"] = "DIRECT"
                        if params[0] not in n["attrs"]["user_controlled_params_in_query"]:
                            n["attrs"]["user_controlled_params_in_query"].append(params[0])

        # Middleware guards for safe protected endpoints
        if vuln_type is None and requires_auth and not is_public:
            mw_id = _sid(f"middleware__AUTHENTICATION__{self.app_name}_{idx}")
            self._add_node({
                "id": mw_id,
                "type": "middleware",
                "attrs": {
                    "guard_type": "AUTHENTICATION",
                    "condition": "is_authenticated",
                    "position": "BEFORE_HANDLER",
                },
            })
            # Rewire: endpoint -> middleware -> first service
            if chain:
                # Remove direct endpoint -> service[0] edge and insert middleware
                self.edges = [
                    e for e in self.edges
                    if not (e["src"] == eid and e["dst"] == chain[0] and e["type"] == "call")
                ]
                self.seen_edges.discard((eid, chain[0], "call"))
                self._add_edge(eid, mw_id, "call")
                self._add_edge(mw_id, chain[0], "call")

            if ownership_check:
                own_mw_id = _sid(f"middleware__OWNERSHIP_CHECK__{self.app_name}_{idx}")
                self._add_node({
                    "id": own_mw_id,
                    "type": "middleware",
                    "attrs": {
                        "guard_type": "OWNERSHIP_CHECK",
                        "condition": "check_object_permissions",
                        "position": "BEFORE_HANDLER",
                    },
                })
                if chain:
                    self.edges = [
                        e for e in self.edges
                        if not (e["src"] == mw_id and e["dst"] == chain[0] and e["type"] == "call")
                    ]
                    self.seen_edges.discard((mw_id, chain[0], "call"))
                    self._add_edge(mw_id, own_mw_id, "call")
                    self._add_edge(own_mw_id, chain[0], "call")

        # Label
        if vuln_type == "MISSING_AUTH":
            self.labels[eid] = Label(label=LabelKind.VULNERABLE, subtype=VulnSubtype.MISSING_AUTH, cwe="CWE-862")
        elif vuln_type == "MISSING_ROLE":
            self.labels[eid] = Label(label=LabelKind.VULNERABLE, subtype=VulnSubtype.MISSING_ROLE, cwe="CWE-863")
        elif vuln_type == "IDOR":
            self.labels[eid] = Label(label=LabelKind.VULNERABLE, subtype=VulnSubtype.IDOR, cwe="CWE-639")
        elif vuln_type == "TENANT_ISOLATION_FAILURE":
            self.labels[eid] = Label(label=LabelKind.VULNERABLE, subtype=VulnSubtype.TENANT_ISOLATION_FAILURE, cwe="CWE-284")
        elif vuln_type == "OBJECT_LEVEL_PERMISSION_BYPASS":
            self.labels[eid] = Label(label=LabelKind.VULNERABLE, subtype=VulnSubtype.OBJECT_LEVEL_PERMISSION_BYPASS, cwe="CWE-284")
        elif vuln_type == "COMBINED":
            self.labels[eid] = Label(label=LabelKind.VULNERABLE, subtype=VulnSubtype.COMBINED, cwe="CWE-862")
        elif is_public:
            self.labels[eid] = Label(label=LabelKind.INTENTIONALLY_PUBLIC)
        else:
            self.labels[eid] = Label(label=LabelKind.SAFE)

    def build(self) -> tuple[PFG, dict[str, Label]]:
        """Assemble the full mini-app."""
        self._build_service_pool()
        self._build_data_pool()

        # Decide which endpoints are vulnerable
        n_vuln = int(self.n_endpoints * self.vuln_ratio)
        n_public = max(2, self.n_endpoints // 15)
        n_safe = self.n_endpoints - n_vuln - n_public

        # Distribute vulns across the access-control taxonomy.
        vuln_assignments: list[str] = []
        n_idor = max(1, int(n_vuln * 0.30))
        n_missing_auth = max(1, int(n_vuln * 0.20))
        n_missing_role = max(1, int(n_vuln * 0.15))
        n_tenant = max(1, int(n_vuln * 0.15))
        n_object = max(1, int(n_vuln * 0.15))
        n_combined = max(0, n_vuln - n_idor - n_missing_auth - n_missing_role - n_tenant - n_object)
        vuln_assignments.extend(["IDOR"] * n_idor)
        vuln_assignments.extend(["MISSING_AUTH"] * n_missing_auth)
        vuln_assignments.extend(["MISSING_ROLE"] * n_missing_role)
        vuln_assignments.extend(["TENANT_ISOLATION_FAILURE"] * n_tenant)
        vuln_assignments.extend(["OBJECT_LEVEL_PERMISSION_BYPASS"] * n_object)
        vuln_assignments.extend(["COMBINED"] * n_combined)
        self.rng.shuffle(vuln_assignments)

        # Build all endpoints
        idx = 0
        for vt in vuln_assignments:
            self._make_endpoint(idx, vuln_type=vt)
            idx += 1
        for _ in range(n_safe):
            self._make_endpoint(idx, vuln_type=None)
            idx += 1
        # Intentionally public
        for _ in range(n_public):
            self._make_endpoint(idx, vuln_type=None)
            # Force this one to be public
            eid = [n["id"] for n in self.nodes if n["type"] == "endpoint"][-1]
            for n in self.nodes:
                if n["id"] == eid:
                    n["attrs"]["is_intentionally_public"] = True
                    n["attrs"]["requires_auth"] = False
                    n["attrs"]["required_role"] = "NONE"
            self.labels[eid] = Label(label=LabelKind.INTENTIONALLY_PUBLIC)
            idx += 1

        pfg = PFG.model_validate({
            "schema_version": "1.0",
            "application": self.app_name,
            "framework": "synthetic",
            "nodes": self.nodes,
            "edges": self.edges,
        })
        from pfg.pfg.features import enrich_endpoint_features
        enrich_endpoint_features(pfg)
        return pfg, self.labels


def _pfg_to_samples(pfg: PFG, labels: dict[str, Label]) -> list[Sample]:
    """Convert a full-app PFG + labels into per-endpoint Samples."""
    from pfg.pfg.nodes import NodeType
    samples: list[Sample] = []
    for node in pfg.nodes:
        if node.type != NodeType.ENDPOINT.value:
            continue
        label = labels.get(node.id, Label(label=LabelKind.SAFE))
        samples.append(Sample(pfg=pfg, label=label, target_endpoint_id=node.id))
    return samples


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_realistic_dataset(
    n_apps: int = 15,
    endpoints_per_app: tuple[int, int] = (30, 70),
    vuln_ratio: float = 0.35,
    seed: int = 0,
) -> list[Sample]:
    """Generate a large realistic synthetic dataset.

    Parameters
    ----------
    n_apps:
        Number of synthetic mini-apps to generate.
    endpoints_per_app:
        (min, max) endpoints per app.
    vuln_ratio:
        Fraction of endpoints that should be vulnerable (across all types).
    seed:
        Random seed for reproducibility.

    Returns
    -------
    List of Samples ready for training. Each sample has the full app PFG
    and a target_endpoint_id, matching the format used by real corpus samples.
    """
    rng = random.Random(seed)
    all_samples: list[Sample] = []

    for app_idx in range(n_apps):
        n_ep = rng.randint(*endpoints_per_app)
        builder = _AppBuilder(rng, app_idx, n_ep, vuln_ratio)
        pfg, labels = builder.build()
        samples = _pfg_to_samples(pfg, labels)
        all_samples.extend(samples)

    rng.shuffle(all_samples)
    return all_samples
