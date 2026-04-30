"""Synthetic PFG generator (Phase 3).

Generates labeled PFGs that mimic the structural patterns produced by the
real Django extractor (Phase 2) but parameterized by knobs so we can
produce thousands of training samples cheaply.

Output is a sequence of `(PFG, Label)` pairs where the label is one of:

    SAFE
    VULNERABLE / MISSING_AUTH
    VULNERABLE / MISSING_ROLE
    VULNERABLE / IDOR
    VULNERABLE / COMBINED
    INTENTIONALLY_PUBLIC

The generator is deterministic given a seed.

Design choices
--------------
* Topology mimics the W11 assembly: an endpoint connects to a single
  handler service via a `call` edge; the handler may chain through
  intermediate services into a single data_access leaf.
* For IDOR we add an `identifier_flow` edge from the endpoint to the
  data-access leaf with `param` set to a route param name. The leaf may
  or may not have an ownership predicate.
* IDs are schema-safe identifiers (only [A-Za-z0-9_]).
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any

from pfg.pfg.graph import PFG
from pfg.pfg.nodes import Label, LabelKind, VulnSubtype

# --- public types ---------------------------------------------------------


@dataclass(frozen=True)
class Sample:
    """One labeled PFG in the synthetic corpus."""

    pfg: PFG
    label: Label
    target_endpoint_id: str  # the endpoint that carries the (potential) issue


# --- internal helpers -----------------------------------------------------


_HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
_ROLES = ("NONE", "USER", "MODERATOR", "ADMIN", "SUPERADMIN")
_ENTITIES = ("Invoice", "User", "Order", "Comment", "Post", "Document", "Booking")
_PARAM_NAMES = ("pk", "id", "slug", "uid")


def _rand_route(rng: random.Random, with_param: bool) -> tuple[str, list[str]]:
    base = rng.choice(["api", "app", "v1", "internal"])
    seg = rng.choice(["users", "items", "invoices", "posts", "orders", "documents"])
    if with_param:
        param = rng.choice(_PARAM_NAMES)
        return f"/{base}/{seg}/{{{param}}}/", [param]
    return f"/{base}/{seg}/", []


def _safe_id(s: str) -> str:
    out = "".join(c if c.isalnum() else "_" for c in s)
    if not out or not (out[0].isalpha() or out[0] == "_"):
        out = "_" + out
    return out


def _mk_endpoint(
    rng: random.Random,
    *,
    requires_auth: bool,
    role: str,
    is_public: bool,
    with_param: bool,
    suffix: str,
) -> tuple[dict[str, Any], str, list[str]]:
    method = rng.choice(_HTTP_METHODS)
    route, params = _rand_route(rng, with_param)
    eid = _safe_id(f"endpoint__{method}__{route}__{suffix}")
    node = {
        "id": eid,
        "type": "endpoint",
        "attrs": {
            "http_method": method,
            "route": route,
            "route_params": params,
            "requires_auth": requires_auth,
            "required_role": role,
            "ownership_check_present": False,
            "is_intentionally_public": is_public,
        },
    }
    return node, eid, params


def _mk_service(rng: random.Random, suffix: str, *, da: bool, mut: bool) -> tuple[dict[str, Any], str]:
    name = rng.choice(["handle", "do", "exec", "run", "process"]) + "_" + suffix
    sid = _safe_id(f"service__{name}")
    node = {
        "id": sid,
        "type": "service",
        "attrs": {
            "name": name,
            "performs_data_access": da,
            "performs_mutation": mut,
        },
    }
    return node, sid


def _mk_data_access(
    rng: random.Random,
    suffix: str,
    *,
    operation: str,
    has_owner: bool,
    user_params: list[str],
) -> tuple[dict[str, Any], str]:
    entity = rng.choice(_ENTITIES)
    did = _safe_id(f"data__{operation}__{entity}__{suffix}")
    node = {
        "id": did,
        "type": "data_access",
        "attrs": {
            "operation": operation,
            "target_entity": entity,
            "has_ownership_predicate": has_owner,
            "ownership_predicate_type": ("DIRECT" if has_owner else "NONE"),
            "user_controlled_params_in_query": list(user_params),
        },
    }
    return node, did


# --- core generator -------------------------------------------------------


def _generate_one(rng: random.Random, idx: int) -> Sample:
    """Generate a single labeled PFG by choosing a class then sampling.

    Class distribution (uniform across 6 buckets):
      0  SAFE — auth + role + ownership
      1  MISSING_AUTH — no auth, but reaches data
      2  MISSING_ROLE — auth on, no role, mutation
      3  IDOR — auth on, route param flows to data access without ownership
      4  COMBINED — no auth + IDOR-style flow
      5  INTENTIONALLY_PUBLIC — explicitly public, public-route prefix
    """
    cls = idx % 6
    suffix = f"s{idx}"
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    # Decide endpoint shape per class.
    if cls == 0:  # SAFE
        ep_node, eid, params = _mk_endpoint(
            rng, requires_auth=True, role=rng.choice(["USER", "ADMIN"]), is_public=False,
            with_param=rng.random() < 0.5, suffix=suffix,
        )
        op = rng.choice(["READ", "WRITE", "UPDATE", "DELETE"])
        has_owner = True
        user_params: list[str] = list(params)
        label = Label(label=LabelKind.SAFE)
        add_id_flow = bool(params)
    elif cls == 1:  # MISSING_AUTH
        ep_node, eid, params = _mk_endpoint(
            rng, requires_auth=False, role="NONE", is_public=False,
            with_param=False, suffix=suffix,
        )
        op = rng.choice(["READ", "WRITE", "UPDATE", "DELETE"])
        has_owner = False
        user_params = []
        label = Label(label=LabelKind.VULNERABLE, subtype=VulnSubtype.MISSING_AUTH, cwe="CWE-862")
        add_id_flow = False
    elif cls == 2:  # MISSING_ROLE
        ep_node, eid, params = _mk_endpoint(
            rng, requires_auth=True, role="NONE", is_public=False,
            with_param=False, suffix=suffix,
        )
        op = rng.choice(["WRITE", "UPDATE", "DELETE"])
        has_owner = False
        user_params = []
        label = Label(label=LabelKind.VULNERABLE, subtype=VulnSubtype.MISSING_ROLE, cwe="CWE-863")
        add_id_flow = False
    elif cls == 3:  # IDOR
        ep_node, eid, params = _mk_endpoint(
            rng, requires_auth=True, role=rng.choice(["NONE", "USER"]), is_public=False,
            with_param=True, suffix=suffix,
        )
        op = rng.choice(["READ", "UPDATE", "DELETE"])
        has_owner = False
        user_params = list(params)
        label = Label(label=LabelKind.VULNERABLE, subtype=VulnSubtype.IDOR, cwe="CWE-639")
        add_id_flow = True
    elif cls == 4:  # COMBINED
        ep_node, eid, params = _mk_endpoint(
            rng, requires_auth=False, role="NONE", is_public=False,
            with_param=True, suffix=suffix,
        )
        op = rng.choice(["UPDATE", "DELETE"])
        has_owner = False
        user_params = list(params)
        label = Label(label=LabelKind.VULNERABLE, subtype=VulnSubtype.COMBINED, cwe="CWE-862")
        add_id_flow = True
    else:  # INTENTIONALLY_PUBLIC
        method = rng.choice(["GET", "POST"])
        route = rng.choice(["/health", "/login", "/public/static"])
        eid = _safe_id(f"endpoint__{method}__{route}__{suffix}")
        ep_node = {
            "id": eid,
            "type": "endpoint",
            "attrs": {
                "http_method": method,
                "route": route,
                "route_params": [],
                "requires_auth": False,
                "required_role": "NONE",
                "ownership_check_present": False,
                "is_intentionally_public": True,
            },
        }
        params = []
        op = "READ"
        has_owner = False
        user_params = []
        label = Label(label=LabelKind.INTENTIONALLY_PUBLIC)
        add_id_flow = False

    nodes.append(ep_node)

    # Service chain: 1-3 services from endpoint to leaf.
    chain_len = rng.randint(1, 3)
    prev_id = eid
    last_service_id = None
    is_mut = op in {"WRITE", "UPDATE", "DELETE"}
    for hop in range(chain_len):
        snode, sid = _mk_service(rng, f"{suffix}_h{hop}", da=(hop == chain_len - 1), mut=is_mut)
        nodes.append(snode)
        edges.append({"src": prev_id, "dst": sid, "type": "call"})
        prev_id = sid
        last_service_id = sid

    # Data access leaf attached to last service.
    dnode, did = _mk_data_access(rng, suffix, operation=op, has_owner=has_owner, user_params=user_params)
    nodes.append(dnode)
    assert last_service_id is not None
    edges.append({"src": last_service_id, "dst": did, "type": "call"})

    # Identifier flow edge for IDOR-style classes (and SAFE with params).
    if add_id_flow and params:
        edges.append(
            {"src": eid, "dst": did, "type": "identifier_flow", "param": params[0]}
        )

    pfg = PFG.model_validate(
        {
            "schema_version": "1.0",
            "application": f"synth_{idx}",
            "framework": "synthetic",
            "nodes": nodes,
            "edges": edges,
        }
    )
    return Sample(pfg=pfg, label=label, target_endpoint_id=eid)


# --- public API -----------------------------------------------------------


def generate_dataset(n: int, *, seed: int = 0) -> list[Sample]:
    """Generate `n` synthetic labeled PFG samples deterministically from `seed`."""
    rng = random.Random(seed)
    return [_generate_one(rng, i) for i in range(n)]
