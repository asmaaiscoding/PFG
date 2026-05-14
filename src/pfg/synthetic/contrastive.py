"""Contrastive synthetic PFG generator for Model B pre-training.

Generates paired samples (vulnerable + safe twin) with identical graph
topology and only the security-relevant feature differing.  This teaches
the GNN to attend to the *correct* discriminative signals rather than
learning spurious correlations.

Design:
  * Mini-app topology: 8-20 endpoints sharing services and data-access nodes.
  * Each vulnerable sample has a "hard negative" safe twin with the same
    graph structure but flipped security feature.
  * Middleware guard nodes (AUTHENTICATION, OWNERSHIP_CHECK) are placed on
    safe paths so the GNN can learn that guards = safe.
"""

from __future__ import annotations

import random
from typing import Any

from pfg.pfg.graph import PFG
from pfg.pfg.nodes import Label, LabelKind, VulnSubtype
from pfg.synthetic.generator import Sample

_HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
_ENTITIES = ("Invoice", "User", "Order", "Comment", "Post", "Document", "Booking")
_PARAM_NAMES = ("pk", "id", "slug", "uid")
_OPERATIONS = ("READ", "WRITE", "UPDATE", "DELETE")


def _sid(s: str) -> str:
    out = "".join(c if c.isalnum() else "_" for c in s)
    if not out or not (out[0].isalpha() or out[0] == "_"):
        out = "_" + out
    return out


def _mk_endpoint(
    rng: random.Random,
    idx: str,
    *,
    requires_auth: bool,
    role: str,
    is_public: bool,
    with_param: bool,
    ownership_check: bool,
) -> tuple[dict[str, Any], str, list[str]]:
    method = rng.choice(_HTTP_METHODS)
    base = rng.choice(["api", "v1", "v2", "app"])
    seg = rng.choice(["users", "items", "invoices", "posts", "orders", "reports"])
    if with_param:
        param = rng.choice(_PARAM_NAMES)
        route = f"/{base}/{seg}/{{{param}}}/"
        params = [param]
    else:
        route = f"/{base}/{seg}/"
        params = []
    eid = _sid(f"endpoint__{method}__{route}__{idx}")
    node = {
        "id": eid,
        "type": "endpoint",
        "attrs": {
            "http_method": method,
            "route": route,
            "route_params": params,
            "requires_auth": requires_auth,
            "required_role": role,
            "ownership_check_present": ownership_check,
            "is_intentionally_public": is_public,
        },
    }
    return node, eid, params


def _mk_service(idx: str, name: str, *, da: bool, mut: bool) -> tuple[dict[str, Any], str]:
    sid = _sid(f"service__{name}__{idx}")
    return {
        "id": sid,
        "type": "service",
        "attrs": {"name": name, "performs_data_access": da, "performs_mutation": mut},
    }, sid


def _mk_data_access(
    rng: random.Random,
    idx: str,
    *,
    operation: str,
    has_owner: bool,
    user_params: list[str],
) -> tuple[dict[str, Any], str]:
    entity = rng.choice(_ENTITIES)
    did = _sid(f"data__{operation}__{entity}__{idx}")
    return {
        "id": did,
        "type": "data_access",
        "attrs": {
            "operation": operation,
            "target_entity": entity,
            "has_ownership_predicate": has_owner,
            "ownership_predicate_type": "DIRECT" if has_owner else "NONE",
            "user_controlled_params_in_query": list(user_params),
        },
    }, did


def _mk_middleware(idx: str, guard_type: str) -> tuple[dict[str, Any], str]:
    mid = _sid(f"middleware__{guard_type}__{idx}")
    return {
        "id": mid,
        "type": "middleware",
        "attrs": {
            "guard_type": guard_type,
            "condition": guard_type.lower(),
            "position": "BEFORE_HANDLER",
        },
    }, mid


# ---------------------------------------------------------------------------
# Contrastive pair generators
# ---------------------------------------------------------------------------


def _pair_idor(
    rng: random.Random, app_idx: int, pair_idx: int
) -> tuple[Sample, Sample]:
    """IDOR vulnerable + safe twin with ownership check."""
    idx_v = f"a{app_idx}_p{pair_idx}_v"
    idx_s = f"a{app_idx}_p{pair_idx}_s"
    op = rng.choice(["READ", "UPDATE", "DELETE"])
    is_mut = op in {"WRITE", "UPDATE", "DELETE"}

    # Both endpoints have route params and reach the same data access
    ep_v, eid_v, params_v = _mk_endpoint(
        rng, idx_v, requires_auth=True, role=rng.choice(["NONE", "USER"]),
        is_public=False, with_param=True, ownership_check=False,
    )
    ep_s, eid_s, params_s = _mk_endpoint(
        rng, idx_s, requires_auth=True, role=rng.choice(["USER", "ADMIN"]),
        is_public=False, with_param=True, ownership_check=True,
    )

    # Shared service chain
    svc1_v, sid1_v = _mk_service(idx_v, "handler", da=False, mut=is_mut)
    svc2_v, sid2_v = _mk_service(idx_v, "repo", da=True, mut=is_mut)
    svc1_s, sid1_s = _mk_service(idx_s, "handler", da=False, mut=is_mut)
    svc2_s, sid2_s = _mk_service(idx_s, "repo", da=True, mut=is_mut)

    # Data access: vulnerable has no ownership, safe has ownership
    da_v, did_v = _mk_data_access(rng, idx_v, operation=op, has_owner=False, user_params=list(params_v))
    da_s, did_s = _mk_data_access(rng, idx_s, operation=op, has_owner=True, user_params=list(params_s))

    # Safe twin gets an ownership middleware guard
    mw_s, mwid_s = _mk_middleware(idx_s, "OWNERSHIP_CHECK")

    nodes_v = [ep_v, svc1_v, svc2_v, da_v]
    edges_v = [
        {"src": eid_v, "dst": sid1_v, "type": "call"},
        {"src": sid1_v, "dst": sid2_v, "type": "call"},
        {"src": sid2_v, "dst": did_v, "type": "call"},
        {"src": eid_v, "dst": did_v, "type": "identifier_flow", "param": params_v[0]},
    ]

    nodes_s = [ep_s, svc1_s, mw_s, svc2_s, da_s]
    edges_s = [
        {"src": eid_s, "dst": sid1_s, "type": "call"},
        {"src": sid1_s, "dst": mwid_s, "type": "call"},
        {"src": mwid_s, "dst": sid2_s, "type": "call"},
        {"src": sid2_s, "dst": did_s, "type": "call"},
        {"src": eid_s, "dst": did_s, "type": "identifier_flow", "param": params_s[0]},
    ]

    pfg_v = PFG.model_validate({
        "schema_version": "1.0", "application": f"contrastive_{app_idx}",
        "framework": "synthetic", "nodes": nodes_v, "edges": edges_v,
    })
    pfg_s = PFG.model_validate({
        "schema_version": "1.0", "application": f"contrastive_{app_idx}",
        "framework": "synthetic", "nodes": nodes_s, "edges": edges_s,
    })

    vuln = Sample(pfg=pfg_v, label=Label(label=LabelKind.VULNERABLE, subtype=VulnSubtype.IDOR, cwe="CWE-639"), target_endpoint_id=eid_v)
    safe = Sample(pfg=pfg_s, label=Label(label=LabelKind.SAFE), target_endpoint_id=eid_s)
    return vuln, safe


def _pair_missing_auth(
    rng: random.Random, app_idx: int, pair_idx: int
) -> tuple[Sample, Sample]:
    """MISSING_AUTH vulnerable + safe twin (intentionally public OR with auth guard)."""
    idx_v = f"a{app_idx}_p{pair_idx}_v"
    idx_s = f"a{app_idx}_p{pair_idx}_s"
    op = rng.choice(_OPERATIONS)
    is_mut = op in {"WRITE", "UPDATE", "DELETE"}

    # Vulnerable: no auth, not public, reaches data
    ep_v, eid_v, _ = _mk_endpoint(
        rng, idx_v, requires_auth=False, role="NONE",
        is_public=False, with_param=False, ownership_check=False,
    )
    # Safe twin variant: either (a) has auth, or (b) intentionally public
    use_public = rng.random() < 0.4
    if use_public:
        ep_s, eid_s, _ = _mk_endpoint(
            rng, idx_s, requires_auth=False, role="NONE",
            is_public=True, with_param=False, ownership_check=False,
        )
        # Override route to a known public route
        ep_s["attrs"]["route"] = rng.choice(["/health/", "/login/", "/public/static/"])
    else:
        ep_s, eid_s, _ = _mk_endpoint(
            rng, idx_s, requires_auth=True, role=rng.choice(["USER", "ADMIN"]),
            is_public=False, with_param=False, ownership_check=False,
        )

    svc_v, svid_v = _mk_service(idx_v, "handler", da=True, mut=is_mut)
    svc_s, svid_s = _mk_service(idx_s, "handler", da=True, mut=is_mut)
    da_v, did_v = _mk_data_access(rng, idx_v, operation=op, has_owner=False, user_params=[])
    da_s, did_s = _mk_data_access(rng, idx_s, operation=op, has_owner=False, user_params=[])

    # Safe twin gets an auth middleware if it has auth
    nodes_v = [ep_v, svc_v, da_v]
    edges_v = [
        {"src": eid_v, "dst": svid_v, "type": "call"},
        {"src": svid_v, "dst": did_v, "type": "call"},
    ]

    if use_public:
        nodes_s = [ep_s, svc_s, da_s]
        edges_s = [
            {"src": eid_s, "dst": svid_s, "type": "call"},
            {"src": svid_s, "dst": did_s, "type": "call"},
        ]
    else:
        mw_s, mwid_s = _mk_middleware(idx_s, "AUTHENTICATION")
        nodes_s = [ep_s, mw_s, svc_s, da_s]
        edges_s = [
            {"src": eid_s, "dst": mwid_s, "type": "call"},
            {"src": mwid_s, "dst": svid_s, "type": "call"},
            {"src": svid_s, "dst": did_s, "type": "call"},
        ]

    pfg_v = PFG.model_validate({
        "schema_version": "1.0", "application": f"contrastive_{app_idx}",
        "framework": "synthetic", "nodes": nodes_v, "edges": edges_v,
    })
    pfg_s = PFG.model_validate({
        "schema_version": "1.0", "application": f"contrastive_{app_idx}",
        "framework": "synthetic", "nodes": nodes_s, "edges": edges_s,
    })

    vuln = Sample(pfg=pfg_v, label=Label(label=LabelKind.VULNERABLE, subtype=VulnSubtype.MISSING_AUTH, cwe="CWE-862"), target_endpoint_id=eid_v)
    safe_label = Label(label=LabelKind.INTENTIONALLY_PUBLIC) if use_public else Label(label=LabelKind.SAFE)
    safe = Sample(pfg=pfg_s, label=safe_label, target_endpoint_id=eid_s)
    return vuln, safe


def _pair_missing_role(
    rng: random.Random, app_idx: int, pair_idx: int
) -> tuple[Sample, Sample]:
    """MISSING_ROLE vulnerable + safe twin with role guard."""
    idx_v = f"a{app_idx}_p{pair_idx}_v"
    idx_s = f"a{app_idx}_p{pair_idx}_s"
    op = rng.choice(["WRITE", "UPDATE", "DELETE"])

    ep_v, eid_v, _ = _mk_endpoint(
        rng, idx_v, requires_auth=True, role="NONE",
        is_public=False, with_param=False, ownership_check=False,
    )
    ep_s, eid_s, _ = _mk_endpoint(
        rng, idx_s, requires_auth=True, role=rng.choice(["ADMIN", "MODERATOR"]),
        is_public=False, with_param=False, ownership_check=False,
    )

    svc_v, svid_v = _mk_service(idx_v, "handler", da=True, mut=True)
    svc_s, svid_s = _mk_service(idx_s, "handler", da=True, mut=True)
    da_v, did_v = _mk_data_access(rng, idx_v, operation=op, has_owner=False, user_params=[])
    da_s, did_s = _mk_data_access(rng, idx_s, operation=op, has_owner=False, user_params=[])

    mw_s, mwid_s = _mk_middleware(idx_s, "ROLE_CHECK")

    nodes_v = [ep_v, svc_v, da_v]
    edges_v = [
        {"src": eid_v, "dst": svid_v, "type": "call"},
        {"src": svid_v, "dst": did_v, "type": "call"},
    ]
    nodes_s = [ep_s, mw_s, svc_s, da_s]
    edges_s = [
        {"src": eid_s, "dst": mwid_s, "type": "call"},
        {"src": mwid_s, "dst": svid_s, "type": "call"},
        {"src": svid_s, "dst": did_s, "type": "call"},
    ]

    pfg_v = PFG.model_validate({
        "schema_version": "1.0", "application": f"contrastive_{app_idx}",
        "framework": "synthetic", "nodes": nodes_v, "edges": edges_v,
    })
    pfg_s = PFG.model_validate({
        "schema_version": "1.0", "application": f"contrastive_{app_idx}",
        "framework": "synthetic", "nodes": nodes_s, "edges": edges_s,
    })

    vuln = Sample(pfg=pfg_v, label=Label(label=LabelKind.VULNERABLE, subtype=VulnSubtype.MISSING_ROLE, cwe="CWE-863"), target_endpoint_id=eid_v)
    safe = Sample(pfg=pfg_s, label=Label(label=LabelKind.SAFE), target_endpoint_id=eid_s)
    return vuln, safe


def _pair_combined(
    rng: random.Random, app_idx: int, pair_idx: int
) -> tuple[Sample, Sample]:
    """COMBINED (no auth + IDOR) vulnerable + safe twin."""
    idx_v = f"a{app_idx}_p{pair_idx}_v"
    idx_s = f"a{app_idx}_p{pair_idx}_s"
    op = rng.choice(["UPDATE", "DELETE"])

    ep_v, eid_v, params_v = _mk_endpoint(
        rng, idx_v, requires_auth=False, role="NONE",
        is_public=False, with_param=True, ownership_check=False,
    )
    ep_s, eid_s, params_s = _mk_endpoint(
        rng, idx_s, requires_auth=True, role=rng.choice(["USER", "ADMIN"]),
        is_public=False, with_param=True, ownership_check=True,
    )

    svc_v, svid_v = _mk_service(idx_v, "handler", da=True, mut=True)
    svc_s, svid_s = _mk_service(idx_s, "handler", da=True, mut=True)
    da_v, did_v = _mk_data_access(rng, idx_v, operation=op, has_owner=False, user_params=list(params_v))
    da_s, did_s = _mk_data_access(rng, idx_s, operation=op, has_owner=True, user_params=list(params_s))

    mw_auth, mwid_auth = _mk_middleware(idx_s, "AUTHENTICATION")
    mw_own, mwid_own = _mk_middleware(f"{idx_s}_own", "OWNERSHIP_CHECK")

    nodes_v = [ep_v, svc_v, da_v]
    edges_v = [
        {"src": eid_v, "dst": svid_v, "type": "call"},
        {"src": svid_v, "dst": did_v, "type": "call"},
        {"src": eid_v, "dst": did_v, "type": "identifier_flow", "param": params_v[0]},
    ]
    nodes_s = [ep_s, mw_auth, mw_own, svc_s, da_s]
    edges_s = [
        {"src": eid_s, "dst": mwid_auth, "type": "call"},
        {"src": mwid_auth, "dst": mwid_own, "type": "call"},
        {"src": mwid_own, "dst": svid_s, "type": "call"},
        {"src": svid_s, "dst": did_s, "type": "call"},
        {"src": eid_s, "dst": did_s, "type": "identifier_flow", "param": params_s[0]},
    ]

    pfg_v = PFG.model_validate({
        "schema_version": "1.0", "application": f"contrastive_{app_idx}",
        "framework": "synthetic", "nodes": nodes_v, "edges": edges_v,
    })
    pfg_s = PFG.model_validate({
        "schema_version": "1.0", "application": f"contrastive_{app_idx}",
        "framework": "synthetic", "nodes": nodes_s, "edges": edges_s,
    })

    vuln = Sample(pfg=pfg_v, label=Label(label=LabelKind.VULNERABLE, subtype=VulnSubtype.COMBINED, cwe="CWE-862"), target_endpoint_id=eid_v)
    safe = Sample(pfg=pfg_s, label=Label(label=LabelKind.SAFE), target_endpoint_id=eid_s)
    return vuln, safe


def _extra_safe_no_data(
    rng: random.Random, app_idx: int, idx: int
) -> Sample:
    """Safe endpoint with no auth but no reachable data access (harmless)."""
    tag = f"a{app_idx}_nodata_{idx}"
    ep, eid, _ = _mk_endpoint(
        rng, tag, requires_auth=False, role="NONE",
        is_public=False, with_param=False, ownership_check=False,
    )
    svc, svid = _mk_service(tag, "render_template", da=False, mut=False)
    nodes = [ep, svc]
    edges = [{"src": eid, "dst": svid, "type": "call"}]
    pfg = PFG.model_validate({
        "schema_version": "1.0", "application": f"contrastive_{app_idx}",
        "framework": "synthetic", "nodes": nodes, "edges": edges,
    })
    return Sample(pfg=pfg, label=Label(label=LabelKind.SAFE), target_endpoint_id=eid)


def _extra_safe_with_params(
    rng: random.Random, app_idx: int, idx: int
) -> Sample:
    """Safe endpoint with route params AND identifier flow but WITH ownership — hard negative for IDOR."""
    tag = f"a{app_idx}_safeparam_{idx}"
    op = rng.choice(["READ", "UPDATE"])
    ep, eid, params = _mk_endpoint(
        rng, tag, requires_auth=True, role=rng.choice(["USER", "ADMIN"]),
        is_public=False, with_param=True, ownership_check=True,
    )
    svc, svid = _mk_service(tag, "handler", da=True, mut=op != "READ")
    da, did = _mk_data_access(rng, tag, operation=op, has_owner=True, user_params=list(params))
    mw, mwid = _mk_middleware(tag, "OWNERSHIP_CHECK")
    nodes = [ep, mw, svc, da]
    edges = [
        {"src": eid, "dst": mwid, "type": "call"},
        {"src": mwid, "dst": svid, "type": "call"},
        {"src": svid, "dst": did, "type": "call"},
        {"src": eid, "dst": did, "type": "identifier_flow", "param": params[0]},
    ]
    pfg = PFG.model_validate({
        "schema_version": "1.0", "application": f"contrastive_{app_idx}",
        "framework": "synthetic", "nodes": nodes, "edges": edges,
    })
    return Sample(pfg=pfg, label=Label(label=LabelKind.SAFE), target_endpoint_id=eid)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_contrastive_dataset(
    n_pairs: int = 150,
    *,
    seed: int = 0,
) -> list[Sample]:
    """Generate contrastive synthetic samples for Model B pre-training.

    Returns approximately ``n_pairs * 2`` + extras samples with balanced
    class distribution and hard-negative safe twins.
    """
    rng = random.Random(seed)
    samples: list[Sample] = []

    # Pair types and their proportions
    pair_types = [
        (_pair_idor, 0.30),
        (_pair_missing_auth, 0.30),
        (_pair_missing_role, 0.20),
        (_pair_combined, 0.20),
    ]

    app_idx = 0
    for pair_fn, ratio in pair_types:
        count = max(1, int(n_pairs * ratio))
        for i in range(count):
            vuln, safe = pair_fn(rng, app_idx, i)
            samples.append(vuln)
            samples.append(safe)
        app_idx += 1

    # Extra safe samples: no-data-access and params-with-ownership
    n_extra = max(10, n_pairs // 5)
    for i in range(n_extra):
        samples.append(_extra_safe_no_data(rng, app_idx, i))
    app_idx += 1
    for i in range(n_extra):
        samples.append(_extra_safe_with_params(rng, app_idx, i))

    rng.shuffle(samples)
    return samples
