"""Phase 5 W24-W25: Spring Boot extractor tests."""
from __future__ import annotations

from pathlib import Path

from pfg.extractors.spring.build import build_pfg, discover_endpoints

REF = Path(__file__).parents[2] / "benchmarks" / "reference" / "spring_ref_min"


def _eps_by_route(pfg: object) -> dict[tuple[str, str], dict[str, object]]:
    out: dict[tuple[str, str], dict[str, object]] = {}
    for n in pfg.nodes:  # type: ignore[attr-defined]
        ntype = getattr(n.type, "value", n.type)
        if ntype != "endpoint":
            continue
        a = n.attrs.model_dump() if hasattr(n.attrs, "model_dump") else dict(n.attrs)
        out[(str(a["http_method"]), str(a["route"]))] = a
    return out


def test_discover_endpoints_finds_four() -> None:
    found = discover_endpoints(REF)
    routes = sorted({(ep.http_method, ep.route) for ep, _, _ in found})
    assert ("GET", "/api/invoices/{id}") in routes
    assert ("DELETE", "/api/invoices/{id}") in routes
    assert ("GET", "/api/invoices/owned/{id}") in routes
    assert ("GET", "/api/invoices/health") in routes
    assert len(routes) == 4


def test_build_pfg_spring_basic_attrs() -> None:
    pfg = build_pfg(REF, application="spring_demo")
    assert pfg.framework == "spring"
    assert pfg.application == "spring_demo"

    eps = _eps_by_route(pfg)

    # GET /{id}: vulnerable, no auth.
    a = eps[("GET", "/api/invoices/{id}")]
    assert a["requires_auth"] is False
    assert a["required_role"] == "NONE"
    assert "id" in (a["route_params"] or [])

    # DELETE /{id}: requires auth, no role specified beyond isAuthenticated.
    d = eps[("DELETE", "/api/invoices/{id}")]
    assert d["requires_auth"] is True

    # GET /owned/{id}: hasRole('USER').
    o = eps[("GET", "/api/invoices/owned/{id}")]
    assert o["requires_auth"] is True
    assert o["required_role"] == "USER"


def test_data_access_and_idflow_emitted() -> None:
    pfg = build_pfg(REF, application="spring_demo")
    types = {getattr(n.type, "value", n.type) for n in pfg.nodes}
    assert {"endpoint", "service", "data_access"} <= types

    edge_types = {getattr(e.type, "value", e.type) for e in pfg.edges}
    assert "call" in edge_types
    assert "identifier_flow" in edge_types  # path variable id flows into repo call

    # Find the data_access node for the vulnerable getInvoice — should not be
    # owner-checked.
    for n in pfg.nodes:
        if getattr(n.type, "value", n.type) != "data_access":
            continue
        a = n.attrs.model_dump() if hasattr(n.attrs, "model_dump") else dict(n.attrs)
        if a.get("operation") == "READ" and a.get("target_entity") == "Invoice":
            # At least one such read exists.
            break
    else:  # pragma: no cover
        raise AssertionError("expected a READ data_access on Invoice")


def test_ownership_predicate_detected() -> None:
    pfg = build_pfg(REF, application="spring_demo")
    owner_flag = False
    for n in pfg.nodes:
        if getattr(n.type, "value", n.type) != "data_access":
            continue
        a = n.attrs.model_dump() if hasattr(n.attrs, "model_dump") else dict(n.attrs)
        if a.get("has_ownership_predicate"):
            owner_flag = True
            break
    assert owner_flag, "findByIdAndByOwner must be flagged with ownership predicate"
