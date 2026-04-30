"""Phase 2 W6 gate: auth annotation on the ref_auth fixture."""
from __future__ import annotations

from pathlib import Path

import yaml

from pfg.extractors.django import annotate_endpoint, discover_endpoints
from pfg.pfg.nodes import Role

REF_ROOT = Path(__file__).parents[2] / "benchmarks" / "reference" / "ref_auth"


def _expected() -> dict[tuple[str, str], dict[str, object]]:
    raw = yaml.safe_load((REF_ROOT / "expected_auth.yaml").read_text(encoding="utf-8"))
    return {(e["method"], e["route"]): e for e in raw["endpoints"]}


def test_auth_annotation_matches_ground_truth() -> None:
    eps = discover_endpoints(REF_ROOT)
    expected = _expected()

    # Sanity: discovery covers all expected endpoints.
    assert {(e.http_method, e.route) for e in eps} == set(expected.keys())

    for ep in eps:
        exp = expected[(ep.http_method, ep.route)]
        auth = annotate_endpoint(ep, REF_ROOT)
        role_str = auth.required_role.value if hasattr(auth.required_role, "value") else auth.required_role
        assert auth.requires_auth == exp["requires_auth"], f"{ep.route}: requires_auth"
        assert role_str == exp["required_role"], f"{ep.route}: role got {role_str} expected {exp['required_role']}"
        assert auth.is_intentionally_public == exp["is_intentionally_public"], (
            f"{ep.route}: public got {auth.is_intentionally_public} expected {exp['is_intentionally_public']}"
        )


def test_unknown_handler_falls_back_to_public_route_heuristic() -> None:
    """Endpoints we can't resolve still get the public-route heuristic."""
    from pfg.extractors.base import DiscoveredEndpoint

    ep = DiscoveredEndpoint(
        http_method="GET",
        route="/health/",
        route_params=(),
        handler_qualname="nonexistent.module.handler",
        source_location="x:0",
    )
    auth = annotate_endpoint(ep, REF_ROOT)
    assert auth.requires_auth is False
    assert auth.required_role == Role.NONE.value or auth.required_role == Role.NONE
    assert auth.is_intentionally_public is True
