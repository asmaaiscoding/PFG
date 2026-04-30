"""Phase 2 W5 gate: 100% endpoint recall on the ref_min reference app."""
from __future__ import annotations

from pathlib import Path

import yaml

from pfg.extractors.django import discover_endpoints

REF_ROOT = Path(__file__).parents[2] / "benchmarks" / "reference" / "ref_min"


def _load_expected() -> list[dict[str, object]]:
    data = yaml.safe_load((REF_ROOT / "expected_endpoints.yaml").read_text(encoding="utf-8"))
    return list(data["endpoints"])


def test_endpoint_discovery_matches_ground_truth() -> None:
    found = discover_endpoints(REF_ROOT)
    found_set = {(e.http_method, e.route, e.handler_qualname) for e in found}

    expected = _load_expected()
    expected_set = {(e["method"], e["route"], e["handler"]) for e in expected}

    missing = expected_set - found_set
    extra = found_set - expected_set
    assert not missing, f"missing endpoints: {sorted(missing)}"
    assert not extra, f"unexpected endpoints: {sorted(extra)}"


def test_endpoint_route_params_inferred() -> None:
    found = {e.route: e for e in discover_endpoints(REF_ROOT)}
    assert found["/blog/post/{pk}/"].route_params == ("pk",)
    assert found["/blog/archive/{year}/"].route_params == ("year",)
    assert found["/api/users/{pk}/"].route_params == ("pk",)
    assert found["/api/health/"].route_params == ()
