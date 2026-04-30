"""Phase 2 W7-W8 gate: call graph snapshot on ref_callgraph."""
from __future__ import annotations

from pathlib import Path

import yaml

from pfg.extractors.django import build_call_graph

REF_ROOT = Path(__file__).parents[2] / "benchmarks" / "reference" / "ref_callgraph"


def _expected() -> set[tuple[str, str]]:
    raw = yaml.safe_load((REF_ROOT / "expected_callgraph.yaml").read_text(encoding="utf-8"))
    return {(c, e) for c, e in raw["edges"]}


SEEDS = [
    "views.get_invoice",
    "views.noop",
    "views.AdminUsers.get",
    "views.AdminUsers.post",
]


def test_call_graph_matches_ground_truth() -> None:
    edges = build_call_graph(REF_ROOT, SEEDS)
    found = {(e.caller, e.callee) for e in edges}
    expected = _expected()
    missing = expected - found
    extra = found - expected
    assert not missing, f"missing edges: {sorted(missing)}"
    assert not extra, f"unexpected edges: {sorted(extra)}"


def test_isolated_endpoint_has_no_outgoing_edges() -> None:
    edges = build_call_graph(REF_ROOT, ["views.noop"])
    assert all(e.caller != "views.noop" for e in edges)


def test_depth_cap_terminates() -> None:
    # Even with max_depth=1, no infinite loops; we get only direct callees.
    edges = build_call_graph(REF_ROOT, ["views.get_invoice"], max_depth=1)
    callers = {e.caller for e in edges}
    assert callers == {"views.get_invoice"}
