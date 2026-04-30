"""Phase 2 W10 gate: identifier-flow tracking on ref_idflow."""
from __future__ import annotations

import ast
from pathlib import Path

import yaml

from pfg.extractors.django import track_identifier_flow

REF = Path(__file__).parents[2] / "benchmarks" / "reference" / "ref_idflow"


def _functions() -> dict[str, ast.FunctionDef]:
    tree = ast.parse((REF / "views.py").read_text(encoding="utf-8"))
    return {
        n.name: n
        for n in tree.body
        if isinstance(n, ast.FunctionDef)
    }


def _sink_to_dict(s) -> dict:
    return {
        "source": s.source,
        "callee": s.callee,
        "arg_kind": s.arg_kind,
        "arg_name": s.arg_name,
        "arg_index": s.arg_index,
    }


def _sources_for(fname: str) -> list[str]:
    # Anything that isn't `request` or `self` is a source for the test fixture.
    fns = _functions()
    fn = fns[fname]
    return [
        a.arg
        for a in fn.args.args
        if a.arg not in {"request", "self"}
    ]


def test_idflow_matches_ground_truth() -> None:
    expected = yaml.safe_load((REF / "expected_idflow.yaml").read_text(encoding="utf-8"))[
        "functions"
    ]
    fns = _functions()
    for fname, exp_list in expected.items():
        sinks = track_identifier_flow(fns[fname], _sources_for(fname))
        got = [_sink_to_dict(s) for s in sinks]
        # Compare as sets of tuples (order-insensitive but dedup-aware).
        got_t = sorted((d["source"], d["callee"], d["arg_kind"], d["arg_name"], d["arg_index"]) for d in got)
        exp_t = sorted((d["source"], d["callee"], d["arg_kind"], d["arg_name"], d["arg_index"]) for d in exp_list)
        assert got_t == exp_t, f"mismatch for {fname}: got={got_t} expected={exp_t}"


def test_no_sources_means_no_sinks() -> None:
    fn = _functions()["flow_direct"]
    assert track_identifier_flow(fn, []) == []
