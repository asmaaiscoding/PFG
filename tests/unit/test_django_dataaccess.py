"""Phase 2 W9 gate: data-access + ownership detection on ref_dataaccess."""
from __future__ import annotations

import ast
from pathlib import Path

import yaml

from pfg.extractors.django import detect_data_accesses

REF = Path(__file__).parents[2] / "benchmarks" / "reference" / "ref_dataaccess"


def _load_module() -> ast.Module:
    return ast.parse((REF / "repo.py").read_text(encoding="utf-8"))


def _functions(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    return {
        n.name: n
        for n in tree.body
        if isinstance(n, ast.FunctionDef)
    }


def test_dataaccess_matches_ground_truth() -> None:
    expected = yaml.safe_load((REF / "expected_dataaccess.yaml").read_text(encoding="utf-8"))[
        "functions"
    ]
    fns = _functions(_load_module())
    assert set(expected) <= set(fns), f"missing fixtures: {set(expected) - set(fns)}"
    for fname, exp_list in expected.items():
        accesses = detect_data_accesses(fns[fname])
        got = [
            {
                "operation": a.operation,
                "target_entity": a.target_entity,
                "has_ownership_predicate": a.has_ownership_predicate,
                "ownership_predicate_type": a.ownership_predicate_type,
            }
            for a in accesses
        ]
        assert got == exp_list, f"mismatch for {fname}: got={got} expected={exp_list}"


def test_no_dataaccess_in_pure_function() -> None:
    src = "def f(x):\n    return x + 1\n"
    fn = ast.parse(src).body[0]
    assert isinstance(fn, ast.FunctionDef)
    assert detect_data_accesses(fn) == []


def test_file_write_open_counts_as_dataaccess() -> None:
    src = """
def upload(path, chunks):
    with open(path, "wb+") as file:
        for chunk in chunks:
            file.write(chunk)
"""
    fn = ast.parse(src).body[0]
    assert isinstance(fn, ast.FunctionDef)

    accesses = detect_data_accesses(fn)

    assert len(accesses) == 1
    assert accesses[0].operation == "WRITE"
    assert accesses[0].target_entity == "filesystem"
    assert not accesses[0].has_ownership_predicate
