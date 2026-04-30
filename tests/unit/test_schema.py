"""Verify the JSON Schema is loadable and rejects malformed PFGs."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import ValidationError

from pfg.pfg.graph import load_pfg, validate_pfg

GOLDEN = ["toy_safe", "toy_missing_auth", "toy_missing_role", "toy_idor", "toy_combined", "toy_public"]


@pytest.mark.parametrize("name", GOLDEN)
def test_golden_pfg_validates(golden_dir: Path, name: str) -> None:
    pfg = load_pfg(golden_dir / f"{name}.json")
    assert pfg.schema_version == "1.0"
    assert pfg.application == name
    assert len(pfg.nodes) >= 1


def test_schema_rejects_unknown_node_type() -> None:
    bad = {
        "schema_version": "1.0",
        "application": "x",
        "framework": "synthetic",
        "nodes": [{"id": "n1", "type": "ghost", "attrs": {}}],
        "edges": [],
    }
    with pytest.raises(ValidationError):
        validate_pfg(bad)


def test_schema_rejects_bad_role(golden_dir: Path) -> None:
    raw = json.loads((golden_dir / "toy_safe.json").read_text(encoding="utf-8"))
    raw["nodes"][0]["attrs"]["required_role"] = "GOD"
    with pytest.raises(ValidationError):
        validate_pfg(raw)
