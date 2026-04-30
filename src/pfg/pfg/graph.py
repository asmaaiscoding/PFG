"""PFG container with JSON I/O and schema validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from pfg.pfg.nodes import Edge, EdgeType, Label, Node, NodeType

_SCHEMA_CACHE: dict[str, Any] | None = None


def _load_schema() -> dict[str, Any]:
    global _SCHEMA_CACHE
    if _SCHEMA_CACHE is not None:
        return _SCHEMA_CACHE
    # Look for schemas/pfg-1.0.json relative to repo root.
    here = Path(__file__).resolve()
    for parent in [here.parent, *here.parents]:
        candidate = parent / "schemas" / "pfg-1.0.json"
        if candidate.exists():
            _SCHEMA_CACHE = json.loads(candidate.read_text(encoding="utf-8"))
            return _SCHEMA_CACHE
    raise FileNotFoundError("Could not locate schemas/pfg-1.0.json from " + str(here))


def validate_pfg(data: dict[str, Any]) -> None:
    """Validate a raw PFG dict against the JSON Schema. Raises on failure."""
    schema = _load_schema()
    Draft202012Validator(schema).validate(data)


_NodeAdapter: TypeAdapter[Node] = TypeAdapter(Node)


class PFG(BaseModel):
    """In-memory Privilege Flow Graph."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    schema_version: str = "1.0"
    application: str
    framework: str
    nodes: list[Node]
    edges: list[Edge] = Field(default_factory=list)
    labels: dict[str, Label] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    # --- convenience indexes (lazy) -------------------------------------

    def node_index(self) -> dict[str, Node]:
        return {n.id: n for n in self.nodes}

    def endpoints(self) -> list[Node]:
        return [n for n in self.nodes if n.type == NodeType.ENDPOINT.value]

    def data_accesses(self) -> list[Node]:
        return [n for n in self.nodes if n.type == NodeType.DATA_ACCESS.value]

    def middlewares(self) -> list[Node]:
        return [n for n in self.nodes if n.type == NodeType.MIDDLEWARE.value]

    def call_edges(self) -> list[Edge]:
        return [e for e in self.edges if e.type == EdgeType.CALL.value]

    def identifier_flow_edges(self) -> list[Edge]:
        return [e for e in self.edges if e.type == EdgeType.IDENTIFIER_FLOW.value]

    def successors(self, node_id: str, *, edge_type: EdgeType | None = None) -> list[str]:
        return [
            e.dst
            for e in self.edges
            if e.src == node_id and (edge_type is None or e.type == edge_type.value)
        ]

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)


def load_pfg(path: str | Path) -> PFG:
    """Load and validate a PFG from JSON."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_pfg(data)
    return PFG.model_validate(data)


def save_pfg(pfg: PFG, path: str | Path) -> None:
    """Serialize a PFG to JSON, validating against the schema first."""
    data = pfg.to_dict()
    validate_pfg(data)
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=False), encoding="utf-8")
