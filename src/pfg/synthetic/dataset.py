"""PFG -> PyTorch Geometric `Data` conversion (Phase 3).

Optional dependency: torch + torch_geometric. The conversion module is
importable without them — the actual `pfg_to_pyg` function will raise a
helpful error if the deps are missing.

Two graph-level label heads are produced per sample:

  y_binary   : 0 = not vulnerable, 1 = vulnerable
                 (INTENTIONALLY_PUBLIC counts as not-vulnerable)
  y_subtype  : 0 SAFE, 1 MISSING_AUTH, 2 MISSING_ROLE, 3 IDOR,
               4 TENANT_ISOLATION_FAILURE,
               5 OBJECT_LEVEL_PERMISSION_BYPASS,
               6 COMBINED, 7 INTENTIONALLY_PUBLIC

A node-level mask `target_mask` (1 on the target endpoint, else 0) is also
attached so Model B (path-wise) can pool around it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pfg.pfg.features import EDGE_FEATURE_DIM, NODE_FEATURE_DIM, encode_edge, encode_node
from pfg.pfg.nodes import LabelKind, VulnSubtype
from pfg.synthetic.generator import Sample

if TYPE_CHECKING:  # pragma: no cover
    from torch_geometric.data import Data


_SUBTYPE_INDEX = {
    "SAFE": 0,
    VulnSubtype.MISSING_AUTH.value: 1,
    VulnSubtype.MISSING_ROLE.value: 2,
    VulnSubtype.IDOR.value: 3,
    VulnSubtype.TENANT_ISOLATION_FAILURE.value: 4,
    VulnSubtype.OBJECT_LEVEL_PERMISSION_BYPASS.value: 5,
    VulnSubtype.COMBINED.value: 6,
    LabelKind.INTENTIONALLY_PUBLIC.value: 7,
}
NUM_SUBTYPES = 8


def label_to_targets(sample: Sample) -> tuple[int, int]:
    """Return `(y_binary, y_subtype)` for a labeled sample."""
    label = sample.label
    if label.label == LabelKind.VULNERABLE.value:
        sub = label.subtype if isinstance(label.subtype, str) else (
            label.subtype.value if label.subtype is not None else "SAFE"
        )
        return 1, _SUBTYPE_INDEX.get(sub, 0)
    if label.label == LabelKind.INTENTIONALLY_PUBLIC.value:
        return 0, _SUBTYPE_INDEX[LabelKind.INTENTIONALLY_PUBLIC.value]
    return 0, 0  # SAFE


def pfg_to_pyg(sample: Sample) -> Data:
    """Convert one labeled `Sample` to a PyG `Data` object."""
    try:
        import torch
        from torch_geometric.data import Data
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "torch and torch_geometric are required. "
            "Install with: uv sync --extra ml"
        ) from exc

    pfg = sample.pfg
    node_id_to_idx = {n.id: i for i, n in enumerate(pfg.nodes)}

    x = torch.tensor([encode_node(n) for n in pfg.nodes], dtype=torch.float32)
    assert x.shape[1] == NODE_FEATURE_DIM

    if pfg.edges:
        src = [node_id_to_idx[e.src] for e in pfg.edges]
        dst = [node_id_to_idx[e.dst] for e in pfg.edges]
        edge_index = torch.tensor([src, dst], dtype=torch.long)
        edge_attr = torch.tensor(
            [encode_edge(e.type) for e in pfg.edges], dtype=torch.float32
        )
        assert edge_attr.shape[1] == EDGE_FEATURE_DIM
    else:
        edge_index = torch.zeros((2, 0), dtype=torch.long)
        edge_attr = torch.zeros((0, EDGE_FEATURE_DIM), dtype=torch.float32)

    target_mask = torch.zeros(len(pfg.nodes), dtype=torch.float32)
    if sample.target_endpoint_id in node_id_to_idx:
        target_mask[node_id_to_idx[sample.target_endpoint_id]] = 1.0

    y_bin, y_sub = label_to_targets(sample)

    return Data(
        x=x,
        edge_index=edge_index,
        edge_attr=edge_attr,
        target_mask=target_mask,
        y=torch.tensor([y_bin], dtype=torch.long),
        y_subtype=torch.tensor([y_sub], dtype=torch.long),
    )


def samples_to_pyg(samples: list[Sample]) -> list[Data]:
    return [pfg_to_pyg(s) for s in samples]
