"""Model checkpoint save / load.

Checkpoints are torch `.pt` files that bundle the model weights *and* the
hyperparameters needed to reconstruct the architecture. The active node/edge
feature contract is stored with each checkpoint so model artifacts remain
auditable as the PFG schema evolves.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import torch

from pfg.models.gnn import PathAnalyzer, PfgAnomalyDetector
from pfg.pfg.features import EDGE_FEATURE_DIM, NODE_FEATURE_DIM
from pfg.synthetic import NUM_SUBTYPES

ModelKind = Literal["anomaly", "path"]


def save_model(
    model: PfgAnomalyDetector | PathAnalyzer,
    path: str | Path,
    *,
    kind: ModelKind,
    hparams: dict[str, Any],
) -> Path:
    """Persist a model + reconstruction hparams. Returns the resolved path."""
    out = Path(path).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "kind": kind,
        "hparams": hparams,
        "state_dict": model.state_dict(),
        "feature_contract": {
            "node_dim": NODE_FEATURE_DIM,
            "edge_dim": EDGE_FEATURE_DIM,
            "num_subtypes": NUM_SUBTYPES,
        },
    }
    torch.save(payload, out)
    return out


def load_model(path: str | Path) -> tuple[PfgAnomalyDetector | PathAnalyzer, dict[str, Any]]:
    """Reconstruct a model from a checkpoint. Returns (model, payload)."""
    payload = torch.load(Path(path).resolve(), map_location="cpu", weights_only=False)
    kind = payload["kind"]
    hp = payload["hparams"]
    model: PfgAnomalyDetector | PathAnalyzer
    if kind == "anomaly":
        model = PfgAnomalyDetector(
            hidden_dim=hp.get("hidden_dim", 64),
            num_layers=hp.get("num_layers", 3),
            dropout=hp.get("dropout", 0.1),
        )
    elif kind == "path":
        model = PathAnalyzer(
            hidden_dim=hp.get("hidden_dim", 64),
            num_layers=hp.get("num_layers", 3),
            heads=hp.get("heads", 4),
            num_classes=hp.get("num_classes", NUM_SUBTYPES),
            dropout=hp.get("dropout", 0.1),
        )
    else:
        raise ValueError(f"unknown checkpoint kind: {kind!r}")
    model.load_state_dict(payload["state_dict"])
    model.eval()
    return model, payload
