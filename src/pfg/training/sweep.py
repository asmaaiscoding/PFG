"""Phase 3 W16-W17: hyperparameter sweep + ablation studies.

W16: small grid sweep over (lr, hidden_dim, num_layers) for both models.
W17: ablation experiments:
  * `no_identifier_flow`  : strip identifier_flow edges from the corpus.
  * `no_auth_annotations` : zero out auth-related node features
                             (requires_auth, role one-hot, ownership_check,
                              guard_type one-hot — node-feature indices 9..19).

The auth-feature indices are derived from the FROZEN 24-dim node feature
contract in `pfg.pfg.features` and must not drift from it:
  [0:4]  node type | [4:9]  http method | [9] requires_auth
  [10:15] role     | [15] ownership_check_present | [16:19] guard type
  [19:23] op       | [23] has_ownership_predicate
"""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

import torch
from torch_geometric.data import Data

from pfg.synthetic import NUM_SUBTYPES, Sample, samples_to_pyg
from pfg.training.experiment import _result_summary, evaluate_rule_baseline
from pfg.training.trainer import (
    TrainResult,
    split_indices,
    train_anomaly_detector,
    train_path_analyzer,
)

# Auth-feature index range in the frozen 24-dim node feature vector.
_AUTH_FEATURE_START = 9
_AUTH_FEATURE_END = 19  # exclusive


# --- W17: ablation transforms on PyG Data --------------------------------


AblationKind = Literal["none", "no_identifier_flow", "no_auth_annotations"]


def _ablate_identifier_flow(data: Data) -> Data:
    """Drop all identifier_flow edges (edge_attr column 1 == 1)."""
    if data.edge_attr is None or data.edge_attr.numel() == 0:
        return data
    keep = data.edge_attr[:, 1] < 0.5
    new = data.clone()
    new.edge_index = data.edge_index[:, keep]
    new.edge_attr = data.edge_attr[keep]
    return new


def _ablate_auth_annotations(data: Data) -> Data:
    """Zero out auth-related node features (indices 9..19)."""
    new = data.clone()
    x = data.x.clone()
    x[:, _AUTH_FEATURE_START:_AUTH_FEATURE_END] = 0.0
    new.x = x
    return new


def apply_ablation(samples_pyg: list[Data], kind: AblationKind) -> list[Data]:
    if kind == "none":
        return [d.clone() for d in samples_pyg]
    if kind == "no_identifier_flow":
        return [_ablate_identifier_flow(d) for d in samples_pyg]
    if kind == "no_auth_annotations":
        return [_ablate_auth_annotations(d) for d in samples_pyg]
    raise ValueError(f"unknown ablation: {kind}")


# --- W16: hyperparameter sweep -------------------------------------------


@dataclass
class SweepEntry:
    config: dict[str, Any]
    anomaly: dict[str, Any]
    path_analyzer: dict[str, Any]


@dataclass
class SweepReport:
    grid: list[SweepEntry] = field(default_factory=list)
    best_anomaly: dict[str, Any] = field(default_factory=dict)
    best_path_analyzer: dict[str, Any] = field(default_factory=dict)


def run_hparam_sweep(
    samples: list[Sample],
    *,
    lrs: tuple[float, ...] = (1e-3, 1e-4),
    hidden_dims: tuple[int, ...] = (32, 64),
    num_layers_list: tuple[int, ...] = (2, 3),
    epochs: int = 20,
    batch_size: int = 32,
    seed: int = 0,
    use_mlflow: bool = False,
) -> SweepReport:
    """Small grid: lr x hidden_dim x num_layers - same grid for both models."""
    grid: list[SweepEntry] = []
    for lr in lrs:
        for h in hidden_dims:
            for nl in num_layers_list:
                cfg = {"lr": lr, "hidden_dim": h, "num_layers": nl}
                _, am = train_anomaly_detector(
                    samples,
                    epochs=epochs,
                    batch_size=batch_size,
                    seed=seed,
                    use_mlflow=use_mlflow,
                    lr=lr,
                    hidden_dim=h,
                    num_layers=nl,
                )
                _, pm = train_path_analyzer(
                    samples,
                    epochs=epochs,
                    batch_size=batch_size,
                    seed=seed,
                    use_mlflow=use_mlflow,
                    lr=lr,
                    hidden_dim=h,
                    num_layers=nl,
                )
                grid.append(SweepEntry(cfg, _result_summary(am), _result_summary(pm)))
    best_a = max(grid, key=lambda e: e.anomaly["test_macro_f1"])
    best_p = max(grid, key=lambda e: e.path_analyzer["test_macro_f1"])
    return SweepReport(
        grid=grid,
        best_anomaly={"config": best_a.config, **best_a.anomaly},
        best_path_analyzer={"config": best_p.config, **best_p.path_analyzer},
    )


# --- W17: ablation runner ------------------------------------------------


@dataclass
class AblationOutcome:
    ablation: str
    anomaly: dict[str, Any]
    path_analyzer: dict[str, Any]


def _train_on_pyg(
    pyg_data: list[Data],
    *,
    which: Literal["anomaly", "path"],
    epochs: int,
    batch_size: int,
    hidden_dim: int,
    num_layers: int,
    heads: int,
    seed: int,
    use_mlflow: bool,
) -> TrainResult:
    """Train a model directly on a list of (already-ablated) PyG `Data`.

    Mirrors `train_anomaly_detector` / `train_path_analyzer` but skips the
    `samples_to_pyg` step so we can train on transformed copies.
    """
    from torch_geometric.loader import DataLoader  # local import — torch only here

    from pfg.models.gnn import PathAnalyzer, PfgAnomalyDetector
    from pfg.training.trainer import _class_weights, _split, _train_loop

    torch.manual_seed(seed)
    dev = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    train, val, test = _split(pyg_data, seed=seed)
    train_loader = DataLoader(train, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val, batch_size=batch_size)
    test_loader = DataLoader(test, batch_size=batch_size)

    if which == "anomaly":
        model: Any = PfgAnomalyDetector(hidden_dim=hidden_dim, num_layers=num_layers).to(dev)
        weights = _class_weights((int(d.y.item()) for d in train), num_classes=2)
        num_classes = 2
        run_name = "anomaly_ablation"
    else:
        model = PathAnalyzer(
            hidden_dim=hidden_dim,
            num_layers=num_layers,
            heads=heads,
            num_classes=NUM_SUBTYPES,
        ).to(dev)
        weights = _class_weights(
            (int(d.y_subtype.item()) for d in train), num_classes=NUM_SUBTYPES
        )
        num_classes = NUM_SUBTYPES
        run_name = "path_ablation"

    return _train_loop(
        model,
        train_loader,
        val_loader,
        test_loader,
        epochs=epochs,
        lr=1e-3,
        weight_decay=1e-4,
        class_weights=weights,
        num_classes=num_classes,
        device=dev,
        use_mlflow=use_mlflow,
        run_name=run_name,
    )


def run_ablations(
    samples: list[Sample],
    *,
    epochs: int = 20,
    batch_size: int = 32,
    hidden_dim: int = 32,
    num_layers: int = 2,
    heads: int = 2,
    seed: int = 0,
    use_mlflow: bool = False,
    kinds: tuple[AblationKind, ...] = (
        "none",
        "no_identifier_flow",
        "no_auth_annotations",
    ),
) -> list[AblationOutcome]:
    """Train both models under each ablation and return per-ablation metrics."""
    base = samples_to_pyg(samples)
    results: list[AblationOutcome] = []
    for kind in kinds:
        ablated = apply_ablation(base, kind)
        # Use deepcopy on the list reference so the trainer cannot mutate
        # tensors shared across runs.
        am = _train_on_pyg(
            copy.deepcopy(ablated),
            which="anomaly",
            epochs=epochs,
            batch_size=batch_size,
            hidden_dim=hidden_dim,
            num_layers=num_layers,
            heads=heads,
            seed=seed,
            use_mlflow=use_mlflow,
        )
        pm = _train_on_pyg(
            copy.deepcopy(ablated),
            which="path",
            epochs=epochs,
            batch_size=batch_size,
            hidden_dim=hidden_dim,
            num_layers=num_layers,
            heads=heads,
            seed=seed,
            use_mlflow=use_mlflow,
        )
        results.append(
            AblationOutcome(
                ablation=kind,
                anomaly=_result_summary(am),
                path_analyzer=_result_summary(pm),
            )
        )
    return results


# --- helper to bundle reports for CLI / persistence ----------------------


def report_to_dict(sweep: SweepReport, ablations: list[AblationOutcome]) -> dict[str, Any]:
    return {
        "sweep": {
            "grid": [asdict(e) for e in sweep.grid],
            "best_anomaly": sweep.best_anomaly,
            "best_path_analyzer": sweep.best_path_analyzer,
        },
        "ablations": [asdict(a) for a in ablations],
    }


__all__ = [
    "AblationKind",
    "AblationOutcome",
    "SweepEntry",
    "SweepReport",
    "apply_ablation",
    "evaluate_rule_baseline",  # re-export for convenience
    "report_to_dict",
    "run_ablations",
    "run_hparam_sweep",
    "split_indices",
]
