"""Training utilities for Models A and B (Phase 3 W14-W15).

Provides:
  * train_anomaly_detector(samples, ...) -> (model, metrics)
  * train_path_analyzer(samples, ...)    -> (model, metrics)

Both functions:
  * shuffle the dataset deterministically given a seed,
  * split 80/10/10 train/val/test,
  * run AdamW optimization with class-weighted CrossEntropyLoss,
  * record per-epoch train/val metrics,
  * optionally log everything to MLflow (turned on with `use_mlflow=True`).

Returned metrics include test accuracy, per-class F1, confusion matrix, and
the best epoch's validation loss.
"""

from __future__ import annotations

import math
import random
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import torch
from torch.nn import functional as F  # noqa: N812
from torch.optim import AdamW
from torch_geometric.data import Data
from torch_geometric.loader import DataLoader

from pfg.models.gnn import PathAnalyzer, PfgAnomalyDetector
from pfg.synthetic import NUM_SUBTYPES, Sample, samples_to_pyg

# --- public types ---------------------------------------------------------


@dataclass
class TrainResult:
    """Metrics returned from a training run."""

    test_accuracy: float
    test_macro_f1: float
    best_val_loss: float
    history: list[dict[str, float]] = field(default_factory=list)
    confusion: list[list[int]] = field(default_factory=list)


# --- helpers --------------------------------------------------------------


def split_indices(
    n: int, *, seed: int, ratios: tuple[float, float, float] = (0.8, 0.1, 0.1)
) -> tuple[list[int], list[int], list[int]]:
    """Deterministic train/val/test index split. Shared across trainer + eval."""
    rng = random.Random(seed)
    idx = list(range(n))
    rng.shuffle(idx)
    n_train = int(n * ratios[0])
    n_val = int(n * ratios[1])
    return (
        idx[:n_train],
        idx[n_train : n_train + n_val],
        idx[n_train + n_val :],
    )


def _split(
    data: list[Data], *, seed: int, ratios: tuple[float, float, float] = (0.8, 0.1, 0.1)
) -> tuple[list[Data], list[Data], list[Data]]:
    tr, va, te = split_indices(len(data), seed=seed, ratios=ratios)
    return [data[i] for i in tr], [data[i] for i in va], [data[i] for i in te]


def _class_weights(labels: Iterable[int], num_classes: int) -> torch.Tensor:
    counts = [0] * num_classes
    for y in labels:
        counts[int(y)] += 1
    total = sum(counts)
    # Inverse-frequency, normalized so weights average ~1.
    w = [
        (total / (num_classes * c)) if c > 0 else 0.0
        for c in counts
    ]
    return torch.tensor(w, dtype=torch.float32)


def _confusion_matrix(preds: list[int], targets: list[int], k: int) -> list[list[int]]:
    cm = [[0] * k for _ in range(k)]
    for p, t in zip(preds, targets, strict=True):
        cm[t][p] += 1
    return cm


def _macro_f1(cm: list[list[int]]) -> float:
    k = len(cm)
    f1s: list[float] = []
    for c in range(k):
        tp = cm[c][c]
        fp = sum(cm[r][c] for r in range(k) if r != c)
        fn = sum(cm[c][r] for r in range(k) if r != c)
        if tp == 0:
            f1s.append(0.0)
            continue
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1s.append((2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0)
    return sum(f1s) / k if k else 0.0


def _y_field(model: Any) -> str:
    return "y_subtype" if isinstance(model, PathAnalyzer) else "y"


def _focal_loss(
    logits: torch.Tensor,
    targets: torch.Tensor,
    weight: torch.Tensor,
    gamma: float = 2.0,
) -> torch.Tensor:
    """Focal loss (Lin et al., 2017) with class weights."""
    ce = F.cross_entropy(logits, targets, weight=weight, reduction="none")
    pt = torch.exp(-ce)
    return ((1 - pt) ** gamma * ce).mean()


def _eval(
    model: Any, loader: DataLoader, device: torch.device, num_classes: int
) -> tuple[float, float, list[list[int]], list[int], list[int]]:
    model.eval()
    losses = 0.0
    n = 0
    y_field = _y_field(model)
    preds: list[int] = []
    targets: list[int] = []
    with torch.no_grad():
        for batch in loader:
            batch = batch.to(device)
            logits = model(batch)
            y = getattr(batch, y_field).view(-1)
            losses += float(F.cross_entropy(logits, y, reduction="sum").item())
            n += int(y.numel())
            preds.extend(logits.argmax(dim=-1).cpu().tolist())
            targets.extend(y.cpu().tolist())
    avg_loss = losses / max(n, 1)
    cm = _confusion_matrix(preds, targets, num_classes)
    f1 = _macro_f1(cm)
    return avg_loss, f1, cm, preds, targets


def _train_loop(
    model: Any,
    train_loader: DataLoader,
    val_loader: DataLoader,
    test_loader: DataLoader,
    *,
    epochs: int,
    lr: float,
    weight_decay: float,
    class_weights: torch.Tensor,
    num_classes: int,
    device: torch.device,
    use_mlflow: bool,
    run_name: str,
    focal_gamma: float = 0.0,
) -> TrainResult:
    optim = AdamW(model.parameters(), lr=lr, weight_decay=weight_decay)
    y_field = _y_field(model)
    weights = class_weights.to(device)
    history: list[dict[str, float]] = []
    best_val = math.inf
    best_state: dict[str, torch.Tensor] | None = None

    mlflow_run = None
    if use_mlflow:
        try:
            import mlflow

            mlflow_run = mlflow.start_run(run_name=run_name)
            mlflow.log_params(
                {"epochs": epochs, "lr": lr, "weight_decay": weight_decay, "num_classes": num_classes}
            )
        except Exception:  # pragma: no cover - mlflow is optional
            mlflow_run = None

    for epoch in range(1, epochs + 1):
        model.train()
        running = 0.0
        n = 0
        for batch in train_loader:
            batch = batch.to(device)
            optim.zero_grad()
            logits = model(batch)
            y = getattr(batch, y_field).view(-1)
            if focal_gamma > 0.0:
                loss = _focal_loss(logits, y, weights, focal_gamma)
            else:
                loss = F.cross_entropy(logits, y, weight=weights)
            loss.backward()  # type: ignore[no-untyped-call]
            optim.step()
            running += float(loss.item()) * int(y.numel())
            n += int(y.numel())
        train_loss = running / max(n, 1)

        val_loss, val_f1, _, _, _ = _eval(model, val_loader, device, num_classes)
        history.append({"epoch": epoch, "train_loss": train_loss, "val_loss": val_loss, "val_f1": val_f1})
        if mlflow_run is not None:  # pragma: no cover
            try:
                import mlflow

                mlflow.log_metrics({"train_loss": train_loss, "val_loss": val_loss, "val_f1": val_f1}, step=epoch)
            except Exception:
                pass
        if val_loss < best_val:
            best_val = val_loss
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}

    if best_state is not None:
        model.load_state_dict(best_state)
    test_loss, test_f1, cm, preds, targets = _eval(model, test_loader, device, num_classes)
    test_acc = (
        sum(1 for p, t in zip(preds, targets, strict=True) if p == t) / len(preds)
        if preds
        else 0.0
    )

    if mlflow_run is not None:  # pragma: no cover
        try:
            import mlflow

            mlflow.log_metrics({"test_loss": test_loss, "test_acc": test_acc, "test_f1": test_f1})
            mlflow.end_run()
        except Exception:
            pass

    return TrainResult(
        test_accuracy=test_acc,
        test_macro_f1=test_f1,
        best_val_loss=best_val,
        history=history,
        confusion=cm,
    )


# --- public API -----------------------------------------------------------


def train_anomaly_detector(
    samples: list[Sample],
    *,
    epochs: int = 30,
    lr: float = 1e-3,
    weight_decay: float = 1e-4,
    batch_size: int = 16,
    seed: int = 0,
    use_mlflow: bool = False,
    device: str | None = None,
    hidden_dim: int = 64,
    num_layers: int = 3,
) -> tuple[PfgAnomalyDetector, TrainResult]:
    """Train Model A. Returns the trained model and test metrics."""
    torch.manual_seed(seed)
    dev = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))
    data = samples_to_pyg(samples)
    train, val, test = _split(data, seed=seed)
    train_loader = DataLoader(train, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val, batch_size=batch_size)
    test_loader = DataLoader(test, batch_size=batch_size)

    model = PfgAnomalyDetector(hidden_dim=hidden_dim, num_layers=num_layers).to(dev)
    weights = _class_weights((int(d.y.item()) for d in train), num_classes=2)
    metrics = _train_loop(
        model,
        train_loader,
        val_loader,
        test_loader,
        epochs=epochs,
        lr=lr,
        weight_decay=weight_decay,
        class_weights=weights,
        num_classes=2,
        device=dev,
        use_mlflow=use_mlflow,
        run_name="anomaly_detector",
    )
    return model, metrics


def train_path_analyzer(
    samples: list[Sample],
    *,
    epochs: int = 30,
    lr: float = 1e-3,
    weight_decay: float = 1e-4,
    batch_size: int = 16,
    seed: int = 0,
    use_mlflow: bool = False,
    device: str | None = None,
    hidden_dim: int = 64,
    num_layers: int = 3,
    heads: int = 4,
) -> tuple[PathAnalyzer, TrainResult]:
    """Train Model B. Returns the trained model and test metrics."""
    torch.manual_seed(seed)
    dev = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))
    data = samples_to_pyg(samples)
    train, val, test = _split(data, seed=seed)
    train_loader = DataLoader(train, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val, batch_size=batch_size)
    test_loader = DataLoader(test, batch_size=batch_size)

    model = PathAnalyzer(
        hidden_dim=hidden_dim, num_layers=num_layers, heads=heads, num_classes=NUM_SUBTYPES
    ).to(dev)
    weights = _class_weights(
        (int(d.y_subtype.item()) for d in train), num_classes=NUM_SUBTYPES
    )
    metrics = _train_loop(
        model,
        train_loader,
        val_loader,
        test_loader,
        epochs=epochs,
        lr=lr,
        weight_decay=weight_decay,
        class_weights=weights,
        num_classes=NUM_SUBTYPES,
        device=dev,
        use_mlflow=use_mlflow,
        run_name="path_analyzer",
    )
    return model, metrics


def train_path_analyzer_split(
    train_samples: list[Sample],
    val_samples: list[Sample],
    test_samples: list[Sample],
    *,
    epochs: int = 30,
    lr: float = 1e-3,
    weight_decay: float = 1e-4,
    batch_size: int = 16,
    seed: int = 0,
    use_mlflow: bool = False,
    device: str | None = None,
    hidden_dim: int = 64,
    num_layers: int = 3,
    heads: int = 4,
    focal_gamma: float = 0.0,
    pretrained_state: dict[str, torch.Tensor] | None = None,
) -> tuple[PathAnalyzer, TrainResult]:
    """Train Model B with pre-split samples.

    Use this for real corpora so split boundaries can be defined at the
    app/advisory level before endpoints are converted into PyG samples.

    If *pretrained_state* is supplied, the model loads those weights before
    fine-tuning (two-stage training).
    """
    if not train_samples or not val_samples or not test_samples:
        raise ValueError("train, val, and test sample lists must all be non-empty")
    torch.manual_seed(seed)
    dev = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))
    train = samples_to_pyg(train_samples)
    val = samples_to_pyg(val_samples)
    test = samples_to_pyg(test_samples)

    train_loader = DataLoader(train, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val, batch_size=batch_size)
    test_loader = DataLoader(test, batch_size=batch_size)

    model = PathAnalyzer(
        hidden_dim=hidden_dim, num_layers=num_layers, heads=heads, num_classes=NUM_SUBTYPES
    ).to(dev)
    if pretrained_state is not None:
        model.load_state_dict(pretrained_state, strict=False)
    weights = _class_weights(
        (int(d.y_subtype.item()) for d in train), num_classes=NUM_SUBTYPES
    )
    metrics = _train_loop(
        model,
        train_loader,
        val_loader,
        test_loader,
        epochs=epochs,
        lr=lr,
        weight_decay=weight_decay,
        class_weights=weights,
        num_classes=NUM_SUBTYPES,
        device=dev,
        use_mlflow=use_mlflow,
        run_name="path_analyzer_real_corpus",
        focal_gamma=focal_gamma,
    )
    return model, metrics


def pretrain_path_analyzer(
    samples: list[Sample],
    *,
    epochs: int = 20,
    lr: float = 1e-3,
    weight_decay: float = 1e-4,
    batch_size: int = 32,
    seed: int = 0,
    device: str | None = None,
    hidden_dim: int = 64,
    num_layers: int = 3,
    heads: int = 4,
    focal_gamma: float = 2.0,
) -> dict[str, torch.Tensor]:
    """Pre-train Model B on synthetic data and return the state_dict.

    This is stage 1 of two-stage training. The returned state_dict can be
    passed as *pretrained_state* to ``train_path_analyzer_split``.
    """
    torch.manual_seed(seed)
    dev = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))
    data = samples_to_pyg(samples)
    train, val, test = _split(data, seed=seed)
    train_loader = DataLoader(train, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val, batch_size=batch_size)
    test_loader = DataLoader(test, batch_size=batch_size)

    model = PathAnalyzer(
        hidden_dim=hidden_dim, num_layers=num_layers, heads=heads, num_classes=NUM_SUBTYPES
    ).to(dev)
    weights = _class_weights(
        (int(d.y_subtype.item()) for d in train), num_classes=NUM_SUBTYPES
    )
    _train_loop(
        model,
        train_loader,
        val_loader,
        test_loader,
        epochs=epochs,
        lr=lr,
        weight_decay=weight_decay,
        class_weights=weights,
        num_classes=NUM_SUBTYPES,
        device=dev,
        use_mlflow=False,
        run_name="path_analyzer_pretrain_synthetic",
        focal_gamma=focal_gamma,
    )
    return {k: v.cpu().clone() for k, v in model.state_dict().items()}
