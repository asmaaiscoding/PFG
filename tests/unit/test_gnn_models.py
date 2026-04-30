"""Phase 3 W13-W14 gate: GNN models forward pass + can-learn smoke."""
from __future__ import annotations

import pytest

torch = pytest.importorskip("torch")
pyg = pytest.importorskip("torch_geometric")

from torch_geometric.loader import DataLoader  # noqa: E402

from pfg.models import PathAnalyzer, PfgAnomalyDetector  # noqa: E402
from pfg.synthetic import generate_dataset, samples_to_pyg  # noqa: E402
from pfg.training import train_anomaly_detector, train_path_analyzer  # noqa: E402


def test_anomaly_detector_forward_shape() -> None:
    samples = generate_dataset(8, seed=0)
    data = samples_to_pyg(samples)
    loader = DataLoader(data, batch_size=4)
    model = PfgAnomalyDetector(hidden_dim=16, num_layers=2)
    for batch in loader:
        out = model(batch)
        assert out.shape == (batch.num_graphs, 2)
        break


def test_path_analyzer_forward_shape() -> None:
    samples = generate_dataset(8, seed=0)
    data = samples_to_pyg(samples)
    loader = DataLoader(data, batch_size=4)
    model = PathAnalyzer(hidden_dim=16, num_layers=2, heads=2, num_classes=6)
    for batch in loader:
        out = model(batch)
        assert out.shape == (batch.num_graphs, 6)
        break


def test_anomaly_detector_learns_synthetic() -> None:
    """Smoke: Model A should easily clear 75% on this trivial synthetic split."""
    samples = generate_dataset(240, seed=1)
    _, metrics = train_anomaly_detector(
        samples, epochs=30, batch_size=32, hidden_dim=32, num_layers=2, seed=1
    )
    assert metrics.test_accuracy >= 0.75, f"acc={metrics.test_accuracy:.3f}"


def test_path_analyzer_learns_synthetic() -> None:
    samples = generate_dataset(180, seed=2)
    _, metrics = train_path_analyzer(
        samples,
        epochs=25,
        batch_size=16,
        hidden_dim=32,
        num_layers=2,
        heads=2,
        seed=2,
    )
    # 6-class classification on a deliberately easy synthetic distribution.
    assert metrics.test_macro_f1 >= 0.5, f"f1={metrics.test_macro_f1:.3f}"
