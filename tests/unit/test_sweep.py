"""Phase 3 W16+W17 gate: HP sweep and ablation studies."""
from __future__ import annotations

import pytest

pytest.importorskip("torch")
pytest.importorskip("torch_geometric")

from pfg.synthetic import generate_dataset, samples_to_pyg
from pfg.training import (
    apply_ablation,
    run_ablations,
    run_hparam_sweep,
)


def test_apply_ablation_no_identifier_flow_drops_idflow_edges() -> None:
    samples = generate_dataset(20, seed=0)
    pyg = samples_to_pyg(samples)
    ablated = apply_ablation(pyg, "no_identifier_flow")
    for d in ablated:
        if d.edge_attr.numel() == 0:
            continue
        # Column 1 of edge_attr is the identifier_flow indicator.
        assert d.edge_attr[:, 1].sum().item() == 0.0


def test_apply_ablation_no_auth_zeros_auth_features() -> None:
    samples = generate_dataset(20, seed=0)
    pyg = samples_to_pyg(samples)
    ablated = apply_ablation(pyg, "no_auth_annotations")
    for d in ablated:
        # Auth features live at indices 9..19 (frozen contract).
        assert d.x[:, 9:19].abs().sum().item() == 0.0


def test_run_hparam_sweep_smoke() -> None:
    samples = generate_dataset(120, seed=0)
    report = run_hparam_sweep(
        samples,
        lrs=(1e-3,),
        hidden_dims=(16,),
        num_layers_list=(2,),
        epochs=4,
        batch_size=16,
        seed=0,
    )
    assert len(report.grid) == 1
    assert "config" in report.best_anomaly
    assert 0.0 <= report.best_anomaly["test_macro_f1"] <= 1.0


def test_run_ablations_smoke() -> None:
    samples = generate_dataset(120, seed=0)
    outcomes = run_ablations(
        samples, epochs=4, batch_size=16, hidden_dim=16, num_layers=2, heads=2, seed=0
    )
    kinds = {o.ablation for o in outcomes}
    assert kinds == {"none", "no_identifier_flow", "no_auth_annotations"}
    for o in outcomes:
        assert 0.0 <= o.anomaly["test_macro_f1"] <= 1.0
        assert 0.0 <= o.path_analyzer["test_macro_f1"] <= 1.0
