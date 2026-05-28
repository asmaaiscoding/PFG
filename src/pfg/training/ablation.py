"""Ablation experiment: GNN vs MLP baseline, with optional feature decontamination.

Runs on synthetic data with the same train/val/test split. Reports:
  - PathAnalyzer (GNN) accuracy & F1
  - EndpointMLP accuracy & F1
  - Rule baseline accuracy & F1
  - Optionally: decontaminated versions of both

Usage:
  python -m pfg.training.ablation [--n-samples 600] [--epochs 30] [--decontaminate]
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from pfg.synthetic import NUM_SUBTYPES, Sample, generate_dataset
from pfg.training.experiment import evaluate_rule_baseline
from pfg.training.trainer import (
    TrainResult,
    split_indices,
    train_mlp_split,
    train_path_analyzer_split,
)

# Feature indices that leak label information:
# Conservative: features directly derived from vulnerability labels
DECONTAMINATE_CONSERVATIVE = [
    9,   # requires_auth (directly signals missing_auth)
    15,  # ownership_check_present (signals IDOR absence)
    31,  # tenant_check_present (signals tenant isolation)
]

# Aggressive: all features that correlate strongly with vulnerability subtypes
DECONTAMINATE_AGGRESSIVE = [
    9,   # requires_auth
    15,  # ownership_check_present
    23,  # has_ownership_predicate
    27,  # unprotected_data_reachable
    28,  # role_check_present
    29,  # model_permission_check_present
    30,  # object_permission_check_present
    31,  # tenant_check_present
    32,  # has_tenant_scope
    33,  # unscoped_tenant_data_reachable
    34,  # object_permission_data_reachable
    35,  # tenant_object_guard_signal
]


@dataclass
class AblationResult:
    condition: str
    model: str
    test_accuracy: float
    test_macro_f1: float
    best_val_loss: float
    confusion: list[list[int]] = field(default_factory=list)


@dataclass
class AblationReport:
    n_samples: int
    seed: int
    epochs: int
    results: list[dict[str, Any]] = field(default_factory=list)


def _summarize(condition: str, model_name: str, r: TrainResult) -> dict[str, Any]:
    return {
        "condition": condition,
        "model": model_name,
        "test_accuracy": r.test_accuracy,
        "test_macro_f1": r.test_macro_f1,
        "best_val_loss": r.best_val_loss,
        "confusion": r.confusion,
    }


def run_ablation(
    *,
    n_samples: int = 600,
    seed: int = 0,
    epochs: int = 30,
    batch_size: int = 32,
    hidden_dim: int = 64,
    num_layers: int = 3,
    heads: int = 4,
    decontaminate: bool = False,
    out_path: str | Path | None = None,
) -> AblationReport:
    """Run GNN vs MLP ablation, optionally with feature decontamination."""
    samples = generate_dataset(n_samples, seed=seed)

    train_idx, val_idx, test_idx = split_indices(len(samples), seed=seed)
    train_samples = [samples[i] for i in train_idx]
    val_samples = [samples[i] for i in val_idx]
    test_samples = [samples[i] for i in test_idx]

    results: list[dict[str, Any]] = []

    # --- Full features (baseline comparison) ---
    print("=== Full features: GNN (PathAnalyzer) ===")
    _, gnn_metrics = train_path_analyzer_split(
        train_samples, val_samples, test_samples,
        epochs=epochs, batch_size=batch_size, hidden_dim=hidden_dim,
        num_layers=num_layers, heads=heads, seed=seed,
    )
    results.append(_summarize("full_features", "GNN_PathAnalyzer", gnn_metrics))
    print(f"  Acc={gnn_metrics.test_accuracy:.4f}  F1={gnn_metrics.test_macro_f1:.4f}")

    print("=== Full features: MLP (EndpointMLP) ===")
    _, mlp_metrics = train_mlp_split(
        train_samples, val_samples, test_samples,
        epochs=epochs, batch_size=batch_size, hidden_dim=hidden_dim, seed=seed,
    )
    results.append(_summarize("full_features", "MLP_Baseline", mlp_metrics))
    print(f"  Acc={mlp_metrics.test_accuracy:.4f}  F1={mlp_metrics.test_macro_f1:.4f}")

    # Rule baseline
    baseline = evaluate_rule_baseline(test_samples)
    results.append({
        "condition": "full_features",
        "model": "Rule_Baseline",
        "test_accuracy": baseline.test_accuracy_subtype,
        "test_macro_f1": baseline.test_macro_f1_subtype,
        "best_val_loss": None,
        "confusion": baseline.confusion_subtype,
    })
    print(f"=== Full features: Rule Baseline ===")
    print(f"  Acc={baseline.test_accuracy_subtype:.4f}  F1={baseline.test_macro_f1_subtype:.4f}")

    # --- Decontaminated features ---
    if decontaminate:
        for name, indices in [
            ("decontam_conservative", DECONTAMINATE_CONSERVATIVE),
            ("decontam_aggressive", DECONTAMINATE_AGGRESSIVE),
        ]:
            print(f"\n=== {name}: GNN (PathAnalyzer) ===")
            _, gnn_d = train_path_analyzer_split(
                train_samples, val_samples, test_samples,
                epochs=epochs, batch_size=batch_size, hidden_dim=hidden_dim,
                num_layers=num_layers, heads=heads, seed=seed,
                mask_indices=indices,
            )
            results.append(_summarize(name, "GNN_PathAnalyzer", gnn_d))
            print(f"  Acc={gnn_d.test_accuracy:.4f}  F1={gnn_d.test_macro_f1:.4f}")

            print(f"=== {name}: MLP (EndpointMLP) ===")
            _, mlp_d = train_mlp_split(
                train_samples, val_samples, test_samples,
                epochs=epochs, batch_size=batch_size, hidden_dim=hidden_dim, seed=seed,
                mask_indices=indices,
            )
            results.append(_summarize(name, "MLP_Baseline", mlp_d))
            print(f"  Acc={mlp_d.test_accuracy:.4f}  F1={mlp_d.test_macro_f1:.4f}")

    report = AblationReport(n_samples=n_samples, seed=seed, epochs=epochs, results=results)

    if out_path is not None:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")
        print(f"\nResults saved to {out_path}")

    # Print summary table
    print("\n" + "=" * 70)
    print(f"{'Condition':<25} {'Model':<18} {'Accuracy':>10} {'Macro-F1':>10}")
    print("-" * 70)
    for r in results:
        print(f"{r['condition']:<25} {r['model']:<18} {r['test_accuracy']:>10.4f} {r['test_macro_f1']:>10.4f}")
    print("=" * 70)

    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="GNN vs MLP ablation study")
    parser.add_argument("--n-samples", type=int, default=600)
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--decontaminate", action="store_true")
    parser.add_argument("--out", type=str, default="artifacts/ablation_results.json")
    args = parser.parse_args()

    run_ablation(
        n_samples=args.n_samples,
        seed=args.seed,
        epochs=args.epochs,
        decontaminate=args.decontaminate,
        out_path=args.out,
    )
