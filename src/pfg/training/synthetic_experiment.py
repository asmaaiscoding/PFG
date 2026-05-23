"""Synthetic-only training experiment with real-world evaluation.

Train Model B entirely on synthetic data, then evaluate on ALL real-world
apps (no real data in training). Compares GNN vs rule baseline on the same
real test set.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import torch

from pfg.eval.harness import (
    evaluate_corpus,
    gnn_detector,
    report_to_dict,
    rule_detector,
)
from pfg.eval.manifest import Manifest, discover_manifests
from pfg.extractors.django.build import build_pfg
from pfg.models.checkpoint import save_model
from pfg.models.gnn import PathAnalyzer
from pfg.synthetic import NUM_SUBTYPES, label_to_targets, pfg_to_pyg, samples_to_pyg
from pfg.synthetic.generator import Sample
from pfg.synthetic.realistic import generate_realistic_dataset
from pfg.training.corpus import PfgCache, samples_from_manifests
from pfg.training.trainer import TrainResult, _class_weights, _split, _train_loop

CLASS_NAMES = [
    "SAFE",
    "MISSING_AUTH",
    "MISSING_ROLE",
    "IDOR",
    "TENANT_ISOLATION_FAILURE",
    "OBJECT_LEVEL_PERMISSION_BYPASS",
    "COMBINED",
    "INTENTIONALLY_PUBLIC",
]
VULNERABLE_CLASS_IDS = {1, 2, 3, 4, 5, 6}


@dataclass(frozen=True)
class SyntheticExperimentOutputs:
    metrics_path: Path
    report_path: Path
    model_path: Path
    metrics: dict[str, Any]


def _class_counts(samples: list[Sample]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for sample in samples:
        _, y = label_to_targets(sample)
        counts[CLASS_NAMES[y]] += 1
    return {name: counts.get(name, 0) for name in CLASS_NAMES}


def _metrics_from_confusion(cm: list[list[int]]) -> dict[str, Any]:
    per_class: dict[str, dict[str, float | int]] = {}
    total = sum(sum(row) for row in cm)
    correct = sum(cm[i][i] for i in range(len(cm)))
    f1s: list[float] = []
    for i, name in enumerate(CLASS_NAMES):
        tp = cm[i][i]
        fp = sum(cm[r][i] for r in range(len(cm)) if r != i)
        fn = sum(cm[i][c] for c in range(len(cm)) if c != i)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        f1s.append(f1)
        per_class[name] = {
            "support": sum(cm[i]),
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }

    vuln_tp = sum(cm[i][j] for i in VULNERABLE_CLASS_IDS for j in VULNERABLE_CLASS_IDS)
    vuln_fp = sum(
        cm[i][j]
        for i in range(len(cm))
        for j in VULNERABLE_CLASS_IDS
        if i not in VULNERABLE_CLASS_IDS
    )
    vuln_fn = sum(
        cm[i][j]
        for i in VULNERABLE_CLASS_IDS
        for j in range(len(cm))
        if j not in VULNERABLE_CLASS_IDS
    )
    vuln_precision = vuln_tp / (vuln_tp + vuln_fp) if (vuln_tp + vuln_fp) else 0.0
    vuln_recall = vuln_tp / (vuln_tp + vuln_fn) if (vuln_tp + vuln_fn) else 0.0
    vuln_f1 = (
        2 * vuln_precision * vuln_recall / (vuln_precision + vuln_recall)
        if (vuln_precision + vuln_recall)
        else 0.0
    )
    return {
        "accuracy": correct / total if total else 0.0,
        "macro_f1": sum(f1s) / len(f1s) if f1s else 0.0,
        "per_class": per_class,
        "vulnerability_finding": {
            "precision": vuln_precision,
            "recall": vuln_recall,
            "f1": vuln_f1,
            "tp": vuln_tp,
            "fp": vuln_fp,
            "fn": vuln_fn,
        },
        "confusion": cm,
    }


def _train_result_to_dict(result: TrainResult) -> dict[str, Any]:
    metrics = _metrics_from_confusion(result.confusion)
    metrics.update({
        "test_accuracy": result.test_accuracy,
        "test_macro_f1": result.test_macro_f1,
        "best_val_loss": result.best_val_loss,
        "history": result.history,
    })
    return metrics


def _predict_samples(model: PathAnalyzer, samples: list[Sample]) -> list[dict[str, Any]]:
    model.eval()
    out: list[dict[str, Any]] = []
    with torch.no_grad():
        for sample in samples:
            data = pfg_to_pyg(sample)
            logits, _attn = model.forward_with_attention(data)
            probs = torch.softmax(logits, dim=-1).squeeze(0)
            predicted_idx = int(probs.argmax().item())
            _, expected_idx = label_to_targets(sample)
            out.append({
                "endpoint_id": sample.target_endpoint_id,
                "expected": CLASS_NAMES[expected_idx],
                "predicted": CLASS_NAMES[predicted_idx],
                "confidence": float(probs[predicted_idx].item()),
                "correct": expected_idx == predicted_idx,
            })
    return out


def _predict_real_samples(
    model: PathAnalyzer,
    manifests: list[Manifest],
    *,
    cache: PfgCache | None = None,
) -> list[dict[str, Any]]:
    """Run GNN predictions on all real endpoints from manifests."""
    real_samples = samples_from_manifests(manifests, cache=cache)
    return _predict_samples(model, real_samples)


# ---------------------------------------------------------------------------
# Main experiment
# ---------------------------------------------------------------------------


def run_synthetic_experiment(
    corpus_root: str | Path,
    *,
    n_apps: int = 15,
    endpoints_per_app: tuple[int, int] = (30, 70),
    vuln_ratio: float = 0.35,
    epochs: int = 40,
    seed: int = 0,
    batch_size: int = 32,
    hidden_dim: int = 64,
    num_layers: int = 3,
    heads: int = 4,
    focal_gamma: float = 2.0,
    gnn_threshold: float = 0.5,
    out_dir: str | Path = "artifacts",
) -> SyntheticExperimentOutputs:
    """Train on synthetic, evaluate on ALL real data.

    1. Generate synthetic dataset (n_apps mini-apps)
    2. Split synthetic 80/10/10 → train/val/test
    3. Train GNN on synthetic only (with focal loss)
    4. Report synthetic test metrics (capability proof)
    5. Evaluate trained GNN on ALL real apps
    6. Compare with rule baseline on same real apps
    """
    # --- Step 1: Generate synthetic data ---
    synthetic_samples = generate_realistic_dataset(
        n_apps=n_apps,
        endpoints_per_app=endpoints_per_app,
        vuln_ratio=vuln_ratio,
        seed=seed,
    )

    # --- Step 2: Split synthetic data ---
    pyg_data = samples_to_pyg(synthetic_samples)
    torch.manual_seed(seed)
    train_data, val_data, test_data = _split(pyg_data, seed=seed)

    from torch_geometric.loader import DataLoader
    train_loader = DataLoader(train_data, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_data, batch_size=batch_size)
    test_loader = DataLoader(test_data, batch_size=batch_size)

    # --- Step 3: Train GNN ---
    dev = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = PathAnalyzer(
        hidden_dim=hidden_dim, num_layers=num_layers, heads=heads, num_classes=NUM_SUBTYPES
    ).to(dev)

    weights = _class_weights(
        (int(d.y_subtype.item()) for d in train_data), num_classes=NUM_SUBTYPES
    )

    synth_result = _train_loop(
        model,
        train_loader,
        val_loader,
        test_loader,
        epochs=epochs,
        lr=1e-3,
        weight_decay=1e-4,
        class_weights=weights,
        num_classes=NUM_SUBTYPES,
        device=dev,
        use_mlflow=False,
        run_name="path_analyzer_synthetic_only",
        focal_gamma=focal_gamma,
    )

    # --- Step 4: Save model ---
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    model_path = out / "path_analyzer_synthetic.pt"
    save_model(
        model,
        model_path,
        kind="path",
        hparams={"hidden_dim": hidden_dim, "num_layers": num_layers, "heads": heads},
    )

    # --- Step 5: Evaluate on ALL real data ---
    all_manifests = discover_manifests(corpus_root)
    pfg_cache: PfgCache = {}

    def cached_build(root: Path):
        resolved = str(Path(root).resolve())
        for (cached_root, _application), pfg in pfg_cache.items():
            if cached_root == resolved:
                return pfg
        return build_pfg(root)

    # Also get per-endpoint predictions on real data. This loads each real PFG
    # once and lets all detector evaluations reuse those parsed graphs.
    real_predictions = _predict_real_samples(model, all_manifests, cache=pfg_cache)

    rule_report = evaluate_corpus(
        all_manifests, rule_detector, detector_name="rule_baseline", build=cached_build
    )
    gnn_report = evaluate_corpus(
        all_manifests,
        gnn_detector(model, threshold=gnn_threshold),
        detector_name="gnn_synthetic",
        build=cached_build,
    )

    # --- Step 6: Assemble metrics ---
    synth_metrics = _train_result_to_dict(synth_result)

    metrics: dict[str, Any] = {
        "experiment": "synthetic_only_training_real_evaluation",
        "model_scope": "Model B / PathAnalyzer — trained on synthetic only",
        "config": {
            "n_apps": n_apps,
            "endpoints_per_app": list(endpoints_per_app),
            "vuln_ratio": vuln_ratio,
            "seed": seed,
            "epochs": epochs,
            "batch_size": batch_size,
            "hidden_dim": hidden_dim,
            "num_layers": num_layers,
            "heads": heads,
            "focal_gamma": focal_gamma,
            "gnn_threshold": gnn_threshold,
        },
        "synthetic_dataset": {
            "total_samples": len(synthetic_samples),
            "n_train": len(train_data),
            "n_val": len(val_data),
            "n_test": len(test_data),
            "class_distribution": _class_counts(synthetic_samples),
        },
        "synthetic_test_metrics": synth_metrics,
        "real_evaluation": {
            "total_real_endpoints": sum(
                len([n for n in __import__("pfg.extractors.django.build", fromlist=["build_pfg"]).build_pfg(m.project_root, application=m.application).nodes if n.type == "endpoint"])
                for m in all_manifests
            ) if False else len(real_predictions),  # avoid double PFG build
            "gnn_synthetic": report_to_dict(gnn_report),
            "rule_baseline": report_to_dict(rule_report),
        },
        "real_predictions": real_predictions,
        "real_error_analysis": [p for p in real_predictions if not p["correct"]],
    }

    metrics_path = out / "synthetic_experiment_metrics.json"
    report_path = out / "synthetic_experiment_report.md"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    report_path.write_text(_render_report(metrics), encoding="utf-8")

    return SyntheticExperimentOutputs(
        metrics_path=metrics_path,
        report_path=report_path,
        model_path=model_path,
        metrics=metrics,
    )


def _render_report(metrics: dict[str, Any]) -> str:
    sd = metrics["synthetic_dataset"]
    sm = metrics["synthetic_test_metrics"]
    gnn = metrics["real_evaluation"]["gnn_synthetic"]
    rule = metrics["real_evaluation"]["rule_baseline"]
    sm_vuln = sm["vulnerability_finding"]
    gnn_apps = gnn.get("apps", [])
    rule_apps = rule.get("apps", [])

    lines = [
        "# Synthetic-Only Training → Real-World Evaluation",
        "",
        "## Methodology",
        "",
        "Model B (PathAnalyzer) trained entirely on synthetic PFGs, then evaluated",
        "on all real-world apps. No real data used in training.",
        "",
        "## Synthetic Dataset",
        "",
        f"- Total samples: {sd['total_samples']}",
        f"- Train / Val / Test: {sd['n_train']} / {sd['n_val']} / {sd['n_test']}",
        f"- Class distribution: {sd['class_distribution']}",
        "",
        "## Synthetic Test Metrics (capability proof)",
        "",
        f"- Accuracy: {sm['accuracy']:.4f}",
        f"- Macro F1: {sm['macro_f1']:.4f}",
        f"- Vuln Precision: {sm_vuln['precision']:.4f}",
        f"- Vuln Recall: {sm_vuln['recall']:.4f}",
        f"- Vuln F1: {sm_vuln['f1']:.4f}",
        "",
        "## Real-World Evaluation",
        "",
        "| System | Precision | Recall | F1 |",
        "| --- | ---: | ---: | ---: |",
        f"| GNN (synthetic) | {gnn['micro_precision']:.4f} | {gnn['micro_recall']:.4f} | {gnn['micro_f1']:.4f} |",
        f"| Rule baseline | {rule['micro_precision']:.4f} | {rule['micro_recall']:.4f} | {rule['micro_f1']:.4f} |",
        "",
        "### Per-App Breakdown",
        "",
        "| App | System | TP | FP | FN |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for app in gnn_apps:
        lines.append(f"| {app['application']} | GNN | {app['tp']} | {app['fp']} | {app['fn']} |")
    for app in rule_apps:
        lines.append(f"| {app['application']} | Rule | {app['tp']} | {app['fp']} | {app['fn']} |")

    lines.extend([
        "",
        "## Conclusion",
        "",
        "Detailed per-endpoint predictions are in `synthetic_experiment_metrics.json`.",
        "",
    ])
    return "\n".join(lines)
