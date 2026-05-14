"""Bridging experiment: synthetic pretrain → real fine-tune.

Loads a synthetic-pretrained PathAnalyzer and fine-tunes it on real data
using leave-one-app-out cross-validation.  Compares three systems on each
holdout app:

  1. **Synthetic-only GNN** (no fine-tuning — baseline for domain gap)
  2. **Fine-tuned GNN** (synthetic pretrain → real fine-tune)
  3. **Rule baseline** (deterministic graph traversal)

This bridges the gap between synthetic training (high recall, massive FPs)
and real-world deployment (needs precision).
"""

from __future__ import annotations

import json
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
from pfg.models.checkpoint import load_model, save_model
from pfg.models.gnn import PathAnalyzer
from pfg.pfg.nodes import LabelKind
from pfg.synthetic import NUM_SUBTYPES
from pfg.synthetic.realistic import generate_realistic_dataset
from pfg.training.corpus import (
    samples_from_manifests,
)
from pfg.training.trainer import train_path_analyzer_split


@dataclass(frozen=True)
class BridgingExperimentOutputs:
    metrics_path: Path
    report_path: Path
    model_dir: Path
    metrics: dict[str, Any]


def _app_groups(manifests: list[Manifest]) -> list[str]:
    """Distinct holdout groups (application names) in corpus order."""
    seen: set[str] = set()
    groups: list[str] = []
    for m in manifests:
        g = m.dataset_split_group or m.application
        if g not in seen:
            seen.add(g)
            groups.append(g)
    return groups


def _run_fold(
    fold_name: str,
    train_samples: list,
    val_samples: list,
    test_manifests: list[Manifest],
    synth_state: dict[str, torch.Tensor],
    synth_vuln_samples: list,
    *,
    epochs: int,
    lr: float,
    focal_gamma: float,
    batch_size: int,
    hidden_dim: int,
    num_layers: int,
    heads: int,
    gnn_threshold: float,
    seed: int,
) -> dict[str, Any]:
    """Train + evaluate one leave-one-out fold."""
    test_samples = samples_from_manifests(test_manifests)

    # Mix synthetic vulnerable samples into training to maintain vuln knowledge
    mixed_train = [*train_samples, *synth_vuln_samples]

    # --- Fine-tuned GNN (synthetic pretrain → real fine-tune) ---
    finetuned_model, ft_result = train_path_analyzer_split(
        mixed_train,
        val_samples,
        test_samples,
        epochs=epochs,
        lr=lr,
        weight_decay=1e-4,
        batch_size=batch_size,
        seed=seed,
        hidden_dim=hidden_dim,
        num_layers=num_layers,
        heads=heads,
        focal_gamma=focal_gamma,
        pretrained_state=synth_state,
        freeze_encoder=True,
    )

    # --- Evaluate all three systems on the holdout app(s) ---
    ft_report = evaluate_corpus(
        test_manifests,
        gnn_detector(finetuned_model, threshold=gnn_threshold),
        detector_name="gnn_finetuned",
    )
    rule_report = evaluate_corpus(
        test_manifests,
        rule_detector,
        detector_name="rule_baseline",
    )

    # --- Also run synthetic-only model on holdout ---
    synth_model = PathAnalyzer(
        hidden_dim=hidden_dim, num_layers=num_layers, heads=heads, num_classes=NUM_SUBTYPES
    )
    synth_model.load_state_dict(synth_state)
    synth_model.eval()
    synth_report = evaluate_corpus(
        test_manifests,
        gnn_detector(synth_model, threshold=gnn_threshold),
        detector_name="gnn_synthetic_only",
    )

    return {
        "fold": fold_name,
        "n_train_real": len(train_samples),
        "n_train_synth_vuln": len(synth_vuln_samples),
        "n_train_total": len(mixed_train),
        "n_val": len(val_samples),
        "n_test": len(test_samples),
        "finetuned": report_to_dict(ft_report),
        "synthetic_only": report_to_dict(synth_report),
        "rule_baseline": report_to_dict(rule_report),
        "finetuned_train_result": {
            "test_accuracy": ft_result.test_accuracy,
            "test_macro_f1": ft_result.test_macro_f1,
            "best_val_loss": ft_result.best_val_loss,
        },
        "model": finetuned_model,
    }


def run_bridging_experiment(
    corpus_root: str | Path,
    *,
    synth_model_path: str | Path | None = None,
    n_synth_apps: int = 5,
    synth_vuln_ratio: float = 0.8,
    epochs: int = 15,
    lr: float = 5e-5,
    focal_gamma: float = 2.0,
    batch_size: int = 16,
    hidden_dim: int = 64,
    num_layers: int = 3,
    heads: int = 4,
    gnn_threshold: float = 0.5,
    seed: int = 0,
    out_dir: str | Path = "artifacts",
) -> BridgingExperimentOutputs:
    """Synthetic pretrain → mixed fine-tune with leave-one-app-out CV.

    1. Load synthetic pretrained model
    2. Generate small set of synthetic vulnerable samples (knowledge anchors)
    3. For each real app as holdout:
       a. Fine-tune pretrained model on real data + synthetic vulns
       b. Evaluate fine-tuned, synthetic-only, and rule baseline on holdout
    4. Aggregate results across all folds
    """
    # --- Step 1: Load synthetic pretrained state ---
    if synth_model_path is None:
        synth_model_path = Path("artifacts/synthetic-v1/path_analyzer_synthetic.pt")
    synth_model_path = Path(synth_model_path)
    if not synth_model_path.exists():
        raise ValueError(
            f"Synthetic model not found at {synth_model_path}. "
            "Run 'pfg synthetic-experiment' first."
        )
    synth_model, payload = load_model(synth_model_path)
    synth_state = {k: v.cpu().clone() for k, v in synth_model.state_dict().items()}
    hp = payload.get("hparams", {})
    hidden_dim = hp.get("hidden_dim", hidden_dim)
    num_layers = hp.get("num_layers", num_layers)
    heads = hp.get("heads", heads)

    # --- Step 2: Generate synthetic vuln "anchors" ---
    # Small set of synthetic apps with high vuln ratio — keeps vuln knowledge
    # alive during fine-tuning.  Only vulnerable samples are injected.
    all_synth = generate_realistic_dataset(
        n_apps=n_synth_apps,
        endpoints_per_app=(15, 30),
        vuln_ratio=synth_vuln_ratio,
        seed=seed + 99,
    )
    synth_vuln_samples = [
        s for s in all_synth
        if s.label.label == LabelKind.VULNERABLE
    ]

    # --- Step 3: Discover real apps ---
    all_manifests = discover_manifests(corpus_root)
    groups = _app_groups(all_manifests)

    # --- Step 4: Leave-one-app-out CV ---
    folds: list[dict[str, Any]] = []
    best_model: PathAnalyzer | None = None
    best_fold_f1 = -1.0
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    for holdout in groups:
        # Holdout app → test; remaining apps → sample-level 80/20 train/val
        test_manifests = [m for m in all_manifests
                         if (m.dataset_split_group or m.application) == holdout]
        rest_manifests = [m for m in all_manifests
                         if (m.dataset_split_group or m.application) != holdout]
        rest_samples = samples_from_manifests(rest_manifests)
        rng = __import__("random").Random(seed)
        rng.shuffle(rest_samples)
        n_train = max(1, int(len(rest_samples) * 0.8))
        train_samples = rest_samples[:n_train]
        val_samples = rest_samples[n_train:]
        if not val_samples:
            val_samples = train_samples[-2:]
            train_samples = train_samples[:-2]

        fold_result = _run_fold(
            fold_name=holdout,
            train_samples=train_samples,
            val_samples=val_samples,
            test_manifests=test_manifests,
            synth_state=synth_state,
            synth_vuln_samples=synth_vuln_samples,
            epochs=epochs,
            lr=lr,
            focal_gamma=focal_gamma,
            batch_size=batch_size,
            hidden_dim=hidden_dim,
            num_layers=num_layers,
            heads=heads,
            gnn_threshold=gnn_threshold,
            seed=seed,
        )
        model = fold_result.pop("model")
        folds.append(fold_result)

        # Track best fold model by fine-tuned F1
        ft_f1 = fold_result["finetuned"]["micro_f1"]
        if ft_f1 > best_fold_f1:
            best_fold_f1 = ft_f1
            best_model = model

        # Save per-fold model
        save_model(
            model,
            out / f"path_analyzer_finetuned_{holdout}.pt",
            kind="path",
            hparams={"hidden_dim": hidden_dim, "num_layers": num_layers, "heads": heads},
        )

    # --- Step 4: Aggregate across folds ---
    def _agg(system_key: str) -> dict[str, int | float]:
        tp = sum(
            sum(a["tp"] for a in f[system_key]["apps"])
            for f in folds
        )
        fp = sum(
            sum(a["fp"] for a in f[system_key]["apps"])
            for f in folds
        )
        fn = sum(
            sum(a["fn"] for a in f[system_key]["apps"])
            for f in folds
        )
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
        return {"tp": tp, "fp": fp, "fn": fn, "precision": prec, "recall": rec, "f1": f1}

    agg_finetuned = _agg("finetuned")
    agg_synthetic = _agg("synthetic_only")
    agg_rule = _agg("rule_baseline")

    # Save best model
    best_model_path = out / "path_analyzer_finetuned_best.pt"
    if best_model is not None:
        save_model(
            best_model,
            best_model_path,
            kind="path",
            hparams={"hidden_dim": hidden_dim, "num_layers": num_layers, "heads": heads},
        )

    metrics: dict[str, Any] = {
        "experiment": "bridging_synthetic_pretrain_mixed_finetune",
        "config": {
            "synth_model_path": str(synth_model_path),
            "n_synth_apps": n_synth_apps,
            "synth_vuln_ratio": synth_vuln_ratio,
            "synth_vuln_anchors": len(synth_vuln_samples),
            "epochs": epochs,
            "lr": lr,
            "focal_gamma": focal_gamma,
            "batch_size": batch_size,
            "hidden_dim": hidden_dim,
            "num_layers": num_layers,
            "heads": heads,
            "gnn_threshold": gnn_threshold,
            "seed": seed,
        },
        "folds": folds,
        "aggregate": {
            "finetuned": agg_finetuned,
            "synthetic_only": agg_synthetic,
            "rule_baseline": agg_rule,
        },
    }

    metrics_path = out / "bridging_experiment_metrics.json"
    report_path = out / "bridging_experiment_report.md"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    report_path.write_text(_render_report(metrics), encoding="utf-8")

    return BridgingExperimentOutputs(
        metrics_path=metrics_path,
        report_path=report_path,
        model_dir=out,
        metrics=metrics,
    )


def _render_report(metrics: dict[str, Any]) -> str:
    folds = metrics["folds"]
    agg = metrics["aggregate"]

    lines = [
        "# Bridging Experiment: Synthetic Pretrain → Real Fine-tune",
        "",
        "## Methodology",
        "",
        "Leave-one-app-out cross-validation. For each fold the holdout app is",
        "unseen during fine-tuning. The synthetic-pretrained model provides the",
        "initial weights; fine-tuning mixes real data with synthetic vulnerable",
        "samples (knowledge anchors) to prevent catastrophic forgetting.",
        "",
        f"Synthetic vuln anchors: {metrics['config']['synth_vuln_anchors']} samples",
        "",
        "## Aggregate Results (across all holdout folds)",
        "",
        "| System | TP | FP | FN | Precision | Recall | F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, a in [
        ("Fine-tuned GNN", agg["finetuned"]),
        ("Synthetic-only GNN", agg["synthetic_only"]),
        ("Rule baseline", agg["rule_baseline"]),
    ]:
        lines.append(
            f"| {name} | {a['tp']} | {a['fp']} | {a['fn']} "
            f"| {a['precision']:.4f} | {a['recall']:.4f} | {a['f1']:.4f} |"
        )

    lines.extend(["", "## Per-Fold Breakdown", ""])
    for fold in folds:
        lines.append(f"### Holdout: {fold['fold']}")
        lines.append(f"- Training: {fold['n_train_real']} real + "
                      f"{fold['n_train_synth_vuln']} synth vuln = {fold['n_train_total']} total, "
                      f"Val: {fold['n_val']}, Test: {fold['n_test']}")
        lines.append("")
        lines.append("| System | TP | FP | FN | P | R | F1 |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
        for system_key, label in [
            ("finetuned", "Fine-tuned"),
            ("synthetic_only", "Synthetic-only"),
            ("rule_baseline", "Rule"),
        ]:
            r = fold[system_key]
            for app in r["apps"]:
                lines.append(
                    f"| {label} ({app['application']}) "
                    f"| {app['tp']} | {app['fp']} | {app['fn']} "
                    f"| {app['precision']:.3f} | {app['recall']:.3f} | {app['f1']:.3f} |"
                )
        lines.append("")

    lines.extend([
        "## Conclusion",
        "",
        "Detailed metrics in `bridging_experiment_metrics.json`.",
        "",
    ])
    return "\n".join(lines)
