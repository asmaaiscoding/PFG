"""Phase 3 W15: full training experiment + rule-baseline comparison.

`run_experiment` generates a synthetic corpus, splits it deterministically
(shared with the GNN trainers), trains both Model A (anomaly) and Model B
(subtype path analyzer), then evaluates the mandatory rule baseline on the
same test split. All metrics are returned as a dictionary and optionally
written to JSON / logged to MLflow.

This satisfies Gate G3: GNN must beat the rule baseline on synthetic data
before we move to real-world evaluation.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from pfg.detectors.rule_baseline import detect_all
from pfg.pfg.nodes import VulnSubtype
from pfg.synthetic import NUM_SUBTYPES, Sample, generate_dataset, label_to_targets
from pfg.training.trainer import (
    TrainResult,
    split_indices,
    train_anomaly_detector,
    train_path_analyzer,
)

# --- baseline evaluation --------------------------------------------------


_SUBTYPE_INDEX = {
    "SAFE": 0,
    "MISSING_AUTH": 1,
    "MISSING_ROLE": 2,
    "IDOR": 3,
    "TENANT_ISOLATION_FAILURE": 4,
    "OBJECT_LEVEL_PERMISSION_BYPASS": 5,
    "COMBINED": 6,
    "INTENTIONALLY_PUBLIC": 7,
}


def _rule_predict(sample: Sample) -> tuple[int, int]:
    """Apply rule baseline to one sample. Returns (binary, subtype) prediction.

    Convention:
      * binary: 1 if any rule fires on the target endpoint, else 0.
      * subtype: COMBINED if multiple distinct rules fire on target endpoint,
                 otherwise the firing subtype, else SAFE (= 0).
        INTENTIONALLY_PUBLIC is never predicted by rules (treated as SAFE
        because rules cannot recover that label).
    """
    findings = [f for f in detect_all(sample.pfg) if f.endpoint_id == sample.target_endpoint_id]
    if not findings:
        return 0, _SUBTYPE_INDEX["SAFE"]
    subtypes = {f.subtype for f in findings}
    if len(subtypes) >= 2:
        return 1, _SUBTYPE_INDEX["COMBINED"]
    only = next(iter(subtypes))
    name = only.value if isinstance(only, VulnSubtype) else str(only)
    return 1, _SUBTYPE_INDEX.get(name, _SUBTYPE_INDEX["SAFE"])


def _confusion(preds: list[int], targets: list[int], k: int) -> list[list[int]]:
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
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1s.append((2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0)
    return sum(f1s) / k if k else 0.0


@dataclass
class BaselineResult:
    test_accuracy_binary: float
    test_macro_f1_binary: float
    test_accuracy_subtype: float
    test_macro_f1_subtype: float
    confusion_binary: list[list[int]]
    confusion_subtype: list[list[int]]


def evaluate_rule_baseline(test_samples: list[Sample]) -> BaselineResult:
    bin_preds: list[int] = []
    bin_targets: list[int] = []
    sub_preds: list[int] = []
    sub_targets: list[int] = []
    for s in test_samples:
        bp, sp = _rule_predict(s)
        bin_preds.append(bp)
        sub_preds.append(sp)
        y_bin, y_sub = label_to_targets(s)
        bin_targets.append(y_bin)
        sub_targets.append(y_sub)
    cm_b = _confusion(bin_preds, bin_targets, 2)
    cm_s = _confusion(sub_preds, sub_targets, NUM_SUBTYPES)
    acc_b = (
        sum(1 for p, t in zip(bin_preds, bin_targets, strict=True) if p == t) / len(bin_preds)
        if bin_preds
        else 0.0
    )
    acc_s = (
        sum(1 for p, t in zip(sub_preds, sub_targets, strict=True) if p == t) / len(sub_preds)
        if sub_preds
        else 0.0
    )
    return BaselineResult(
        test_accuracy_binary=acc_b,
        test_macro_f1_binary=_macro_f1(cm_b),
        test_accuracy_subtype=acc_s,
        test_macro_f1_subtype=_macro_f1(cm_s),
        confusion_binary=cm_b,
        confusion_subtype=cm_s,
    )


# --- experiment driver ----------------------------------------------------


@dataclass
class ExperimentReport:
    n_samples: int
    seed: int
    epochs: int
    anomaly: dict[str, Any] = field(default_factory=dict)
    path_analyzer: dict[str, Any] = field(default_factory=dict)
    rule_baseline: dict[str, Any] = field(default_factory=dict)


def _result_summary(r: TrainResult) -> dict[str, Any]:
    return {
        "test_accuracy": r.test_accuracy,
        "test_macro_f1": r.test_macro_f1,
        "best_val_loss": r.best_val_loss,
        "confusion": r.confusion,
        "epochs_run": len(r.history),
    }


def run_experiment(
    *,
    n_samples: int = 600,
    seed: int = 0,
    epochs: int = 30,
    batch_size: int = 32,
    hidden_dim: int = 64,
    num_layers: int = 3,
    heads: int = 4,
    use_mlflow: bool = False,
    out_path: str | Path | None = None,
) -> ExperimentReport:
    """Train both GNN models and benchmark against the rule baseline."""
    samples = generate_dataset(n_samples, seed=seed)

    # Determine the test split that matches the trainer's internal split.
    _, _, test_idx = split_indices(len(samples), seed=seed)
    test_samples = [samples[i] for i in test_idx]
    baseline = evaluate_rule_baseline(test_samples)

    _, anom_metrics = train_anomaly_detector(
        samples,
        epochs=epochs,
        batch_size=batch_size,
        hidden_dim=hidden_dim,
        num_layers=num_layers,
        seed=seed,
        use_mlflow=use_mlflow,
    )
    _, path_metrics = train_path_analyzer(
        samples,
        epochs=epochs,
        batch_size=batch_size,
        hidden_dim=hidden_dim,
        num_layers=num_layers,
        heads=heads,
        seed=seed,
        use_mlflow=use_mlflow,
    )

    report = ExperimentReport(
        n_samples=n_samples,
        seed=seed,
        epochs=epochs,
        anomaly=_result_summary(anom_metrics),
        path_analyzer=_result_summary(path_metrics),
        rule_baseline=asdict(baseline),
    )

    if out_path is not None:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")

    return report
