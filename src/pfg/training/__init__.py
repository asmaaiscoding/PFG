"""Training loop and metrics."""

from pfg.training.corpus import (
    samples_from_manifest,
    samples_from_manifests,
    samples_from_pfg,
    split_manifests_by_group,
)
from pfg.training.experiment import (
    BaselineResult,
    ExperimentReport,
    evaluate_rule_baseline,
    run_experiment,
)
from pfg.training.sweep import (
    AblationKind,
    AblationOutcome,
    SweepEntry,
    SweepReport,
    apply_ablation,
    report_to_dict,
    run_ablations,
    run_hparam_sweep,
)
from pfg.training.trainer import (
    TrainResult,
    split_indices,
    train_anomaly_detector,
    train_path_analyzer,
    train_path_analyzer_split,
)

__all__ = [
    "AblationKind",
    "AblationOutcome",
    "BaselineResult",
    "ExperimentReport",
    "SweepEntry",
    "SweepReport",
    "TrainResult",
    "apply_ablation",
    "evaluate_rule_baseline",
    "report_to_dict",
    "run_ablations",
    "run_experiment",
    "run_hparam_sweep",
    "samples_from_manifest",
    "samples_from_manifests",
    "samples_from_pfg",
    "split_indices",
    "split_manifests_by_group",
    "train_anomaly_detector",
    "train_path_analyzer",
    "train_path_analyzer_split",
]
