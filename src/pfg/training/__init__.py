"""Training loop and metrics."""

from pfg.training.augmentation import (
    AugmentationConfig,
    augmented_samples_from_manifest,
    augmented_samples_from_manifests,
    augmented_samples_from_pfg,
)
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
from pfg.training.final import (
    FinalExperimentOutputs,
    final_outputs_to_dict,
    run_final_experiment,
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
from pfg.training.weak_supervision import (
    WeakSupervisionConfig,
    pseudo_labeled_samples_from_manifest,
    pseudo_labeled_samples_from_manifests,
)

__all__ = [
    "AblationKind",
    "AblationOutcome",
    "AugmentationConfig",
    "BaselineResult",
    "ExperimentReport",
    "FinalExperimentOutputs",
    "SweepEntry",
    "SweepReport",
    "TrainResult",
    "WeakSupervisionConfig",
    "apply_ablation",
    "augmented_samples_from_manifest",
    "augmented_samples_from_manifests",
    "augmented_samples_from_pfg",
    "evaluate_rule_baseline",
    "final_outputs_to_dict",
    "pseudo_labeled_samples_from_manifest",
    "pseudo_labeled_samples_from_manifests",
    "report_to_dict",
    "run_ablations",
    "run_experiment",
    "run_final_experiment",
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
