"""Synthetic PFG dataset (Phase 3)."""

from pfg.synthetic.dataset import NUM_SUBTYPES, label_to_targets, pfg_to_pyg, samples_to_pyg
from pfg.synthetic.generator import Sample, generate_dataset

__all__ = [
    "NUM_SUBTYPES",
    "Sample",
    "generate_dataset",
    "label_to_targets",
    "pfg_to_pyg",
    "samples_to_pyg",
]
