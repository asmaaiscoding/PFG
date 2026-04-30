"""Synthetic generator tests (Phase 3 W12)."""
from __future__ import annotations

from collections import Counter

from pfg.detectors.rule_baseline import detect_all
from pfg.pfg.graph import save_pfg
from pfg.pfg.nodes import LabelKind, VulnSubtype
from pfg.synthetic import generate_dataset, label_to_targets


def test_generator_is_deterministic() -> None:
    a = generate_dataset(20, seed=42)
    b = generate_dataset(20, seed=42)
    assert [s.target_endpoint_id for s in a] == [s.target_endpoint_id for s in b]
    assert [s.label.label for s in a] == [s.label.label for s in b]


def test_class_distribution_balanced() -> None:
    samples = generate_dataset(60, seed=0)
    counts: Counter[str] = Counter()
    for s in samples:
        if s.label.label == LabelKind.SAFE.value:
            counts["SAFE"] += 1
        elif s.label.label == LabelKind.INTENTIONALLY_PUBLIC.value:
            counts["PUBLIC"] += 1
        else:
            assert s.label.subtype is not None
            counts[s.label.subtype] += 1
    # 60 / 6 = 10 per class.
    for k in (
        "SAFE",
        VulnSubtype.MISSING_AUTH.value,
        VulnSubtype.MISSING_ROLE.value,
        VulnSubtype.IDOR.value,
        VulnSubtype.COMBINED.value,
        "PUBLIC",
    ):
        assert counts[k] == 10, f"class {k}: {counts[k]} != 10"


def test_all_samples_validate_against_schema(tmp_path) -> None:
    samples = generate_dataset(12, seed=1)
    for i, s in enumerate(samples):
        save_pfg(s.pfg, tmp_path / f"s{i}.json")  # raises on invalid


def test_label_to_targets_mapping() -> None:
    samples = generate_dataset(6, seed=0)
    seen = {label_to_targets(s) for s in samples}
    # SAFE=(0,0), MISSING_AUTH=(1,1), MISSING_ROLE=(1,2), IDOR=(1,3),
    # COMBINED=(1,4), PUBLIC=(0,5)
    assert (0, 0) in seen
    assert (1, 1) in seen
    assert (1, 2) in seen
    assert (1, 3) in seen
    assert (1, 4) in seen
    assert (0, 5) in seen


def test_rule_baseline_recall_on_synthetic() -> None:
    """Sanity: the rule baseline should detect most VULNERABLE synth samples."""
    samples = generate_dataset(60, seed=0)
    vulnerable = [s for s in samples if s.label.label == LabelKind.VULNERABLE.value]
    detected = 0
    for s in vulnerable:
        if detect_all(s.pfg):
            detected += 1
    # Allow 90% recall as a smoke threshold.
    assert detected / len(vulnerable) >= 0.9, f"only {detected}/{len(vulnerable)} detected"


def test_rule_baseline_low_fp_on_safe() -> None:
    samples = generate_dataset(60, seed=0)
    benign = [
        s
        for s in samples
        if s.label.label in (LabelKind.SAFE.value, LabelKind.INTENTIONALLY_PUBLIC.value)
    ]
    fp = sum(1 for s in benign if detect_all(s.pfg))
    assert fp / len(benign) <= 0.1, f"too many FPs: {fp}/{len(benign)}"
