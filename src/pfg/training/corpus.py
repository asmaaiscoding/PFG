"""Bridge real corpus manifests into Model B training samples."""

from __future__ import annotations

import random
from collections.abc import Sequence

from pfg.eval.manifest import ExpectedFinding, Manifest
from pfg.extractors.django.build import build_pfg
from pfg.pfg.graph import PFG
from pfg.pfg.nodes import Label, LabelKind, NodeType, VulnSubtype
from pfg.synthetic.generator import Sample


def _label_for_endpoint(
    endpoint_id: str,
    findings_by_endpoint: dict[str, ExpectedFinding],
    intentional_public: set[str],
) -> Label:
    if endpoint_id in intentional_public:
        return Label(label=LabelKind.INTENTIONALLY_PUBLIC)
    finding = findings_by_endpoint.get(endpoint_id)
    if finding is None:
        return Label(label=LabelKind.SAFE)
    return Label(label=LabelKind.VULNERABLE, subtype=VulnSubtype(finding.subtype), cwe=finding.cve)


def samples_from_pfg(pfg: PFG, manifest: Manifest) -> list[Sample]:
    """Emit one labeled Model B sample per endpoint node."""
    findings_by_endpoint = {f.endpoint_id: f for f in manifest.expected_findings}
    intentional_public = set(manifest.intentional_public_endpoints)
    samples: list[Sample] = []
    for node in pfg.nodes:
        if node.type != NodeType.ENDPOINT.value:
            continue
        samples.append(
            Sample(
                pfg=pfg,
                label=_label_for_endpoint(node.id, findings_by_endpoint, intentional_public),
                target_endpoint_id=node.id,
            )
        )
    return samples


def samples_from_manifest(manifest: Manifest) -> list[Sample]:
    if manifest.framework != "django":
        raise ValueError(f"{manifest.application}: only django corpus samples are supported")
    pfg = build_pfg(manifest.project_root, application=manifest.application)
    return samples_from_pfg(pfg, manifest)


def samples_from_manifests(manifests: Sequence[Manifest]) -> list[Sample]:
    samples: list[Sample] = []
    for manifest in manifests:
        samples.extend(samples_from_manifest(manifest))
    return samples


def split_manifests_by_group(
    manifests: Sequence[Manifest],
    *,
    seed: int = 0,
    holdout_group: str | None = None,
    ratios: tuple[float, float, float] = (0.7, 0.15, 0.15),
) -> tuple[list[Manifest], list[Manifest], list[Manifest]]:
    """Split whole apps/advisories, never endpoints, across train/val/test."""
    by_group: dict[str, list[Manifest]] = {}
    for manifest in manifests:
        group = manifest.dataset_split_group or manifest.application
        by_group.setdefault(group, []).append(manifest)

    groups = sorted(by_group)
    if holdout_group is not None:
        test_groups = [holdout_group]
        train_val_groups = [g for g in groups if g != holdout_group]
    else:
        rng = random.Random(seed)
        rng.shuffle(groups)
        n_train = int(len(groups) * ratios[0])
        n_val = int(len(groups) * ratios[1])
        train_groups = groups[:n_train]
        val_groups = groups[n_train : n_train + n_val]
        test_groups = groups[n_train + n_val :]
        return (
            [m for g in train_groups for m in by_group[g]],
            [m for g in val_groups for m in by_group[g]],
            [m for g in test_groups for m in by_group[g]],
        )

    rng = random.Random(seed)
    rng.shuffle(train_val_groups)
    n_train = int(len(train_val_groups) * (ratios[0] / max(ratios[0] + ratios[1], 1e-12)))
    train_groups = train_val_groups[:n_train]
    val_groups = train_val_groups[n_train:]
    return (
        [m for g in train_groups for m in by_group[g]],
        [m for g in val_groups for m in by_group[g]],
        [m for g in test_groups for m in by_group[g]],
    )


__all__ = [
    "samples_from_manifest",
    "samples_from_manifests",
    "samples_from_pfg",
    "split_manifests_by_group",
]
