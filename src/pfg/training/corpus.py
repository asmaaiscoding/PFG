"""Bridge real corpus manifests into Model B training samples."""

from __future__ import annotations

import random
from collections.abc import MutableMapping, Sequence

from pfg.eval.manifest import ExpectedFinding, Manifest
from pfg.extractors.django.build import build_pfg
from pfg.pfg.graph import PFG
from pfg.pfg.nodes import Label, LabelKind, NodeType, VulnSubtype
from pfg.synthetic.generator import Sample

PfgCacheKey = tuple[str, str]
PfgCache = MutableMapping[PfgCacheKey, PFG]


def _manifest_cache_key(manifest: Manifest) -> PfgCacheKey:
    return (str(manifest.project_root.resolve()), manifest.application)


def pfg_from_manifest(manifest: Manifest, *, cache: PfgCache | None = None) -> PFG:
    if manifest.framework != "django":
        raise ValueError(f"{manifest.application}: only django corpus samples are supported")
    if cache is None:
        return build_pfg(manifest.project_root, application=manifest.application)
    key = _manifest_cache_key(manifest)
    pfg = cache.get(key)
    if pfg is None:
        pfg = build_pfg(manifest.project_root, application=manifest.application)
        cache[key] = pfg
    return pfg


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


def samples_from_manifest(manifest: Manifest, *, cache: PfgCache | None = None) -> list[Sample]:
    return samples_from_pfg(pfg_from_manifest(manifest, cache=cache), manifest)


def samples_from_manifests(
    manifests: Sequence[Manifest], *, cache: PfgCache | None = None
) -> list[Sample]:
    samples: list[Sample] = []
    for manifest in manifests:
        samples.extend(samples_from_manifest(manifest, cache=cache))
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
        if len(groups) >= 3:
            n_test = max(1, round(len(groups) * ratios[2]))
            n_val = max(1, round(len(groups) * ratios[1]))
            if n_test + n_val >= len(groups):
                n_test = 1
                n_val = 1
            n_train = len(groups) - n_val - n_test
        else:
            n_train = int(len(groups) * ratios[0])
            n_val = int(len(groups) * ratios[1])
            n_test = len(groups) - n_train - n_val
        train_groups = groups[:n_train]
        val_groups = groups[n_train : n_train + n_val]
        test_groups = groups[n_train + n_val : n_train + n_val + n_test]
        return (
            [m for g in train_groups for m in by_group[g]],
            [m for g in val_groups for m in by_group[g]],
            [m for g in test_groups for m in by_group[g]],
        )

    rng = random.Random(seed)
    rng.shuffle(train_val_groups)
    if len(train_val_groups) >= 2:
        n_train = max(
            1,
            int(len(train_val_groups) * (ratios[0] / max(ratios[0] + ratios[1], 1e-12))),
        )
        n_train = min(n_train, len(train_val_groups) - 1)
    else:
        n_train = len(train_val_groups)
    train_groups = train_val_groups[:n_train]
    val_groups = train_val_groups[n_train:]
    return (
        [m for g in train_groups for m in by_group[g]],
        [m for g in val_groups for m in by_group[g]],
        [m for g in test_groups for m in by_group[g]],
    )


__all__ = [
    "PfgCache",
    "PfgCacheKey",
    "pfg_from_manifest",
    "samples_from_manifest",
    "samples_from_manifests",
    "samples_from_pfg",
    "split_manifests_by_group",
]
