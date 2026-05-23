"""Training-only weak supervision from PFG rules.

Pseudo-labels produced here are deliberately separate from real corpus
manifests. Callers should pass only training manifests for the current split;
held-out validation/test manifests must never be included.
"""

from __future__ import annotations

from dataclasses import dataclass

from pfg.detectors.rule_baseline import detect_all
from pfg.eval.manifest import Manifest
from pfg.pfg.nodes import Label, LabelKind, NodeType, VulnSubtype
from pfg.synthetic.generator import Sample
from pfg.training.corpus import PfgCache, pfg_from_manifest


@dataclass(frozen=True)
class WeakSupervisionConfig:
    enabled: bool = False
    max_per_manifest: int = 64
    confidence: float = 0.35


def pseudo_labeled_samples_from_manifest(
    manifest: Manifest,
    *,
    config: WeakSupervisionConfig | None = None,
    cache: PfgCache | None = None,
) -> list[Sample]:
    """Return rule-derived vulnerable samples for one training manifest.

    Existing advisory-backed labels and intentional-public endpoints are
    excluded. The sample metadata records provenance so experiments can report
    and ablate weak supervision separately.
    """
    cfg = config or WeakSupervisionConfig()
    if not cfg.enabled or manifest.framework != "django":
        return []
    pfg = pfg_from_manifest(manifest, cache=cache)
    expected = {finding.endpoint_id for finding in manifest.expected_findings}
    intentional = set(manifest.intentional_public_endpoints)
    endpoint_ids = {node.id for node in pfg.nodes if node.type == NodeType.ENDPOINT.value}
    out: list[Sample] = []
    for finding in detect_all(pfg):
        if finding.endpoint_id in expected or finding.endpoint_id in intentional:
            continue
        if finding.endpoint_id not in endpoint_ids:
            continue
        out.append(
            Sample(
                pfg=pfg,
                label=Label(
                    label=LabelKind.VULNERABLE,
                    subtype=VulnSubtype(finding.subtype.value),
                    cwe="CWE-284",
                    notes="rule-derived weak supervision label",
                ),
                target_endpoint_id=finding.endpoint_id,
                metadata={
                    "weak_supervision": True,
                    "source": "pfg_rule_baseline",
                    "origin_manifest": manifest.application,
                    "origin_endpoint_id": finding.endpoint_id,
                    "confidence": cfg.confidence,
                },
            )
        )
        if len(out) >= cfg.max_per_manifest:
            break
    return out


def pseudo_labeled_samples_from_manifests(
    manifests: list[Manifest],
    *,
    config: WeakSupervisionConfig | None = None,
    cache: PfgCache | None = None,
) -> list[Sample]:
    samples: list[Sample] = []
    for manifest in manifests:
        samples.extend(pseudo_labeled_samples_from_manifest(manifest, config=config, cache=cache))
    return samples


__all__ = [
    "WeakSupervisionConfig",
    "pseudo_labeled_samples_from_manifest",
    "pseudo_labeled_samples_from_manifests",
]
