"""Bridge: real extracted PFG + manifest ground truth → training Samples.

Converts the output of `pfg build` (a PFG JSON) combined with a manifest.yaml
into a list of Sample objects that the trainer can consume directly, enabling
mixed training on synthetic + real data.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from pfg.eval.manifest import ExpectedFinding, Manifest, load_manifest
from pfg.extractors.django.build import build_pfg
from pfg.pfg.graph import PFG
from pfg.pfg.nodes import Label, LabelKind, NodeType, VulnSubtype
from pfg.synthetic.generator import Sample


def _label_for_endpoint(
    endpoint_id: str,
    findings_by_id: dict[str, ExpectedFinding],
    intentional_public: set[str],
) -> Label:
    """Determine ground-truth label for one endpoint from manifest data."""
    if endpoint_id in intentional_public:
        return Label(label=LabelKind.INTENTIONALLY_PUBLIC, subtype=None)
    finding = findings_by_id.get(endpoint_id)
    if finding is not None:
        return Label(label=LabelKind.VULNERABLE, subtype=VulnSubtype(finding.subtype))
    return Label(label=LabelKind.SAFE, subtype=None)


def samples_from_pfg(pfg: PFG, manifest: Manifest) -> list[Sample]:
    """Convert a PFG + manifest into per-endpoint training Samples.

    One Sample is emitted per endpoint node in the PFG. The label is
    determined by cross-referencing the endpoint's node ID against the
    manifest's expected_findings and intentional_public_endpoints.
    """
    findings_by_id = {f.endpoint_id: f for f in manifest.expected_findings}
    intentional_public = set(manifest.intentional_public_endpoints)

    samples: list[Sample] = []
    for node in pfg.nodes:
        if node.type != NodeType.ENDPOINT.value:
            continue
        label = _label_for_endpoint(node.id, findings_by_id, intentional_public)
        samples.append(Sample(pfg=pfg, label=label, target_endpoint_id=node.id))
    return samples


def samples_from_manifest(manifest: Manifest) -> list[Sample]:
    """End-to-end: run extractor on manifest's project_root, then label.

    Convenience wrapper combining `build_pfg` + `samples_from_pfg`.
    """
    pfg = build_pfg(str(manifest.project_root), application=manifest.application)
    return samples_from_pfg(pfg, manifest)


def samples_from_corpus(manifests: Sequence[Manifest]) -> list[Sample]:
    """Build training samples from multiple app manifests."""
    all_samples: list[Sample] = []
    for m in manifests:
        all_samples.extend(samples_from_manifest(m))
    return all_samples
