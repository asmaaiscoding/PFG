"""Real-derived augmentation for Model B training.

Augmented samples are generated from extracted real PFGs and are intended for
training only. The final held-out validation/test sets must stay real-only.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from pfg.eval.manifest import Manifest
from pfg.extractors.django.build import build_pfg
from pfg.pfg.graph import PFG
from pfg.pfg.nodes import Label, LabelKind, NodeType, VulnSubtype
from pfg.synthetic.generator import Sample


@dataclass(frozen=True)
class AugmentationConfig:
    include_missing_auth: bool = True
    include_missing_role: bool = True
    include_idor: bool = True
    max_per_manifest: int = 48


def _label(subtype: VulnSubtype, cwe: str) -> Label:
    return Label(label=LabelKind.VULNERABLE, subtype=subtype, cwe=cwe)


def _reachable_data_access_ids(pfg_data: dict[str, Any], endpoint_id: str) -> list[str]:
    node_types = {n["id"]: n["type"] for n in pfg_data["nodes"]}
    succ: dict[str, list[str]] = {}
    for edge in pfg_data["edges"]:
        if edge["type"] == "call":
            succ.setdefault(edge["src"], []).append(edge["dst"])

    seen = {endpoint_id}
    stack = [endpoint_id]
    out: list[str] = []
    while stack:
        cur = stack.pop()
        for nxt in succ.get(cur, []):
            if nxt in seen:
                continue
            seen.add(nxt)
            if node_types.get(nxt) == NodeType.DATA_ACCESS.value:
                out.append(nxt)
            stack.append(nxt)
    return out


def _has_call_reachable_data_access(pfg_data: dict[str, Any], endpoint_id: str) -> bool:
    return bool(_reachable_data_access_ids(pfg_data, endpoint_id))


def _copy_with_metadata(
    pfg_data: dict[str, Any],
    *,
    manifest: Manifest,
    endpoint_id: str,
    subtype: VulnSubtype,
    augmentation_type: str,
    cwe: str,
) -> Sample:
    pfg_data.setdefault("metadata", {})
    pfg_data["metadata"] = {
        **pfg_data["metadata"],
        "augmented": True,
        "augmentation_type": augmentation_type,
        "origin_manifest": manifest.application,
        "origin_endpoint_id": endpoint_id,
    }
    return Sample(
        pfg=PFG.model_validate(pfg_data),
        label=_label(subtype, cwe),
        target_endpoint_id=endpoint_id,
        metadata={
            "augmented": True,
            "augmentation_type": augmentation_type,
            "origin_manifest": manifest.application,
            "origin_endpoint_id": endpoint_id,
        },
    )


def _mutate_missing_auth(pfg: PFG, manifest: Manifest) -> list[Sample]:
    out: list[Sample] = []
    base = pfg.to_dict()
    for node in base["nodes"]:
        if node["type"] != NodeType.ENDPOINT.value:
            continue
        endpoint_id = node["id"]
        attrs = node["attrs"]
        if not attrs.get("requires_auth"):
            continue
        if not _has_call_reachable_data_access(base, endpoint_id):
            continue
        mutated = deepcopy(base)
        target = next(n for n in mutated["nodes"] if n["id"] == endpoint_id)
        target["attrs"]["requires_auth"] = False
        target["attrs"]["required_role"] = "NONE"
        target["attrs"]["is_intentionally_public"] = False
        out.append(
            _copy_with_metadata(
                mutated,
                manifest=manifest,
                endpoint_id=endpoint_id,
                subtype=VulnSubtype.MISSING_AUTH,
                augmentation_type="remove_auth_guard",
                cwe="CWE-862",
            )
        )
    return out


def _mutate_missing_role(pfg: PFG, manifest: Manifest) -> list[Sample]:
    out: list[Sample] = []
    base = pfg.to_dict()
    privileged_ops = {"WRITE", "UPDATE", "DELETE"}
    for node in base["nodes"]:
        if node["type"] != NodeType.ENDPOINT.value:
            continue
        endpoint_id = node["id"]
        attrs = node["attrs"]
        if not attrs.get("requires_auth") or attrs.get("required_role") in {"NONE", None}:
            continue
        data_ids = _reachable_data_access_ids(base, endpoint_id)
        if not any(
            n["id"] in data_ids and n["attrs"].get("operation") in privileged_ops
            for n in base["nodes"]
        ):
            continue
        mutated = deepcopy(base)
        target = next(n for n in mutated["nodes"] if n["id"] == endpoint_id)
        target["attrs"]["required_role"] = "NONE"
        out.append(
            _copy_with_metadata(
                mutated,
                manifest=manifest,
                endpoint_id=endpoint_id,
                subtype=VulnSubtype.MISSING_ROLE,
                augmentation_type="remove_role_guard",
                cwe="CWE-863",
            )
        )
    return out


def _mutate_idor(pfg: PFG, manifest: Manifest) -> list[Sample]:
    out: list[Sample] = []
    base = pfg.to_dict()
    for node in base["nodes"]:
        if node["type"] != NodeType.ENDPOINT.value:
            continue
        endpoint_id = node["id"]
        params = node["attrs"].get("route_params") or []
        if not params:
            continue
        data_ids = _reachable_data_access_ids(base, endpoint_id)
        owned = [
            n["id"]
            for n in base["nodes"]
            if n["id"] in data_ids and n["attrs"].get("has_ownership_predicate")
        ]
        if not owned:
            continue
        mutated = deepcopy(base)
        target = next(n for n in mutated["nodes"] if n["id"] == endpoint_id)
        target["attrs"]["ownership_check_present"] = False
        for da_id in owned:
            da = next(n for n in mutated["nodes"] if n["id"] == da_id)
            da["attrs"]["has_ownership_predicate"] = False
            da["attrs"]["ownership_predicate_type"] = "NONE"
            if params[0] not in da["attrs"]["user_controlled_params_in_query"]:
                da["attrs"]["user_controlled_params_in_query"].append(params[0])
            flow = {"src": endpoint_id, "dst": da_id, "type": "identifier_flow", "param": params[0]}
            if flow not in mutated["edges"]:
                mutated["edges"].append(flow)
        out.append(
            _copy_with_metadata(
                mutated,
                manifest=manifest,
                endpoint_id=endpoint_id,
                subtype=VulnSubtype.IDOR,
                augmentation_type="remove_ownership_predicate",
                cwe="CWE-639",
            )
        )
    return out


def augmented_samples_from_pfg(
    pfg: PFG,
    manifest: Manifest,
    *,
    config: AugmentationConfig | None = None,
) -> list[Sample]:
    cfg = config or AugmentationConfig()
    out: list[Sample] = []
    if cfg.include_missing_auth:
        out.extend(_mutate_missing_auth(pfg, manifest))
    if cfg.include_missing_role:
        out.extend(_mutate_missing_role(pfg, manifest))
    if cfg.include_idor:
        out.extend(_mutate_idor(pfg, manifest))
    return out[: cfg.max_per_manifest]


def augmented_samples_from_manifest(
    manifest: Manifest,
    *,
    config: AugmentationConfig | None = None,
) -> list[Sample]:
    if manifest.framework != "django":
        return []
    pfg = build_pfg(manifest.project_root, application=manifest.application)
    return augmented_samples_from_pfg(pfg, manifest, config=config)


def augmented_samples_from_manifests(
    manifests: list[Manifest],
    *,
    config: AugmentationConfig | None = None,
) -> list[Sample]:
    samples: list[Sample] = []
    for manifest in manifests:
        samples.extend(augmented_samples_from_manifest(manifest, config=config))
    return samples


__all__ = [
    "AugmentationConfig",
    "augmented_samples_from_manifest",
    "augmented_samples_from_manifests",
    "augmented_samples_from_pfg",
]
