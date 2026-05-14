"""Real-derived augmentation behavior."""

from __future__ import annotations

from pathlib import Path

from pfg.eval.manifest import load_manifest
from pfg.pfg.graph import PFG
from pfg.training.augmentation import augmented_samples_from_pfg
from pfg.training.final import _metrics_from_confusion


def _manifest(path: Path) -> object:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """
application: app
framework: django
source_root: src
repo_url: https://github.com/example/app
git_ref: abc123
fixed_commit: def456
checkout_dir: src
dataset_split_group: app
expected_findings: []
""",
        encoding="utf-8",
    )
    return load_manifest(path)


def _safe_pfg() -> PFG:
    return PFG(
        application="app",
        framework="django",
        nodes=[
            {
                "id": "endpoint__GET___orders__pk__",
                "type": "endpoint",
                "attrs": {
                    "http_method": "GET",
                    "route": "/orders/{pk}/",
                    "route_params": ["pk"],
                    "requires_auth": True,
                    "required_role": "USER",
                    "ownership_check_present": True,
                },
            },
            {
                "id": "service__orders_detail",
                "type": "service",
                "attrs": {
                    "name": "orders.detail",
                    "performs_data_access": True,
                    "performs_mutation": False,
                },
            },
            {
                "id": "data__Order__L10__0",
                "type": "data_access",
                "attrs": {
                    "operation": "READ",
                    "target_entity": "Order",
                    "has_ownership_predicate": True,
                    "ownership_predicate_type": "DIRECT",
                    "user_controlled_params_in_query": [],
                },
            },
        ],
        edges=[
            {"src": "endpoint__GET___orders__pk__", "dst": "service__orders_detail", "type": "call"},
            {"src": "service__orders_detail", "dst": "data__Order__L10__0", "type": "call"},
        ],
    )


def test_augmented_samples_are_marked_and_training_only_safe(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path / "app" / "manifest.yaml")
    samples = augmented_samples_from_pfg(_safe_pfg(), manifest)  # type: ignore[arg-type]

    assert samples
    assert all(sample.metadata["augmented"] is True for sample in samples)
    assert {sample.metadata["origin_manifest"] for sample in samples} == {"app"}
    assert {sample.target_endpoint_id for sample in samples} == {"endpoint__GET___orders__pk__"}
    assert {sample.metadata["augmentation_type"] for sample in samples} >= {
        "remove_auth_guard",
        "remove_ownership_predicate",
    }


def test_final_metrics_include_vulnerability_finding_scores() -> None:
    metrics = _metrics_from_confusion(
        [
            [2, 0, 0, 0, 0, 0],
            [0, 1, 0, 0, 0, 0],
            [0, 0, 0, 1, 0, 0],
            [0, 0, 0, 1, 0, 0],
            [0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0],
        ]
    )

    assert metrics["accuracy"] == 0.8
    assert metrics["vulnerability_finding"]["recall"] == 1.0
