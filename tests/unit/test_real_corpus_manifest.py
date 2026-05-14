"""Real corpus manifest behavior."""

from __future__ import annotations

from pathlib import Path

from pfg.corpus import validate_corpus, validation_report_to_dict
from pfg.eval.manifest import discover_manifests, load_manifest
from pfg.pfg.graph import PFG
from pfg.training.corpus import split_manifests_by_group


def _manifest(path: Path, name: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"""
application: {name}
framework: django
source_root: src/wger
repo_url: https://github.com/wger-project/wger
git_ref: abc123
checkout_dir: src
source_subdir: wger
license: AGPL-3.0-or-later
advisory_id: GHSA-example
dataset_split_group: wger
expected_findings: []
""",
        encoding="utf-8",
    )


def test_discover_manifests_skips_template_dirs(tmp_path: Path) -> None:
    _manifest(tmp_path / "_template" / "manifest.yaml", "template")
    _manifest(tmp_path / "wger" / "manifest.yaml", "wger")

    found = discover_manifests(tmp_path)

    assert [m.application for m in found] == ["wger"]


def test_manifest_loads_reproducibility_metadata(tmp_path: Path) -> None:
    manifest_path = tmp_path / "wger" / "manifest.yaml"
    _manifest(manifest_path, "wger")

    manifest = load_manifest(manifest_path)

    assert manifest.repo_url == "https://github.com/wger-project/wger"
    assert manifest.checkout_dir == Path("src")
    assert manifest.source_subdir == Path("wger")
    assert manifest.license == "AGPL-3.0-or-later"
    assert manifest.advisory_id == "GHSA-example"


def _validation_manifest(path: Path, expected_endpoint: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"""
application: real-app
framework: django
source_root: src
repo_url: https://github.com/example/real-app
git_ref: abc123
fixed_commit: def456
checkout_dir: src
advisory_id: GHSA-example
dataset_split_group: real-app
expected_findings:
  - endpoint_id: {expected_endpoint}
    subtype: IDOR
""",
        encoding="utf-8",
    )


def _upload_pfg() -> PFG:
    return PFG(
        application="real-app",
        framework="django",
        nodes=[
            {
                "id": "endpoint__POST___mdeditor_upload_",
                "type": "endpoint",
                "attrs": {
                    "http_method": "POST",
                    "route": "/mdeditor/upload/",
                    "route_params": [],
                    "requires_auth": False,
                    "required_role": "NONE",
                },
            },
            {
                "id": "data__mdeditor_views_upload__L25__0",
                "type": "data_access",
                "attrs": {
                    "operation": "WRITE",
                    "target_entity": "UploadedFile",
                    "has_ownership_predicate": False,
                    "ownership_predicate_type": "NONE",
                },
            },
        ],
        edges=[
            {
                "src": "endpoint__POST___mdeditor_upload_",
                "dst": "data__mdeditor_views_upload__L25__0",
                "type": "call",
            }
        ],
    )


def test_validate_corpus_reports_missing_expected_and_unlabeled_findings(
    tmp_path: Path,
) -> None:
    _validation_manifest(tmp_path / "real-app" / "manifest.yaml", "endpoint__GET___missing_")
    (tmp_path / "real-app" / "src").mkdir()

    report = validate_corpus(tmp_path, build=lambda _m: _upload_pfg())
    data = validation_report_to_dict(report)

    assert not report.ok
    app = report.manifests[0]
    assert app.missing_expected_endpoints == ["endpoint__GET___missing_"]
    assert [f["endpoint_id"] for f in app.unlabeled_detector_findings] == [
        "endpoint__POST___mdeditor_upload_"
    ]
    assert data["class_distribution"]["IDOR"] == 1
    assert data["class_distribution"]["SAFE"] == 1
    assert data["split_groups"] == {"real-app": ["real-app"]}


def test_validate_corpus_reports_missing_checkout(tmp_path: Path) -> None:
    _validation_manifest(
        tmp_path / "real-app" / "manifest.yaml",
        "endpoint__POST___mdeditor_upload_",
    )

    report = validate_corpus(tmp_path, build=lambda _m: _upload_pfg())

    assert not report.ok
    app = report.manifests[0]
    assert not app.checkout_exists
    assert not app.source_exists
    assert any("corpus-fetch" in error for error in app.errors)


def test_split_manifests_by_group_keeps_three_groups_non_empty(tmp_path: Path) -> None:
    paths = []
    for name in ("a", "b", "c"):
        path = tmp_path / name / "manifest.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"""
application: {name}
framework: django
source_root: src
repo_url: https://github.com/example/{name}
git_ref: abc123
fixed_commit: def456
checkout_dir: src
dataset_split_group: {name}
expected_findings: []
""",
            encoding="utf-8",
        )
        paths.append(path)
    manifests = [load_manifest(path) for path in paths]

    train, val, test = split_manifests_by_group(manifests, seed=0)

    assert train
    assert val
    assert test
    split_apps = {
        *(m.application for m in train),
        *(m.application for m in val),
        *(m.application for m in test),
    }
    assert len(split_apps) == 3
