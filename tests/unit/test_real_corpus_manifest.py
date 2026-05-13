"""Real corpus manifest behavior."""

from __future__ import annotations

from pathlib import Path

from pfg.eval.manifest import discover_manifests, load_manifest


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
