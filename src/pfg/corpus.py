"""Real-corpus utilities.

The real corpus intentionally stores small manifests in git, while source
checkouts are fetched reproducibly from pinned repository refs. This keeps the
thesis data auditable without vendoring third-party projects into this repo.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from pfg.eval.manifest import Manifest, discover_manifests


def _run_git(args: list[str], *, cwd: Path | None = None) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip()


def checkout_root(manifest: Manifest) -> Path:
    """Directory where the upstream repository should be cloned."""
    if manifest.manifest_path is None:
        raise ValueError("manifest_path is required to resolve checkout_root")
    if manifest.checkout_dir is not None:
        return (manifest.manifest_path.parent / manifest.checkout_dir).resolve()
    return manifest.project_root


def fetch_manifest_source(manifest: Manifest, *, force: bool = False) -> Path:
    """Clone/update the repository described by a manifest and checkout git_ref."""
    if not manifest.repo_url or not manifest.git_ref:
        raise ValueError(f"{manifest.application}: repo_url and git_ref are required")

    root = checkout_root(manifest)
    if root.exists() and not (root / ".git").exists():
        raise ValueError(f"{manifest.application}: {root} exists but is not a git checkout")

    if not root.exists():
        root.parent.mkdir(parents=True, exist_ok=True)
        _run_git(["clone", manifest.repo_url, str(root)])
    elif force:
        _run_git(["fetch", "--all", "--tags"], cwd=root)

    _run_git(["fetch", "origin", manifest.git_ref], cwd=root)
    _run_git(["checkout", "--detach", manifest.git_ref], cwd=root)
    return manifest.project_root


def fetch_corpus(corpus_root: str | Path, *, force: bool = False) -> list[Path]:
    """Fetch every manifest source under a corpus root."""
    return [fetch_manifest_source(m, force=force) for m in discover_manifests(corpus_root)]


__all__ = ["checkout_root", "fetch_corpus", "fetch_manifest_source"]
