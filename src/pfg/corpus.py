"""Real-corpus utilities.

The real corpus intentionally stores small manifests in git, while source
checkouts are fetched reproducibly from pinned repository refs. This keeps the
thesis data auditable without vendoring third-party projects into this repo.
"""

from __future__ import annotations

import subprocess
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pfg.detectors.rule_baseline import detect_all
from pfg.eval.manifest import Manifest, discover_manifests
from pfg.pfg.graph import PFG

_LABEL_CLASSES = (
    "SAFE",
    "MISSING_AUTH",
    "MISSING_ROLE",
    "IDOR",
    "COMBINED",
    "INTENTIONALLY_PUBLIC",
)

PfgBuilder = Callable[[Manifest], PFG]


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


@dataclass
class ManifestValidation:
    application: str
    manifest_path: str
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    missing_metadata_fields: list[str] = field(default_factory=list)
    checkout_root: str | None = None
    source_root: str | None = None
    checkout_exists: bool = False
    source_exists: bool = False
    node_count: int = 0
    edge_count: int = 0
    endpoint_count: int = 0
    data_access_count: int = 0
    expected_endpoint_count: int = 0
    discovered_expected_endpoints: list[str] = field(default_factory=list)
    missing_expected_endpoints: list[str] = field(default_factory=list)
    missing_intentional_public_endpoints: list[str] = field(default_factory=list)
    detector_findings: list[dict[str, str | None]] = field(default_factory=list)
    unlabeled_detector_findings: list[dict[str, str | None]] = field(default_factory=list)
    class_distribution: dict[str, int] = field(default_factory=dict)


@dataclass
class CorpusValidationReport:
    corpus_root: str
    ok: bool
    manifest_count: int
    manifests: list[ManifestValidation] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    class_distribution: dict[str, int] = field(default_factory=dict)
    split_groups: dict[str, list[str]] = field(default_factory=dict)


def _empty_class_distribution() -> dict[str, int]:
    return {label: 0 for label in _LABEL_CLASSES}


def _manifest_paths(corpus_root: Path) -> list[Path]:
    return sorted(
        p
        for p in corpus_root.rglob("manifest.yaml")
        if not any(part.startswith("_") for part in p.relative_to(corpus_root).parts)
    )


def _missing_metadata_fields(manifest: Manifest) -> list[str]:
    missing = []
    if not manifest.repo_url:
        missing.append("repo_url")
    if not manifest.git_ref:
        missing.append("git_ref")
    if not (manifest.fixed_commit or manifest.fixed_ref):
        missing.append("fixed_commit")
    return missing


def _default_build_pfg(manifest: Manifest) -> PFG:
    if manifest.framework == "django":
        from pfg.extractors.django.build import build_pfg

        return build_pfg(manifest.project_root, application=manifest.application)
    if manifest.framework == "spring":
        from pfg.extractors.spring.build import build_pfg

        return build_pfg(manifest.project_root, application=manifest.application)
    raise ValueError(f"{manifest.application}: unsupported framework '{manifest.framework}'")


def _class_distribution(endpoint_ids: set[str], manifest: Manifest) -> dict[str, int]:
    dist = _empty_class_distribution()
    expected_by_endpoint = {f.endpoint_id: f.subtype for f in manifest.expected_findings}
    intentional_public = set(manifest.intentional_public_endpoints)

    for endpoint_id in endpoint_ids:
        if endpoint_id in expected_by_endpoint:
            dist[expected_by_endpoint[endpoint_id]] += 1
        elif endpoint_id in intentional_public:
            dist["INTENTIONALLY_PUBLIC"] += 1
        else:
            dist["SAFE"] += 1

    for finding in manifest.expected_findings:
        if finding.endpoint_id not in endpoint_ids:
            dist[finding.subtype] += 1
    for endpoint_id in intentional_public:
        if endpoint_id not in endpoint_ids:
            dist["INTENTIONALLY_PUBLIC"] += 1
    return dist


def _validation_to_dict(validation: ManifestValidation) -> dict[str, Any]:
    return {
        "application": validation.application,
        "manifest_path": validation.manifest_path,
        "ok": validation.ok,
        "errors": validation.errors,
        "warnings": validation.warnings,
        "missing_metadata_fields": validation.missing_metadata_fields,
        "checkout_root": validation.checkout_root,
        "source_root": validation.source_root,
        "checkout_exists": validation.checkout_exists,
        "source_exists": validation.source_exists,
        "node_count": validation.node_count,
        "edge_count": validation.edge_count,
        "endpoint_count": validation.endpoint_count,
        "data_access_count": validation.data_access_count,
        "expected_endpoint_count": validation.expected_endpoint_count,
        "discovered_expected_endpoints": validation.discovered_expected_endpoints,
        "missing_expected_endpoints": validation.missing_expected_endpoints,
        "missing_intentional_public_endpoints": validation.missing_intentional_public_endpoints,
        "detector_findings": validation.detector_findings,
        "unlabeled_detector_findings": validation.unlabeled_detector_findings,
        "class_distribution": validation.class_distribution,
    }


def validate_manifest_source(
    manifest: Manifest,
    *,
    corpus_root: str | Path | None = None,
    build: PfgBuilder | None = None,
) -> ManifestValidation:
    """Validate one manifest against its pinned checkout and extracted PFG."""
    errors: list[str] = []
    warnings: list[str] = []
    missing_metadata = _missing_metadata_fields(manifest)
    for field_name in missing_metadata:
        errors.append(f"missing required provenance field: {field_name}")

    checkout = checkout_root(manifest)
    project_root = manifest.project_root
    checkout_exists = checkout.exists()
    source_exists = project_root.exists()
    if not checkout_exists:
        hint_root = str(corpus_root) if corpus_root is not None else "<corpus-root>"
        errors.append(f"source checkout missing at {checkout}; run `pfg corpus-fetch {hint_root}`")
    elif not source_exists:
        errors.append(f"source_root does not exist inside checkout: {project_root}")

    validation = ManifestValidation(
        application=manifest.application,
        manifest_path=str(manifest.manifest_path) if manifest.manifest_path else "",
        ok=False,
        errors=errors,
        warnings=warnings,
        missing_metadata_fields=missing_metadata,
        checkout_root=str(checkout),
        source_root=str(project_root),
        checkout_exists=checkout_exists,
        source_exists=source_exists,
        expected_endpoint_count=len(manifest.expected_findings),
        class_distribution=_class_distribution(set(), manifest),
    )

    if not source_exists:
        validation.ok = not validation.errors
        return validation

    builder = build or _default_build_pfg
    try:
        pfg = builder(manifest)
    except Exception as exc:  # pragma: no cover - exact extractor failures are project-specific
        validation.errors.append(f"failed to build PFG: {exc}")
        validation.ok = False
        return validation

    endpoint_ids = {n.id for n in pfg.endpoints()}
    expected_ids = {f.endpoint_id for f in manifest.expected_findings}
    intentional_public = set(manifest.intentional_public_endpoints)
    missing_expected = sorted(expected_ids - endpoint_ids)
    missing_public = sorted(intentional_public - endpoint_ids)
    if missing_expected:
        validation.errors.append(
            "expected endpoint(s) were not discovered: " + ", ".join(missing_expected)
        )
    if missing_public:
        validation.warnings.append(
            "intentional_public endpoint(s) were not discovered: " + ", ".join(missing_public)
        )

    findings = sorted(detect_all(pfg), key=lambda f: (f.endpoint_id, f.subtype.value))
    finding_dicts = [f.to_dict() for f in findings]
    unlabeled = [
        f.to_dict()
        for f in findings
        if f.endpoint_id not in expected_ids and f.endpoint_id not in intentional_public
    ]
    if unlabeled:
        validation.warnings.append(
            f"{len(unlabeled)} detector finding(s) are not labeled in the manifest"
        )

    validation.node_count = len(pfg.nodes)
    validation.edge_count = len(pfg.edges)
    validation.endpoint_count = len(endpoint_ids)
    validation.data_access_count = len(pfg.data_accesses())
    validation.discovered_expected_endpoints = sorted(expected_ids & endpoint_ids)
    validation.missing_expected_endpoints = missing_expected
    validation.missing_intentional_public_endpoints = missing_public
    validation.detector_findings = finding_dicts
    validation.unlabeled_detector_findings = unlabeled
    validation.class_distribution = _class_distribution(endpoint_ids, manifest)
    validation.ok = not validation.errors
    return validation


def validate_corpus(
    corpus_root: str | Path,
    *,
    build: PfgBuilder | None = None,
) -> CorpusValidationReport:
    """Validate all real-corpus manifests and return a machine-readable report."""
    root = Path(corpus_root).resolve()
    paths = _manifest_paths(root)
    errors: list[str] = []
    validations: list[ManifestValidation] = []
    split_groups: dict[str, list[str]] = {}

    if not paths:
        errors.append(f"no manifest.yaml found under {root}")

    for path in paths:
        try:
            from pfg.eval.manifest import load_manifest

            manifest = load_manifest(path)
        except Exception as exc:
            validations.append(
                ManifestValidation(
                    application=path.parent.name,
                    manifest_path=str(path),
                    ok=False,
                    errors=[f"failed to load manifest: {exc}"],
                    class_distribution=_empty_class_distribution(),
                )
            )
            continue

        group = manifest.dataset_split_group or manifest.application
        split_groups.setdefault(group, []).append(manifest.application)
        validations.append(validate_manifest_source(manifest, corpus_root=root, build=build))

    class_counts: Counter[str] = Counter()
    for validation in validations:
        class_counts.update(validation.class_distribution)
    class_distribution = _empty_class_distribution()
    class_distribution.update({k: class_counts.get(k, 0) for k in _LABEL_CLASSES})

    ok = not errors and all(validation.ok for validation in validations)
    return CorpusValidationReport(
        corpus_root=str(root),
        ok=ok,
        manifest_count=len(paths),
        manifests=validations,
        errors=errors,
        class_distribution=class_distribution,
        split_groups={k: sorted(v) for k, v in sorted(split_groups.items())},
    )


def validation_report_to_dict(report: CorpusValidationReport) -> dict[str, Any]:
    return {
        "corpus_root": report.corpus_root,
        "ok": report.ok,
        "manifest_count": report.manifest_count,
        "errors": report.errors,
        "class_distribution": report.class_distribution,
        "split_groups": report.split_groups,
        "manifests": [_validation_to_dict(validation) for validation in report.manifests],
    }


__all__ = [
    "CorpusValidationReport",
    "ManifestValidation",
    "checkout_root",
    "fetch_corpus",
    "fetch_manifest_source",
    "validate_corpus",
    "validate_manifest_source",
    "validation_report_to_dict",
]
