"""Phase 4: real-world evaluation harness.

Per-app ground truth lives in `benchmarks/realworld/<app>/manifest.yaml`.
The schema is a tight subset of what the thesis evaluation needs:

  application: my-django-app          # required, unique
  repo_url: https://github.com/...    # optional (CVE / GitHub provenance)
  git_ref: 1a2b3c4                    # optional pin
  framework: django                   # required
  source_root: src/                   # path under the repo containing the code
  cwe: [CWE-862, CWE-639]             # optional, informational
  notes: |                            # optional
    Reproduces CVE-2024-XXXXX on /api/orders/<id>/
  expected_findings:                  # required (may be empty list)
    - endpoint_id: ep_orders_detail
      subtype: IDOR                   # access-control subtype
      url_pattern: /api/orders/<id>/  # informational
      cve: CVE-2024-XXXXX             # optional
  intentional_public_endpoints:       # optional (counted as TN, not FP)
    - ep_health_check
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_VALID_SUBTYPES = {
    "MISSING_AUTH",
    "MISSING_ROLE",
    "IDOR",
    "TENANT_ISOLATION_FAILURE",
    "OBJECT_LEVEL_PERMISSION_BYPASS",
    "COMBINED",
}


@dataclass
class ExpectedFinding:
    endpoint_id: str
    subtype: str
    url_pattern: str | None = None
    cve: str | None = None
    advisory_id: str | None = None
    source: str | None = None
    fixed_by: str | None = None


@dataclass
class Manifest:
    application: str
    framework: str
    source_root: Path
    expected_findings: list[ExpectedFinding] = field(default_factory=list)
    intentional_public_endpoints: list[str] = field(default_factory=list)
    repo_url: str | None = None
    git_ref: str | None = None
    fixed_ref: str | None = None
    fixed_commit: str | None = None
    checkout_dir: Path | None = None
    source_subdir: Path | None = None
    license: str | None = None
    advisory_id: str | None = None
    advisory_url: str | None = None
    nvd_url: str | None = None
    dataset_split_group: str | None = None
    label_status: str | None = None
    cwe: list[str] = field(default_factory=list)
    notes: str | None = None
    manifest_path: Path | None = None

    @property
    def project_root(self) -> Path:
        """Absolute path to the source root the extractor should analyze."""
        if self.manifest_path is None:
            return self.source_root
        return (self.manifest_path.parent / self.source_root).resolve()


def _require(d: dict[str, Any], key: str, where: Path) -> Any:
    if key not in d:
        raise ValueError(f"{where}: missing required field '{key}'")
    return d[key]


def load_manifest(path: str | Path) -> Manifest:
    p = Path(path).resolve()
    raw: dict[str, Any] = yaml.safe_load(p.read_text(encoding="utf-8")) or {}

    findings_raw = raw.get("expected_findings", []) or []
    findings: list[ExpectedFinding] = []
    for entry in findings_raw:
        sub = _require(entry, "subtype", p)
        if sub not in _VALID_SUBTYPES:
            raise ValueError(f"{p}: invalid subtype '{sub}' (allowed: {sorted(_VALID_SUBTYPES)})")
        findings.append(
            ExpectedFinding(
                endpoint_id=_require(entry, "endpoint_id", p),
                subtype=sub,
                url_pattern=entry.get("url_pattern"),
                cve=entry.get("cve"),
                advisory_id=entry.get("advisory_id"),
                source=entry.get("source"),
                fixed_by=entry.get("fixed_by"),
            )
        )

    return Manifest(
        application=_require(raw, "application", p),
        framework=_require(raw, "framework", p),
        source_root=Path(_require(raw, "source_root", p)),
        expected_findings=findings,
        intentional_public_endpoints=list(raw.get("intentional_public_endpoints", []) or []),
        repo_url=raw.get("repo_url"),
        git_ref=raw.get("git_ref"),
        fixed_ref=raw.get("fixed_ref"),
        fixed_commit=raw.get("fixed_commit"),
        checkout_dir=Path(raw["checkout_dir"]) if raw.get("checkout_dir") else None,
        source_subdir=Path(raw["source_subdir"]) if raw.get("source_subdir") else None,
        license=raw.get("license"),
        advisory_id=raw.get("advisory_id"),
        advisory_url=raw.get("advisory_url"),
        nvd_url=raw.get("nvd_url"),
        dataset_split_group=raw.get("dataset_split_group"),
        label_status=raw.get("label_status"),
        cwe=list(raw.get("cwe", []) or []),
        notes=raw.get("notes"),
        manifest_path=p,
    )


def discover_manifests(corpus_root: str | Path) -> list[Manifest]:
    """Find every `manifest.yaml` under `corpus_root` (recursively)."""
    root = Path(corpus_root).resolve()
    return sorted(
        (
            load_manifest(p)
            for p in root.rglob("manifest.yaml")
            if not any(part.startswith("_") for part in p.relative_to(root).parts)
        ),
        key=lambda m: m.application,
    )
