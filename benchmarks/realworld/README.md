# Real-World Corpus

This directory contains manifest-only, reproducible corpus entries for
third-party applications. We do not commit upstream source code. Each manifest
pins a repository ref and labels endpoint-level findings.

## Layout

```text
benchmarks/realworld/
  _template/manifest.yaml
  django-mdeditor-cve-2025-13030/
    manifest.yaml
    src/                 # ignored; created by `pfg corpus-fetch`
  wger-cve-2026-27839/
    manifest.yaml
    src/                 # ignored; created by `pfg corpus-fetch`
```

Template directories whose name starts with `_` are ignored by manifest
discovery.

## Fetch Sources

```bash
uv run pfg corpus-fetch benchmarks/realworld
```

The manifests clone:

- `wger-cve-2026-27839`
  repo: `https://github.com/wger-project/wger`
  vulnerable ref: `9c162dc82813d6a7b15dd8cabff128219ddef684`
- `django-mdeditor-cve-2025-13030`
  repo: `https://github.com/pylixm/django-mdeditor`
  vulnerable ref: `e8dd73fb8571ddff2e7a20a4bfa88c376cc33b62`

## Validate Corpus

```bash
uv run pfg corpus-validate benchmarks/realworld \
  --out artifacts/corpus-validation.json
```

The validator checks required provenance fields, source checkouts, PFG
extraction, discovered expected endpoints, class distribution, split groups,
and unlabeled rule-baseline findings.

## Labeling Policy

Every `expected_findings` entry must identify:

- endpoint id produced by the extractor,
- subtype: `MISSING_AUTH`, `MISSING_ROLE`, `IDOR`, or `COMBINED`,
- URL pattern,
- CVE/advisory source,
- fixed commit or fixed version when available.

Labels should be traceable to an advisory, patch, or manual audit note. If a
sample is synthetic or augmented, it must not be placed here; augmented data
should be generated from real manifests and recorded separately.

## Evaluation

```bash
uv run pfg eval benchmarks/realworld --detector rule
```

Current entries:

- wger `CVE-2026-27839`: advisory-confirmed DRF IDOR in three
  `nutritional_values` action endpoints.
- django-mdeditor `CVE-2025-13030`: advisory-confirmed missing authentication
  on `POST /mdeditor/uploads/`.
