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
  nautobot-cve-2023-50263/
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
- `nautobot-cve-2023-50263`
  repo: `https://github.com/nautobot/nautobot`
  vulnerable ref: `b639fca0385477e7a53f927d8e31509f5989d62a`

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

Augmentation is training-only. Final validation and test samples must be real,
advisory-backed corpus samples.

## Evaluation

```bash
uv run pfg eval benchmarks/realworld --detector rule
```

Current entries:

- wger `CVE-2026-27839`: advisory-confirmed DRF IDOR in three
  `nutritional_values` action endpoints.
- django-mdeditor `CVE-2025-13030`: advisory-confirmed missing authentication
  on `POST /mdeditor/uploads/`.
- Nautobot `CVE-2023-50263`: advisory-confirmed missing authentication on
  db-file-storage `GET /files/get/` and `GET /files/download/`.

## Final Model B Comparison

```bash
uv run pfg final-experiment benchmarks/realworld \
  --holdout-group wger \
  --seed 1 \
  --out-dir artifacts
```

The final command trains and compares PathAnalyzer real-only vs PathAnalyzer
real + augmented, then writes `final_metrics.json`, `final_report.md`,
`path_analyzer_real_only.pt`, and `path_analyzer_real_augmented.pt`.
The explicit holdout/seed shown above gives a non-empty augmented training set
with the current minimum corpus. For final thesis evidence, run one pass per
independent holdout group.
