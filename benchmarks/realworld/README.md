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

Rule baseline:

```bash
uv run pfg eval benchmarks/realworld --detector rule
```

Bridging experiment (leave-one-app-out GNN with structural post-validation):

```bash
uv run pfg bridging-experiment benchmarks/realworld \
  --out-dir artifacts/bridging-v7 \
  --synth-model artifacts/synthetic-v3/path_analyzer_synthetic.pt
```

Current entries:

- wger `CVE-2026-27839`: advisory-confirmed DRF IDOR in three
  `nutritional_values` action endpoints.
- django-mdeditor `CVE-2025-13030`: advisory-confirmed missing authentication
  on `POST /mdeditor/uploads/`.
- Nautobot `CVE-2023-50263`: advisory-confirmed missing authentication on
  db-file-storage `GET /files/get/` and `GET /files/download/`.

### Detection Results

| Detector        |  TP |  FP |  FN |     P |     R |    F1 |
| --------------- | --: | --: | --: | ----: | ----: | ----: |
| Rule baseline   |   6 |   6 |   0 | 0.500 | 1.000 | 0.667 |
| GNN (validated) |   6 |  10 |   0 | 0.375 | 1.000 | 0.545 |
| GNN (raw)       |   6 |  25 |   0 | 0.194 | 1.000 | 0.324 |

Per-app breakdown (validated GNN):

| App             |  TP |  FP |  FN |
| --------------- | --: | --: | --: |
| wger            |   3 |   5 |   0 |
| nautobot        |   2 |   5 |   0 |
| django-mdeditor |   1 |   0 |   0 |

All 6 known CVEs are detected with 100% recall. The 10 remaining FPs are
structurally valid endpoints that share graph-level signatures with real
vulnerabilities. See [/docs/gnn-improvement-report.md](/docs/gnn-improvement-report.md)
for the full technical report.

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

The GNN uses a bridging strategy: pre-train on synthetic data (774 samples),
then fine-tune on real data with leave-one-app-out cross-validation. Structural
post-validation (`validated_gnn_detector`) suppresses predictions that lack
necessary graph-level evidence (e.g., IDOR without route params + id_flow,
MISSING_AUTH without reachable data access).

The explicit holdout/seed shown above gives a non-empty augmented training set
with the current minimum corpus. For final thesis evidence, run one pass per
independent holdout group.

The current recorded result uses leave-one-group-out folds under
`artifacts/final/<holdout-group>/` and an aggregate report in
`artifacts/final_report.md`. On this three-group corpus, augmentation increased
vulnerable-endpoint recall from `0.000` to `1.000`, but reduced macro F1 from
`0.166` to `0.049`; it is therefore not yet a net improvement.
