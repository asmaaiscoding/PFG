# Privilege Flow Graphs (PFG)

PFG detects access-control vulnerabilities in web applications by extracting a
security-focused graph from source code and classifying each endpoint with a
Graph Neural Network. The main research model is **Model B / PathAnalyzer**:
a `GATv2Conv` network with target-aware attention pooling.

## Research Goal

We target broken access control, especially:

- `CWE-862` Missing Authorization
- `CWE-863` Incorrect Authorization / missing role checks
- `CWE-639` IDOR / authorization bypass through a user-controlled key
- `CWE-1220` Insufficient Granularity of Access Control (tenant isolation)
- `CWE-285` Improper Authorization (object-level permission bypass)

The thesis question is whether a learned graph representation can detect
multi-layer privilege-flow issues better than rule-only tools. The final
real-data claim is scoped to **Model B / PathAnalyzer only** because the output
must identify the target endpoint and the specific vulnerability subtype. Model
A remains available for older synthetic experiments, but it is not part of the
final real-corpus comparison. The key IDOR pattern is:

```text
route parameter {pk}
  -> identifier_flow
  -> database query using pk
  -> no ownership predicate such as user=request.user
```

## Pipeline

1. Extract a **Privilege Flow Graph** from Django/Spring source.
2. Enrich endpoints with structural features (`enrich_endpoint_features`).
3. Encode nodes into the frozen **36-dimensional** feature contract.
4. Encode edges as `[is_call, is_identifier_flow, is_tenant_flow]`.
5. Classify each target endpoint into one of **8 subtypes** with Model B (PathAnalyzer).
6. Apply structural post-validation to suppress predictions lacking
   graph-level evidence (`validated_gnn_detector`).
7. Evaluate against:
   - our rule baseline,
   - Semgrep output normalized to endpoint findings,
   - CodeQL SARIF output normalized to endpoint findings.

### Node Features (36-dim)

| Dims  | Feature                          | Description                                         |
| ----- | -------------------------------- | --------------------------------------------------- |
| 0–3   | node_type                        | One-hot: endpoint, middleware, service, data_access |
| 4–8   | http_method                      | One-hot: GET, POST, PUT, PATCH, DELETE              |
| 9     | requires_auth                    | Whether the endpoint requires authentication        |
| 10–14 | required_role                    | One-hot role encoding                               |
| 15    | ownership_check                  | Whether the handler verifies object ownership       |
| 16–18 | guard_type                       | One-hot guard encoding                              |
| 19–22 | op_type                          | One-hot operation type                              |
| 23    | has_ownership_predicate          | Data-access node has ownership predicate            |
| 24    | has_route_params                 | URL contains `{pk}`, `{id}`, etc.                   |
| 25    | reachable_data_count             | Normalized count of reachable data_access nodes     |
| 26    | has_id_flow                      | identifier_flow edge reaches a data_access node     |
| 27    | unprotected_data_reachable       | Reachable data_access lacks ownership predicate     |
| 28    | role_check_present               | Endpoint has an explicit role check                 |
| 29    | model_permission_check_present   | DRF model-level permission class present            |
| 30    | object_permission_check_present  | DRF object-level permission class present           |
| 31    | tenant_check_present             | Explicit tenant isolation guard present             |
| 32    | has_tenant_scope                 | Reachable data_access has tenant predicate          |
| 33    | unscoped_tenant_data_reachable   | Reachable data requires tenant scope but lacks it   |
| 34    | object_permission_data_reachable | Reachable data requires obj-perm but lacks it       |
| 35    | tenant_object_guard_signal       | Composite signal: 0/0.33/0.66/1.0                   |

Dimensions 24–27 are structural features computed by `enrich_endpoint_features()`
via BFS over call and identifier_flow edges. Dimensions 28–35 were added for the
8-class expansion to support tenant isolation and object-level permission detection.

### Edge Features (3-dim)

| Dim | Feature            | Description                        |
| --- | ------------------ | ---------------------------------- |
| 0   | is_call            | Call edge (handler → service/repo) |
| 1   | is_identifier_flow | Route param flows to data access   |
| 2   | is_tenant_flow     | Tenant scope propagation edge      |

### Classification Subtypes (8-class)

| Class | Subtype                        | CWE      |
| ----: | ------------------------------ | -------- |
|     0 | SAFE                           | —        |
|     1 | MISSING_AUTH                   | CWE-862  |
|     2 | MISSING_ROLE                   | CWE-863  |
|     3 | IDOR                           | CWE-639  |
|     4 | TENANT_ISOLATION_FAILURE       | CWE-1220 |
|     5 | OBJECT_LEVEL_PERMISSION_BYPASS | CWE-285  |
|     6 | COMBINED                       | multi    |
|     7 | INTENTIONALLY_PUBLIC           | —        |

## GNN Detection Results

### Progression (28-dim / 6-class → 36-dim / 8-class)

The model evolved through two phases. Phase 1 used a 6-class/28-dim contract;
Phase 2 expanded to 8-class/36-dim to support tenant isolation and object-level
permission bypass detection.

| Approach                            |    TP |     FP |    FN |         P |         R |        F1 |
| ----------------------------------- | ----: | -----: | ----: | --------: | --------: | --------: |
| GNN synth-only (24-dim)             |     3 |    435 |     3 |     0.007 |     0.500 |     0.014 |
| GNN synth-only (28-dim)             |     4 |    103 |     2 |     0.037 |     0.667 |     0.071 |
| Bridging 28-dim (synth → fine-tune) |     4 |     22 |     2 |     0.154 |     0.667 |     0.250 |
| + auth extractor fix                |     6 |     25 |     0 |     0.194 |     1.000 |     0.324 |
| + ownership + post-validation (v7)  |     6 |     10 |     0 |     0.375 |     1.000 |     0.545 |
| **36-dim FT + validated (v8i)**     | **5** |  **7** | **1** | **0.417** | **0.833** | **0.556** |
| **36-dim Synth + validated (v8i)**  | **6** | **11** | **0** | **0.353** | **1.000** | **0.522** |
| Rule baseline (5 rules)             |     6 |      6 |     0 |     0.500 |     1.000 |     0.667 |

The 8-class model achieves **higher F1 (0.556)** than the previous 6-class best
(0.545) with fewer false positives (7 vs 10), while adding detection capability
for two new vulnerability subtypes. The Synth+validated system provides a
zero-fine-tuning alternative with perfect recall.

### Current Per-App Breakdown

FT + validated (F1 = 0.556):

| App             |  TP |  FP |  FN |
| --------------- | --: | --: | --: |
| wger            |   3 |   1 |   0 |
| nautobot        |   2 |   6 |   0 |
| django-mdeditor |   0 |   0 |   1 |

Synth + validated (F1 = 0.522, 100% recall):

| App             |  TP |  FP |  FN |
| --------------- | --: | --: | --: |
| wger            |   3 |   5 |   0 |
| nautobot        |   2 |   6 |   0 |
| django-mdeditor |   1 |   0 |   0 |

The FT+validated system misses one django-mdeditor MISSING_AUTH endpoint in its
fold because fine-tuning on IDOR-heavy wger data shifts the decision boundary.
The Synth+validated system catches it without fine-tuning. The remaining FPs are
structurally valid — they share graph-level signatures with real vulnerabilities.
See [docs/gnn-improvement-report.md](docs/gnn-improvement-report.md) for details.

## Current Real-Data Strategy

We no longer use handwritten mini-apps as training/evaluation evidence. They
are useful only as extractor regression fixtures. Real training/evaluation data
must come from reproducible third-party sources with provenance.

For each real corpus entry we store:

- upstream repository URL,
- vulnerable git ref/tag/commit,
- fixed commit or fixed version when available,
- advisory ID / CVE / NVD URL,
- license,
- source root used by the extractor,
- endpoint-level labels,
- notes explaining how the label was derived.

Third-party source code is not vendored in this repo. It is fetched into ignored
`benchmarks/realworld/*/src/` checkouts from pinned manifest refs.

## Real Corpus Entries

The real corpus currently contains three advisory-backed Django targets, with
independent split groups for app-level evaluation.

### wger CVE-2026-27839

```text
benchmarks/realworld/wger-cve-2026-27839/manifest.yaml
```

Provenance:

- Repository: https://github.com/wger-project/wger
- Vulnerable ref: `9c162dc82813d6a7b15dd8cabff128219ddef684` (`2.1`)
- Advisory: https://github.com/wger-project/wger/security/advisories/GHSA-g8gc-6c4h-jg86
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-27839
- Fix commit: https://github.com/wger-project/wger/commit/29876a1954fe959e4b58ef070170e81703dab60e
- CWE: `CWE-639`
- License: AGPL-3.0-or-later

Labeled vulnerable endpoints:

- `GET /api/v2/nutritionplan/{pk}/nutritional_values/`
- `GET /api/v2/meal/{pk}/nutritional_values/`
- `GET /api/v2/mealitem/{pk}/nutritional_values/`

These endpoints directly used `Model.objects.get(pk=pk)`, bypassing the
user-scoped `get_queryset()` / `self.get_object()` path.

### django-mdeditor CVE-2025-13030

```text
benchmarks/realworld/django-mdeditor-cve-2025-13030/manifest.yaml
```

Provenance:

- Repository: https://github.com/pylixm/django-mdeditor
- Vulnerable ref: `e8dd73fb8571ddff2e7a20a4bfa88c376cc33b62`
- Advisory: https://github.com/advisories/GHSA-qp2c-xqv6-phh6
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-13030
- Fix commit: https://github.com/pylixm/django-mdeditor/commit/3e80f9edcabc5d2fc136b05a501964b8a5e97cfe
- CWE: `CWE-306`
- License: GPL-3.0-only

Labeled vulnerable endpoint:

- `POST /mdeditor/uploads/`

This endpoint writes uploaded files into `MEDIA_ROOT` without requiring an
authenticated user in the vulnerable ref. The fixed commit adds an
`upload_require_auth` option, an authentication check, and additional image
format validation.

### Nautobot CVE-2023-50263

```text
benchmarks/realworld/nautobot-cve-2023-50263/manifest.yaml
```

Provenance:

- Repository: https://github.com/nautobot/nautobot
- Vulnerable ref: `b639fca0385477e7a53f927d8e31509f5989d62a`
- Advisory: https://github.com/nautobot/nautobot/security/advisories/GHSA-75mc-3pjc-727q
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-50263
- Fix commit: https://github.com/nautobot/nautobot/commit/458280c359a4833a20da294eaf4b8d55edc91cee
- CWE: `CWE-200`
- License: Apache-2.0

Labeled vulnerable endpoints:

- `GET /files/get/`
- `GET /files/download/`

These endpoints came from `include("db_file_storage.urls")`, exposing
db-file-storage file retrieval without authentication. The fixed commit
replaces the include with Nautobot wrapper views that enforce `FileProxy` view
permissions.

## Commands

Install and test:

```bash
uv sync --all-extras
uv run pytest
```

Fetch real corpus sources:

```bash
uv run pfg corpus-fetch benchmarks/realworld
```

Validate real corpus manifests and labels:

```bash
uv run pfg corpus-validate benchmarks/realworld \
  --out artifacts/corpus-validation.json
```

Build a PFG for the wger vulnerable ref:

```bash
uv run pfg build benchmarks/realworld/wger-cve-2026-27839/src \
  --app wger-cve-2026-27839 \
  --out artifacts/wger-cve-2026-27839.pfg.json
```

Evaluate the rule baseline:

```bash
uv run pfg eval benchmarks/realworld --detector rule \
  --out artifacts/realworld-rule-eval.json
```

Run the bridging experiment (leave-one-app-out):

```bash
uv run pfg bridging-experiment benchmarks/realworld \
  --out-dir artifacts/bridging-v8i \
  --synth-model artifacts/synthetic-v6/path_analyzer_synthetic.pt
```

Current three-corpus validation summary:

```text
SAFE=465 MISSING_AUTH=3 MISSING_ROLE=0 IDOR=3
TENANT_ISOLATION_FAILURE=0 OBJECT_LEVEL_PERMISSION_BYPASS=0
COMBINED=0 INTENTIONALLY_PUBLIC=0
split groups: django-mdeditor, nautobot, wger
total endpoints: 471, vulnerable: 6 (1.3%)
```

Bridging experiment output (FT + validated GNN, 8-class/36-dim):

```text
TP=5  FP=7  FN=1  P=0.417  R=0.833  F1=0.556
```

Bridging experiment output (Synth + validated GNN, 8-class/36-dim):

```text
TP=6  FP=11  FN=0  P=0.353  R=1.000  F1=0.522
```

Train Model B on a real corpus once at least three independent split groups
exist:

```bash
uv run pfg train-corpus benchmarks/realworld \
  --holdout-group <group-name> \
  --out-model artifacts/path_analyzer_real.pt \
  --out-report artifacts/path_analyzer_real_report.json
```

The command intentionally splits by app/advisory group, not by endpoint, to
avoid leakage between train and test.

## Real-Derived Augmentation

The final experiment compares:

- **PathAnalyzer real-only**: trained only on advisory-backed real samples.
- **PathAnalyzer real + augmented**: trained on the same real training split
  plus real-derived augmented samples.

Augmentation is generated from extracted real PFGs, not free synthetic apps.
The implemented mutations remove authentication guards, remove role guards, or
remove ownership predicates from real training graphs. Every augmented sample is
marked with:

- `augmented: true`
- `origin_manifest`
- `origin_endpoint_id`
- `augmentation_type`

Augmented samples are used in the training split only. Validation and test are
always held-out real advisory-backed samples.

Run the paired final experiment:

```bash
uv run pfg final-experiment benchmarks/realworld \
  --holdout-group wger \
  --seed 1 \
  --out-dir artifacts
```

This writes:

- `artifacts/path_analyzer_real_only.pt`
- `artifacts/path_analyzer_real_augmented.pt`
- `artifacts/final_metrics.json`
- `artifacts/final_report.md`

Use `final_metrics.json` to compare whether augmentation improves held-out
real performance, especially macro F1 and vulnerable-endpoint recall.
With the current three-group corpus, the explicit `wger` holdout keeps the
test split real-only while placing Nautobot in training, which produces
non-empty real-derived augmentation. For thesis tables, repeat the command
with each independent holdout group and report the per-group results.

The current recorded final run uses leave-one-group-out evaluation and stores
per-fold checkpoints/reports under:

```text
artifacts/final/<holdout-group>/
```

The aggregate result (holdout = wger, 8-class/36-dim model):

| System                         |  TP |  FP |  FN | Vuln P | Vuln R | Vuln F1 |
| ------------------------------ | --: | --: | --: | -----: | -----: | ------: |
| PathAnalyzer real-only         |   0 |   0 |   3 |  0.000 |  0.000 |   0.000 |
| PathAnalyzer real + augmented  |   2 |  12 |   1 |  0.143 |  0.667 |   0.235 |
| PathAnalyzer two-stage         |   0 |   3 |   3 |  0.000 |  0.000 |   0.000 |
| **Bridging FT + validated**    |   5 |   7 |   1 |  0.417 |  0.833 |   0.556 |
| **Bridging Synth + validated** |   6 |  11 |   0 |  0.353 |  1.000 |   0.522 |
| Rule baseline                  |   6 |   6 |   0 |  0.500 |  1.000 |   0.667 |

Interpretation: real-only training fails on this tiny corpus (predicts
everything SAFE). Real-derived augmentation recovers partial recall (2/3 wger
IDORs) but with low precision. **Synthetic bridging is the clear winner** —
the synthetic pretrained model learns vulnerability patterns that the tiny real
corpus cannot teach, and structural post-validation then removes most false
positives. The bridging strategy is the main contribution.

## External Tool Comparison

Semgrep and CodeQL are compared through normalized endpoint findings.

Semgrep workflow:

```bash
semgrep scan --config p/django --config p/python --json --metrics=off \
  benchmarks/realworld/wger-cve-2026-27839/src \
  > artifacts/semgrep-wger.raw.json

uv run pfg normalize semgrep artifacts/semgrep-wger.raw.json \
  --manifest benchmarks/realworld/wger-cve-2026-27839/manifest.yaml \
  --out artifacts/semgrep-wger.normalized.json

uv run pfg eval benchmarks/realworld --detector external \
  --external-findings artifacts/semgrep-wger.normalized.json
```

CodeQL workflow:

```bash
codeql pack download codeql/python-queries

codeql database create artifacts/codeql/wger-db \
  --language=python \
  --source-root benchmarks/realworld/wger-cve-2026-27839/src

codeql database analyze artifacts/codeql/wger-db \
  codeql/python-queries:codeql-suites/python-security-and-quality.qls \
  --format=sarifv2.1.0 \
  --output artifacts/codeql-wger.sarif.json

uv run pfg normalize codeql artifacts/codeql-wger.sarif.json \
  --manifest benchmarks/realworld/wger-cve-2026-27839/manifest.yaml \
  --out artifacts/codeql-wger.normalized.json

uv run pfg eval benchmarks/realworld --detector external \
  --external-findings artifacts/codeql-wger.normalized.json
```

Current external-tool result:

| Tool    | Raw findings | Normalized endpoint findings | Endpoint-level precision | Endpoint-level recall | Endpoint-level F1 |
| ------- | -----------: | ---------------------------: | -----------------------: | --------------------: | ----------------: |
| Semgrep |           39 |                            0 |                    0.000 |                 0.000 |             0.000 |
| CodeQL  |          462 |                            0 |                    0.000 |                 0.000 |             0.000 |

These are not missing runs: the tools produced raw findings, but their standard
rules/queries did not map to the six advisory-backed privilege-flow endpoint
labels in this corpus.

## Extractor Improvements Made for Real Data

The Django extractor now handles the wger-style patterns needed for the first
real corpus:

- DRF router routes under `include(router.urls)` with the correct URL prefix.
- DRF `@action(detail=True)` custom ViewSet endpoints.
- DRF `Cls.as_view({"post": "post"})` action mappings.
- `get_queryset()` / owner-style ViewSet auth inference.
- Repository ownership predicates that use a `user` parameter rather than
  literal `request.user`.
- Direct route-parameter flow from endpoint `{pk}` to ORM data-access nodes.

## Next Data Milestones

The corpus has three independent split groups. The 8-class model now supports
five vulnerability subtypes but the real corpus only covers two (MISSING_AUTH,
IDOR). Priority targets for corpus expansion:

1. **More IDOR apps** — different from wger, to test IDOR generalization on
   held-out IDOR data.
2. **MISSING_ROLE (CWE-863)** — apps where an authenticated user can access
   admin-only endpoints due to missing role enforcement.
3. **TENANT_ISOLATION_FAILURE (CWE-1220)** — multi-tenant apps where one
   tenant's data leaks to another.
4. **OBJECT_LEVEL_PERMISSION_BYPASS (CWE-285)** — apps with DRF object
   permissions that are missing or bypassed.

All new entries must be Django or Spring (supported extractors), have a public
CVE/GHSA advisory, and have a clear fix commit for before/after comparison.

Final reporting should compare the bridging GNN (FT+validated and
Synth+validated), the rule baseline, Semgrep, and CodeQL on the same held-out
real test groups.

## References

- OWASP Top 10 2021, A01 Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- CWE-862 Missing Authorization: https://cwe.mitre.org/data/definitions/862.html
- CWE-863 Incorrect Authorization: https://cwe.mitre.org/data/definitions/863.html
- CWE-639 Authorization Bypass Through User-Controlled Key: https://cwe.mitre.org/data/definitions/639.html
- GATv2 paper, “How Attentive are Graph Attention Networks?”: https://openreview.net/forum?id=F72ximsx7C1
- PyTorch Geometric `GATv2Conv`: https://pytorch-geometric.readthedocs.io/en/stable/generated/torch_geometric.nn.conv.GATv2Conv.html
- Semgrep taint-mode documentation: https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview
- CodeQL Python data-flow documentation: https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/
