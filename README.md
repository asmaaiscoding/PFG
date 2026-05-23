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

The model evolved through two phases. Phase 1 used a 6-class/28-dim contract on
a 3-app corpus; Phase 2 expanded to 8-class/36-dim with structural
post-validation and was evaluated on an 8-app corpus (4,232 endpoints, 12
advisory-backed labels across 6 split groups).

#### Phase 1 (3-app corpus: wger, nautobot, django-mdeditor)

| Approach                            |    TP |     FP |    FN |         P |         R |        F1 |
| ----------------------------------- | ----: | -----: | ----: | --------: | --------: | --------: |
| GNN synth-only (24-dim)             |     3 |    435 |     3 |     0.007 |     0.500 |     0.014 |
| GNN synth-only (28-dim)             |     4 |    103 |     2 |     0.037 |     0.667 |     0.071 |
| Bridging 28-dim (synth → fine-tune) |     4 |     22 |     2 |     0.154 |     0.667 |     0.250 |
| + auth extractor fix                |     6 |     25 |     0 |     0.194 |     1.000 |     0.324 |
| + ownership + post-validation (v7)  |     6 |     10 |     0 |     0.375 |     1.000 |     0.545 |
| 36-dim FT + validated (v8i)         |     5 |      7 |     1 |     0.417 |     0.833 |     0.556 |
| 36-dim Synth + validated (v8i)      |     6 |     11 |     0 |     0.353 |     1.000 |     0.522 |
| Rule baseline (5 rules)             |     6 |      6 |     0 |     0.500 |     1.000 |     0.667 |

#### Phase 2 (8-app corpus, LOAO cross-validation)

| System                          |    TP |     FP |    FN |       P |       R |      F1 |
| ------------------------------- | ----: | -----: | ----: | ------: | ------: | ------: |
| Synth raw GNN                   |    10 |  3,983 |     2 |   0.003 |   0.833 |   0.005 |
| FT raw GNN                      |     5 |  1,377 |     7 |   0.004 |   0.417 |   0.007 |
| FT + validated                  |     5 |     77 |     7 |   0.061 |   0.417 |   0.106 |
| **Synth + validated**           |   **8** | **116** | **4** | **0.065** | **0.667** | **0.118** |
| Rule baseline (5 rules)         |     8 |     81 |     4 |   0.090 |   0.667 |   0.158 |

Key findings:
- The GNN+validator system matches the rule baseline on recall (66.7%)
- Structural post-validation reduces raw GNN FPs by **97%** (3,983 → 116)
- Synthetic pre-training outperforms fine-tuning (8 vs 5 TP) — the tiny real
  corpus cannot teach vulnerability patterns, but synthetic pre-training can
- The GNN achieves 75% of rule baseline F1 with identical recall
- The GNN outperforms rules on individual apps (e.g., sentry: 34 FP vs 36)

### Current Per-App Breakdown (8-app, Synth+validated)

| App                    | CVE            | Subtype         |  TP |  FP |  FN |
| ---------------------- | -------------- | --------------- | --: | --: | --: |
| django-mdeditor        | CVE-2025-13030 | MISSING_AUTH    |   1 |   0 |   0 |
| nautobot (50263)       | CVE-2023-50263 | IDOR            |   2 |  10 |   0 |
| nautobot (51649)       | CVE-2023-51649 | IDOR            |   1 |   9 |   0 |
| pretix                 | CVE-2025-14881 | IDOR            |   0 |  19 |   1 |
| sentry                 | CVE-2026-26004 | MISSING_ROLE    |   1 |  34 |   0 |
| weblate                | CVE-2026-27457 | TENANT/OBJ_PERM |   0 |   7 |   2 |
| wger (27839)           | CVE-2026-27839 | IDOR            |   3 |  33 |   0 |
| wger (40474)           | CVE-2026-40474 | MISSING_ROLE    |   0 |   4 |   1 |

The undetected cases (FN):
- **pretix**: IDOR where the identifier flow is non-trivial (nested organizer scope)
- **weblate**: Tenant isolation failure on a list endpoint with no route params — the
  structural validator cannot distinguish `Addon.objects.all()` from a legitimate
  unscoped queryset without semantic understanding of model hierarchy
- **wger-40474**: Missing role check on gym config edit — lacks distinguishing
  structural signals (no privileged operation type, no write HTTP method)

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

The real corpus contains **8 advisory-backed Django targets** covering 5 CVE
types across 6 independent split groups (4,232 endpoints, 12 labeled
vulnerabilities).

| Application         | CVE             | CWE      | Subtype                | Endpoints | Labels |
| ------------------- | --------------- | -------- | ---------------------- | --------: | -----: |
| wger (27839)        | CVE-2026-27839  | CWE-639  | IDOR                   |       494 |      3 |
| wger (40474)        | CVE-2026-40474  | CWE-863  | MISSING_ROLE           |       494 |      1 |
| nautobot (50263)    | CVE-2023-50263  | CWE-200  | IDOR                   |     1,716 |      2 |
| nautobot (51649)    | CVE-2023-51649  | CWE-639  | IDOR                   |     1,716 |      1 |
| django-mdeditor     | CVE-2025-13030  | CWE-306  | MISSING_AUTH           |         5 |      1 |
| pretix              | CVE-2025-14881  | CWE-639  | IDOR                   |       808 |      1 |
| sentry              | CVE-2026-26004  | CWE-863  | MISSING_ROLE           |       269 |      1 |
| weblate             | CVE-2026-27457  | CWE-862  | TENANT/OBJ_PERM        |       296 |      2 |

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
  --out-dir artifacts/bridging-8class-v2 \
  --synth-model artifacts/synthetic-8class-v2/path_analyzer_synthetic.pt
```

Current eight-app corpus validation summary:

```text
SAFE=4220 MISSING_AUTH=1 MISSING_ROLE=2 IDOR=7
TENANT_ISOLATION_FAILURE=1 OBJECT_LEVEL_PERMISSION_BYPASS=1
COMBINED=0 INTENTIONALLY_PUBLIC=0
split groups: django-mdeditor, nautobot, wger, pretix, sentry, weblate
total endpoints: 4232, vulnerable: 12 (0.28%)
```

Bridging experiment output (Synth + validated GNN, 8-class/36-dim, LOAO CV):

```text
TP=8  FP=116  FN=4  P=0.065  R=0.667  F1=0.118
```

Bridging experiment output (FT + validated GNN, 8-class/36-dim, LOAO CV):

```text
TP=5  FP=77  FN=7  P=0.061  R=0.417  F1=0.106
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

The aggregate result (8-app LOAO cross-validation, 36-dim/8-class model):

| System                          |  TP |    FP |  FN | Vuln P | Vuln R | Vuln F1 |
| ------------------------------- | --: | ----: | --: | -----: | -----: | ------: |
| Synth raw GNN                   |  10 | 3,983 |   2 |  0.003 |  0.833 |   0.005 |
| FT raw GNN                      |   5 | 1,377 |   7 |  0.004 |  0.417 |   0.007 |
| FT + validated                  |   5 |    77 |   7 |  0.061 |  0.417 |   0.106 |
| **Synth + validated**           |   8 |   116 |   4 |  0.065 |  0.667 |   0.118 |
| Rule baseline                   |   8 |    81 |   4 |  0.090 |  0.667 |   0.158 |

Interpretation: The structural post-validator reduces GNN false positives by
97% (3,983 → 116) while preserving 80% of true positives (10 → 8). Synthetic
pre-training outperforms fine-tuning on this sparse real corpus (8 vs 5 TP)
because the GNN learns vulnerability patterns from controlled synthetic graphs
that the tiny real corpus cannot teach. **The Synth+validated system matches
rule baseline recall (66.7%) and achieves 75% of its F1 score**, demonstrating
that the PFG representation captures sufficient structure for learned
vulnerability detection.

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

The corpus covers 5 of 6 vulnerability subtypes with advisory-backed labels.
Priority targets for further corpus expansion:

1. **More MISSING_ROLE apps** — diverse admin-bypass patterns beyond sentry/wger
   to improve FT recall on this subtype.
2. **TENANT apps with structural signals** — cases where tenant isolation
   failure is detectable via route params or model flags (not just queryset
   semantics).
3. **Spring framework apps** — the Spring extractor is implemented but the real
   corpus currently only contains Django targets.

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
