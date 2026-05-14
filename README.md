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
2. Encode nodes into the frozen 24-dimensional feature contract.
3. Encode edges as `[is_call, is_identifier_flow]`.
4. Classify each target endpoint with Model B.
5. Evaluate against:
   - our rule baseline,
   - Semgrep output normalized to endpoint findings,
   - CodeQL SARIF output normalized to endpoint findings.

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

Current three-corpus validation summary:

```text
SAFE=465 MISSING_AUTH=3 MISSING_ROLE=0 IDOR=3 COMBINED=0 INTENTIONALLY_PUBLIC=0
split groups: django-mdeditor, nautobot, wger
```

Current rule-baseline caveat:

```text
wger: 1 unlabeled rule-baseline finding
nautobot: 129 unlabeled rule-baseline findings
```

The wger false positive is:

```text
GET /api/v2/exerciseimage/{pk}/thumbnails/
```

This is part of the error-analysis backlog: decide whether it is an unlabeled
real issue, an extractor false positive, or a rule-baseline over-approximation.

Previous first-corpus result:

```text
wger-cve-2026-27839: TP=3 FP=1 FN=0
micro precision=0.750 recall=1.000 F1=0.857
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

## External Tool Comparison

Semgrep and CodeQL are compared through normalized endpoint findings.

Semgrep workflow:

```bash
semgrep scan --config auto --json \
  benchmarks/realworld/wger-cve-2026-27839/src \
  > artifacts/semgrep-wger.json

uv run pfg normalize semgrep artifacts/semgrep-wger.json \
  --manifest benchmarks/realworld/wger-cve-2026-27839/manifest.yaml \
  --out artifacts/semgrep-wger.normalized.json

uv run pfg eval benchmarks/realworld --detector external \
  --external-findings artifacts/semgrep-wger.normalized.json
```

CodeQL workflow:

```bash
codeql database create artifacts/codeql/wger-db \
  --language=python \
  --source-root benchmarks/realworld/wger-cve-2026-27839/src

codeql database analyze artifacts/codeql/wger-db \
  --format=sarifv2.1.0 \
  --output artifacts/codeql-wger.sarif.json

uv run pfg normalize codeql artifacts/codeql-wger.sarif.json \
  --manifest benchmarks/realworld/wger-cve-2026-27839/manifest.yaml \
  --out artifacts/codeql-wger.normalized.json

uv run pfg eval benchmarks/realworld --detector external \
  --external-findings artifacts/codeql-wger.normalized.json
```

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

The corpus now has the minimum three independent split groups required for
train/validation/test. Additional groups remain useful for stronger evidence:

- `Nautobot` / `CVE-2023-51649` / object-level permission enforcement.
- `Nautobot` / `CVE-2023-50263` / unauthenticated db-file-storage views.
- Additional wger advisories may be included, but they should share the `wger`
  split group to avoid app-level leakage.

Final reporting should compare PathAnalyzer real-only, PathAnalyzer
real+augmented, the rule baseline, Semgrep, and CodeQL on the same held-out real
test groups.

## References

- OWASP Top 10 2021, A01 Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- CWE-862 Missing Authorization: https://cwe.mitre.org/data/definitions/862.html
- CWE-863 Incorrect Authorization: https://cwe.mitre.org/data/definitions/863.html
- CWE-639 Authorization Bypass Through User-Controlled Key: https://cwe.mitre.org/data/definitions/639.html
- GATv2 paper, “How Attentive are Graph Attention Networks?”: https://openreview.net/forum?id=F72ximsx7C1
- PyTorch Geometric `GATv2Conv`: https://pytorch-geometric.readthedocs.io/en/stable/generated/torch_geometric.nn.conv.GATv2Conv.html
- Semgrep taint-mode documentation: https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview
- CodeQL Python data-flow documentation: https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/
