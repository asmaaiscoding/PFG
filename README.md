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
multi-layer privilege-flow issues better than rule-only tools. The key IDOR
pattern is:

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

## First Real Corpus Entry

The first real target is **wger** because it is a Django/DRF application with
advisory-backed IDOR issues that match PFG’s intended signal.

Manifest:

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

Build a PFG for the wger vulnerable ref:

```bash
uv run pfg build benchmarks/realworld/wger-cve-2026-27839/src \
  --app wger-cve-2026-27839 \
  --out artifacts/wger-cve-2026-27839.pfg.json
```

Evaluate the rule baseline:

```bash
uv run pfg eval benchmarks/realworld --detector rule \
  --out artifacts/wger-rule-eval.json
```

Current first-corpus rule result after extractor hardening:

```text
wger-cve-2026-27839: TP=3 FP=1 FN=0
micro precision=0.750 recall=1.000 F1=0.857
```

The one current false positive is:

```text
GET /api/v2/exerciseimage/{pk}/thumbnails/
```

This is now part of the error-analysis backlog: decide whether it is an
unlabeled real issue, an extractor false positive, or a rule-baseline
over-approximation.

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

Before claiming Model B results, add at least two more independent real
Django/DRF split groups. Candidates already identified:

- `django-mdeditor` / `CVE-2025-13030` / missing authentication.
- `Nautobot` / `CVE-2023-51649` / object-level permission enforcement.
- `Nautobot` / `CVE-2023-50263` / unauthenticated db-file-storage views.
- Additional wger advisories may be included, but they should share the `wger`
  split group to avoid app-level leakage.

Only after the corpus has multiple independent groups should we train and
report Model B against the rule baseline, Semgrep, and CodeQL.

## References

- OWASP Top 10 2021, A01 Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- CWE-862 Missing Authorization: https://cwe.mitre.org/data/definitions/862.html
- CWE-863 Incorrect Authorization: https://cwe.mitre.org/data/definitions/863.html
- CWE-639 Authorization Bypass Through User-Controlled Key: https://cwe.mitre.org/data/definitions/639.html
- GATv2 paper, “How Attentive are Graph Attention Networks?”: https://openreview.net/forum?id=F72ximsx7C1
- PyTorch Geometric `GATv2Conv`: https://pytorch-geometric.readthedocs.io/en/stable/generated/torch_geometric.nn.conv.GATv2Conv.html
- Semgrep taint-mode documentation: https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview
- CodeQL Python data-flow documentation: https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/
