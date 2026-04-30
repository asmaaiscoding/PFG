# Privilege Flow Graphs for Detecting Access Control Vulnerabilities via GNNs
## Implementation-Ready Plan (v2)

> Changes from v1: scope tightened to ship a thesis on time, extractor de-risked first, GNN justified against rule baselines, label strategy concretized, weekly milestones with explicit go/no-go gates.

---

## 0. Scope decisions (locked before any code)

| Decision | v1 | v2 (locked) | Rationale |
|---|---|---|---|
| Frameworks | Django + Spring Boot | **Django only as primary; Spring Boot demoted to "extensibility demo" (1 extractor pass, no full eval)** | Two production-grade extractors is a thesis on its own. |
| Models | Model A (anomaly) + Model B (path) | **Model B is primary contribution; Model A is secondary / future work if time permits** | Model B is directly tied to IDOR (the headline claim). Model A's "inconsistent ≠ vulnerable" assumption is hard to defend. |
| Headline claim | "First learned IDOR detector + access-control GNN" | **"First learned IDOR detector"** (singular, defensible) | One sharp claim survives review better than four. |
| GNN justification | Implicit | **Mandatory: GNN must beat a rule-based baseline on the same PFG** by ≥5 F1 points or the thesis pivots to "PFG + rules, with GNN ablation" | Anticipates the #1 reviewer question. |
| Real-world apps | 5 Django + 5 Spring Boot | **3 Django CVE apps + 3 Django GitHub apps** | Realistic given manual-validation cost. |
| Synthetic apps | 5–8 Django + 5–8 Spring Boot | **6 Django apps generated from a parameterized template** + **2 hand-written for realism** | Templated generation lets you scale labels and run sensitivity analyses without 16 from-scratch builds. |
| Timeline | Unspecified | **28 weeks**, 5 phases, hard gates | Forces de-scoping when something slips. |

---

## 1. Risk register and de-risking sequence

| # | Risk | Probability | Impact | Mitigation | Trigger to act |
|---|---|---|---|---|---|
| R1 | Django extractor underestimates inter-procedural identifier flow | High | Critical | Build the extractor *first* on one tiny app (Phase 2a, week 3). Do not touch GNN code until extractor passes a manual ground-truth audit. | Extractor accuracy <90% on hand-labeled audit. |
| R2 | GNN does not beat rules on PFG | Medium | Critical | Implement rule baseline in Phase 2 (before GNN). Treat as primary baseline, not afterthought. | If rules ≥ GNN F1 in Phase 3 sanity check, pivot framing to "PFG enables both rule and learned detection". |
| R3 | Real-world labels too sparse / noisy | High | High | Pre-screen CVE corpus in Phase 1; require ≥3 reproducible CVE apps before committing. | <3 reproducible CVEs by week 6. |
| R4 | Path explosion in Model B | Medium | Medium | Hard depth cap = 6, hard branch cap = 50 paths per endpoint, drop endpoints exceeding cap and report as "not analyzed". | Median path count >100 on synthetic apps. |
| R5 | Model overfits synthetic generation pattern | High | High | Train/test split is **by application**, never by endpoint. Hold out the 2 hand-written apps from training entirely. | Test F1 drops >15 points vs. validation F1. |
| R6 | Spring Boot scope creep eats Django time | Medium | High | Spring Boot is forbidden until Django end-to-end pipeline passes Phase 4 gate. | Any Spring Boot work before week 22. |

---

## 2. Concrete artifact specifications

### 2.1 PFG file format (frozen contract between extractor and GNN)

PFGs are serialized as JSON, then converted to PyG `Data` at load time. JSON is the source of truth for debuggability and version control.

```json
{
  "schema_version": "1.0",
  "application": "synthetic-banking-01",
  "framework": "django",
  "nodes": [
    {
      "id": "ep_001",
      "type": "endpoint",
      "attrs": {
        "http_method": "GET",
        "route": "/api/accounts/{id}/transactions",
        "route_params": ["id"],
        "requires_auth": true,
        "required_role": "USER",
        "ownership_check_present": false,
        "is_intentionally_public": false,
        "source_location": "app/views.py:42"
      }
    },
    {
      "id": "da_007",
      "type": "data_access",
      "attrs": {
        "operation": "READ",
        "target_entity": "Transaction",
        "has_ownership_predicate": false,
        "ownership_predicate_type": "NONE",
        "user_controlled_params_in_query": ["id"],
        "source_location": "app/services.py:88"
      }
    }
  ],
  "edges": [
    {"src": "ep_001", "dst": "svc_003", "type": "call"},
    {"src": "ep_001", "dst": "da_007", "type": "identifier_flow", "param": "id"}
  ],
  "labels": {
    "ep_001": {"label": "VULNERABLE", "subtype": "IDOR", "cwe": "CWE-639"}
  }
}
```

**Schema validation**: every PFG must pass a JSON Schema validator (`schemas/pfg-1.0.json`) before entering the dataset. CI fails otherwise.

### 2.2 Node feature vector (frozen)

Total dim = **24** (concat order is fixed; reordering breaks model checkpoints).

| Slice | Dim | Encoding | Notes |
|---|---|---|---|
| node_type | 4 | one-hot | endpoint, middleware, service, data_access |
| http_method | 5 | one-hot, all-zero if N/A | GET, POST, PUT, DELETE, PATCH |
| requires_auth | 1 | binary | 0 if N/A |
| required_role | 5 | one-hot | NONE, USER, MOD, ADMIN, SUPERADMIN |
| ownership_check_present | 1 | binary | endpoint-level |
| guard_type | 3 | one-hot | AUTH, ROLE, OWNERSHIP (zero if not a guard) |
| op_type | 4 | one-hot | READ, WRITE, UPDATE, DELETE |
| has_ownership_predicate | 1 | binary | data-access only |

### 2.3 Edge feature vector
2 dims, one-hot: `[call, identifier_flow]`. Identifier name is stored separately as a string (not in the feature tensor) for IDOR attribution.

### 2.4 Labeling scheme
Per endpoint node, exactly one of:
- `SAFE`
- `VULNERABLE` with subtype ∈ {`MISSING_AUTH`, `MISSING_ROLE`, `IDOR`, `COMBINED`}
- `INTENTIONALLY_PUBLIC`

Path-level label (Model B): `PROPERLY_GUARDED` | `INSUFFICIENTLY_GUARDED`. A path inherits its endpoint's label *only* when the data-access terminus is the one referenced by the vulnerability.

---

## 3. Repository structure (create on day 1)

```
pfg/
├── pyproject.toml                # uv / hatch project, Python 3.11
├── README.md
├── schemas/
│   └── pfg-1.0.json              # JSON Schema for PFG files
├── src/pfg/
│   ├── extractors/
│   │   ├── base.py               # Extractor ABC
│   │   └── django/
│   │       ├── endpoints.py
│   │       ├── auth.py
│   │       ├── callgraph.py
│   │       ├── dataaccess.py
│   │       └── idflow.py
│   ├── pfg/
│   │   ├── nodes.py              # dataclasses for each node type
│   │   ├── graph.py              # PFG container, JSON I/O
│   │   └── features.py           # feature vector encoding (frozen)
│   ├── detectors/
│   │   ├── rule_baseline.py      # MUST be implemented before any GNN
│   │   ├── model_b.py            # path GNN
│   │   └── model_a.py            # anomaly GNN (optional)
│   ├── eval/
│   │   ├── metrics.py
│   │   └── report.py
│   └── cli.py
├── benchmarks/
│   ├── synthetic/
│   │   ├── template/             # parameterized Django app skeleton
│   │   ├── generate.py           # produces N apps with controlled vuln ratios
│   │   └── ground_truth/         # one YAML per generated app
│   ├── handwritten/              # 2 apps, frozen, never used for training
│   └── realworld/
│       └── manifests/            # git ref + CVE ID + vuln endpoint per app
├── tests/
│   ├── unit/                     # extractor unit tests
│   └── golden/                   # PFG snapshot tests (input app -> expected JSON)
├── experiments/                  # MLflow runs, configs as YAML
└── docs/
    ├── pfg-spec.md               # the formal spec
    ├── auth-pattern-catalog.md   # Django+(Spring) idioms
    └── thesis/                   # LaTeX
```

---

## 4. Phased plan with weekly gates

> Weeks are working weeks. Each phase ends with a **gate**: a measurable check. If a gate fails, follow the de-scope rule, do not push the gate.

### Phase 0 — Foundation (weeks 1–2)
- **W1**: Repo bootstrap, CI (lint, type-check, unit tests, JSON-schema validation), MLflow up, dataset directory layout.
- **W2**: Literature review → 1 short doc (`docs/related-work.md`, 6–10 pages). Auth-pattern catalog v0.1 (Django only).
- **Gate G0**: `pip install -e .` works, CI green on empty repo, schema validator runs, related-work doc reviewed by advisor.

### Phase 1 — Spec + tiniest synthetic app (weeks 3–4)
- **W3**: Freeze PFG JSON schema (above). Hand-author the PFG of one toy Django app (3 endpoints, 1 IDOR). Commit as `tests/golden/toy_app/expected.json`.
- **W4**: Hand-author 5 more toy PFGs covering each vuln subtype. Implement `pfg.graph` JSON load/save + schema validation.
- **Gate G1**: 6 hand-authored PFGs validate. The IDOR detection rule (§3.3 of original) is implemented as pure Python over the PFG and correctly classifies all 6.

> **De-risking**: at this point the rule baseline already works on hand-authored PFGs. The remaining question is whether the *extractor* can produce correct PFGs from source.

### Phase 2 — Django extractor (weeks 5–11)
Implemented incrementally; each sub-phase has a snapshot test against a real toy app.

- **W5 (2.1)** Endpoint discovery: `urls.py` parsing, FBV + CBV + DRF ViewSet routing. Output: list of endpoints with route params.
  - *Test*: 100% endpoint recall on toy_app and on a 20-endpoint reference app.
- **W6 (2.2)** Auth annotation: decorators, `LoginRequiredMixin`, DRF `permission_classes`/`authentication_classes`, project `MIDDLEWARE`.
  - *Test*: hand-labeled `(requires_auth, required_role)` matches on 30 endpoints.
- **W7–8 (2.3)** Intra-project call graph: AST-based, import resolution, method dispatch via type hints + heuristics. Depth cap 8.
  - *Test*: golden call-graph snapshots for 3 apps.
- **W9 (2.4)** Data access detection: ORM call sites + ownership-predicate detection (`request.user` in `.filter()` kwargs, `get_object_or_404` + assertion patterns).
  - *Test*: hand-labeled ownership flags match on 50 ORM calls.
- **W10 (2.5)** Identifier flow: intra-procedural def-use chain from route param → service args → ORM kwargs.
  - *Test*: 100% recall on synthetic IDOR examples.
- **W11 (2.6)** PFG assembly + visualization (Graphviz dot export).
- **Gate G2**: Run extractor on the 8 synthetic Django apps. **Annotation accuracy ≥90%** on a stratified hand-audited sample (200 annotations). If <90%, fix before proceeding. If <80%, escalate to advisor and consider scope cut.

### Phase 3 — Synthetic dataset + rule baseline + Model B (weeks 12–17)
- **W12** Build the parameterized synthetic generator (`benchmarks/synthetic/generate.py`). Inputs: domain, #endpoints, vuln rate per subtype, seed. Outputs: Django source + `ground_truth.yaml`. Generate 6 apps × 4 vuln rates.
- **W12** Hand-write the 2 held-out realism apps.
- **W13** Implement `rule_baseline.py`: pure-Python IDOR rule (§3.3) + missing-auth + missing-role rules over the PFG. Score on synthetic set. **This is the bar Model B must beat.**
- **W14–15** Implement Model B: path enumeration (DFS, depth=6, ≤50 paths/endpoint), GAT path encoder (3 layers, 4 heads, hidden 64), MLP head, dedicated IDOR head. Cross-validation by application (leave-one-app-out).
- **W16** Hyperparameter sweep (a small one: lr ∈ {1e-3, 1e-4}, hidden ∈ {32, 64}, layers ∈ {2, 3}). Track in MLflow.
- **W17** Ablations: no identifier-flow edges, no auth annotations, GAT vs GraphSAGE, GNN vs LSTM-on-path.
- **Gate G3**: On synthetic test apps (LOAO CV), Model B reaches **F1 ≥ 0.80 AND F1 ≥ rule_baseline + 0.05**. If not: do not proceed to real-world; either fix features/architecture or pivot the framing to "PFG + rules, GNN as enhancement".

### Phase 4 — Real-world evaluation (weeks 18–23)
- **W18** Curate the real-world corpus. Required minimum: 3 reproducible CVE apps (CWE-862 or CWE-639, Django, you can build the project and reproduce the vuln locally) + 3 GitHub apps with ≥20 endpoints. Write per-app `manifest.yaml` (git ref, vuln endpoint, expected label).
- **W19** Run pipeline on CVE apps. Measure recall on known vulns. Manually triage all extra findings.
- **W20** Run on GitHub apps. Manual review of every finding by you; second-opinion review of a 30% sample by a peer.
- **W21** Baselines on the same corpus: Semgrep (community access-control rules), CodeQL (CWE-862 + CWE-639 packs). Same metrics.
- **W22** Scalability: PFG construction time + GNN inference time vs LOC and #endpoints. Plot.
- **W23** Error analysis: every FP and FN categorized as {extraction error, model error, label noise, intentional public}.
- **Gate G4**: Real-world recall on CVE set ≥ 2/3. Real-world precision ≥ 0.50 on GitHub apps. (Lower than synthetic targets — this is realistic.) Comparison table vs Semgrep/CodeQL exists.

### Phase 5 — Spring Boot demo + CLI + thesis (weeks 24–28)
- **W24–25** Spring Boot extractor: minimum viable — endpoints, `@PreAuthorize`, JPA repo calls, `@PathVariable` flow. Run on **one** Spring Boot app, demonstrate PFG construction and rule-based IDOR detection. **No GNN training on Spring data**; framework-extensibility is shown by extractor + rules sharing the PFG schema.
- **W26** CLI: `pfg analyze <project> --framework django -o report.html`. Report = visualization + flagged endpoints + path + missing-check explanation.
- **W27** Thesis writing — methodology + results.
- **W28** Thesis writing — intro, related work, discussion, future work. Defense prep.
- **Gate G5**: Thesis draft to advisor 2 weeks before submission deadline.

---

## 5. What you do *not* build (explicit non-goals)

To prevent scope creep, write these into the thesis as future work:

1. Inter-procedural alias / object-flow analysis beyond simple def-use chains.
2. Dynamic permission checks inferred from runtime tracing.
3. Frameworks beyond Django + the Spring Boot demo (Express, Flask, ASP.NET, Laravel).
4. Model A productionization — keep it as an ablation chapter only if Phase 3 finishes early.
5. Responsible disclosure of new CVEs (mention in thesis, do not let it block submission).
6. A graph-autoencoder variant of Model A (kill it; it dilutes the contribution).

---

## 6. Reproducibility checklist (must hold at submission)

- [ ] All synthetic apps regenerated from `generate.py --seed N` reproducibly.
- [ ] Every PFG in the dataset validates against `schemas/pfg-1.0.json`.
- [ ] All experiment configs are YAML files committed under `experiments/`.
- [ ] Model checkpoints, training curves, and metrics tables are in MLflow and exported to `experiments/results/`.
- [ ] CLI runs end-to-end on a fresh clone with `pip install -e . && pfg analyze ./benchmarks/synthetic/app01`.
- [ ] `pytest` runs all unit + golden tests in <5 minutes and is green.

---

## 7. Single-sentence weekly status template

Use this every Friday in the lab notebook:

> Week N: completed X (gate progress: G_k at p%); blocked by Y; next week ships Z; risks raised: R_i.

---

## 8. Decision log (append-only)

| Date | Decision | Reason |
|---|---|---|
| 2026-04-30 | Drop Spring Boot from primary evaluation; demo only. | Two extractors is a thesis on its own; Django covers the headline IDOR claim. |
| 2026-04-30 | Model A demoted to optional ablation. | "Inconsistency = vulnerability" is hard to defend at viva. |
| 2026-04-30 | Rule baseline on PFG is mandatory and must run before GNN. | Anticipates the #1 reviewer question and provides a working fallback if GNN underperforms. |
| 2026-04-30 | Synthetic apps generated from one parameterized template, not 16 hand-built apps. | Reproducibility, faster iteration, controlled vuln ratios for free. |
