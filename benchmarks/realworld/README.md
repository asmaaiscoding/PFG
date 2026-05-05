# Real-World Training Data & Mixed Training Pipeline

This directory contains **3 mini Django applications** with manually labeled
vulnerability ground truth, plus the infrastructure to use them for training
Model B (PathAnalyzer) alongside synthetic data.

## Apps

| App              | Domain                          | Endpoints | Vulnerabilities                                         | Public |
| ---------------- | ------------------------------- | --------- | ------------------------------------------------------- | ------ |
| `ecommerce_app`  | Orders, products, users         | 23        | 9 (7 IDOR, 2 MISSING_ROLE)                              | 5      |
| `social_app`     | Posts, profiles, messages       | 22        | 7 (5 IDOR, 1 MISSING_ROLE)                              | 7      |
| `healthcare_app` | Patients, appointments, records | 22        | 11 (7 IDOR, 3 MISSING_ROLE, 1 COMBINED, 1 MISSING_AUTH) | 3      |

**Total: 67 labeled endpoints** across all 3 apps.

## Structure

Each app follows the pattern the Django extractor recognizes:

```
<app>/
├── manifest.yaml          # Ground truth labels
└── src/
    ├── urls.py            # Root URL config with include()
    ├── <module>/
    │   ├── urls.py        # path() + DRF router.register()
    │   ├── views.py       # ViewSets, @api_view functions
    │   ├── services.py    # Business logic layer
    │   └── repo.py        # Data access (Model.objects.filter/get/create/delete)
    └── core/
        ├── urls.py
        └── views.py       # Health, login (intentionally public)
```

## Vulnerability Patterns

Each app contains a realistic mix of:

- **SAFE**: Proper auth + ownership checks (or admin-only operations)
- **IDOR**: Has authentication but no ownership check on `{pk}` routes
- **MISSING_ROLE**: Any authenticated user can perform admin actions
- **MISSING_AUTH**: No authentication decorator/permission at all
- **COMBINED**: Both missing role AND missing ownership (e.g., medical notes)
- **INTENTIONALLY_PUBLIC**: Health checks, login, public catalogs

## Quick Start

### 1. Extract & verify a single app

```bash
pfg build benchmarks/realworld/ecommerce_app/src --out /tmp/ecommerce.json --app ecommerce-app
pfg rules /tmp/ecommerce.json
pfg eval benchmarks/realworld/ecommerce_app --detector rule
```

### 2. Train Model B on mixed data (synthetic + real)

```bash
pfg train-mixed benchmarks/realworld \
    --n-synthetic 400 \
    --epochs 30 \
    --holdout healthcare-app \
    --out-model artifacts/path_analyzer_mixed.pt \
    --out-report artifacts/mixed_report.json
```

### 3. Evaluate the mixed-trained model

```bash
pfg eval benchmarks/realworld --detector gnn --checkpoint artifacts/path_analyzer_mixed.pt
```

### 4. Compare with pure-synthetic baseline

```bash
pfg train-and-save --n 600 --epochs 30
pfg eval benchmarks/realworld --detector gnn --checkpoint artifacts/path_analyzer.pt
```

## How the Bridge Works

`src/pfg/training/bridge.py` converts real extracted PFGs + manifest labels
into the same `Sample` objects the synthetic generator produces:

```python
from pfg.training.bridge import samples_from_manifest, samples_from_corpus
from pfg.eval.manifest import load_manifest, discover_manifests

samples = samples_from_manifest(load_manifest("benchmarks/realworld/ecommerce_app/manifest.yaml"))
# or
all_samples = samples_from_corpus(discover_manifests("benchmarks/realworld"))
```

## Adding More Apps

1. Create `benchmarks/realworld/<your_app>/src/` with Django source
2. Add `manifest.yaml` with expected_findings (see `_template/manifest.yaml`)
3. Re-run `pfg train-mixed` — it auto-discovers all manifests
