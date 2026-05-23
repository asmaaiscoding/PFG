# Synthetic-Only Training → Real-World Evaluation

## Methodology

Model B (PathAnalyzer) trained entirely on synthetic PFGs, then evaluated
on all real-world apps. No real data used in training.

## Synthetic Dataset

- Total samples: 636
- Train / Val / Test: 508 / 63 / 65
- Class distribution: {'SAFE': 335, 'MISSING_AUTH': 38, 'MISSING_ROLE': 24, 'IDOR': 57, 'TENANT_ISOLATION_FAILURE': 24, 'OBJECT_LEVEL_PERMISSION_BYPASS': 24, 'COMBINED': 49, 'INTENTIONALLY_PUBLIC': 85}

## Synthetic Test Metrics (capability proof)

- Accuracy: 0.6923
- Macro F1: 0.7294
- Vuln Precision: 0.5455
- Vuln Recall: 1.0000
- Vuln F1: 0.7059

## Real-World Evaluation

| System | Precision | Recall | F1 |
| --- | ---: | ---: | ---: |
| GNN (synthetic) | 0.0025 | 0.8333 | 0.0050 |
| Rule baseline | 0.0899 | 0.6667 | 0.1584 |

### Per-App Breakdown

| App | System | TP | FP | FN |
| --- | --- | ---: | ---: | ---: |
| django-mdeditor-cve-2025-13030 | GNN | 1 | 4 | 0 |
| nautobot-cve-2023-50263 | GNN | 2 | 837 | 0 |
| nautobot-cve-2023-51649 | GNN | 1 | 838 | 0 |
| pretix-cve-2025-14881 | GNN | 1 | 807 | 0 |
| sentry-cve-2026-26004 | GNN | 1 | 268 | 0 |
| weblate-cve-2026-27457 | GNN | 1 | 295 | 1 |
| wger-cve-2026-27839 | GNN | 3 | 491 | 0 |
| wger-cve-2026-40474 | GNN | 0 | 443 | 1 |
| django-mdeditor-cve-2025-13030 | Rule | 1 | 0 | 0 |
| nautobot-cve-2023-50263 | Rule | 2 | 8 | 0 |
| nautobot-cve-2023-51649 | Rule | 1 | 7 | 0 |
| pretix-cve-2025-14881 | Rule | 0 | 5 | 1 |
| sentry-cve-2026-26004 | Rule | 1 | 36 | 0 |
| weblate-cve-2026-27457 | Rule | 0 | 6 | 2 |
| wger-cve-2026-27839 | Rule | 3 | 17 | 0 |
| wger-cve-2026-40474 | Rule | 0 | 2 | 1 |

## Conclusion

Detailed per-endpoint predictions are in `synthetic_experiment_metrics.json`.
