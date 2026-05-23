# Synthetic-Only Training → Real-World Evaluation

## Methodology

Model B (PathAnalyzer) trained entirely on synthetic PFGs, then evaluated
on all real-world apps. No real data used in training.

## Synthetic Dataset

- Total samples: 751
- Train / Val / Test: 600 / 75 / 76
- Class distribution: {'SAFE': 381, 'MISSING_AUTH': 43, 'MISSING_ROLE': 30, 'IDOR': 71, 'TENANT_ISOLATION_FAILURE': 30, 'OBJECT_LEVEL_PERMISSION_BYPASS': 30, 'COMBINED': 51, 'INTENTIONALLY_PUBLIC': 115}

## Synthetic Test Metrics (capability proof)

- Accuracy: 0.7500
- Macro F1: 0.7685
- Vuln Precision: 0.5476
- Vuln Recall: 1.0000
- Vuln F1: 0.7077

## Real-World Evaluation

| System | Precision | Recall | F1 |
| --- | ---: | ---: | ---: |
| GNN (synthetic) | 0.0023 | 0.7500 | 0.0046 |
| Rule baseline | 0.0899 | 0.6667 | 0.1584 |

### Per-App Breakdown

| App | System | TP | FP | FN |
| --- | --- | ---: | ---: | ---: |
| django-mdeditor-cve-2025-13030 | GNN | 1 | 1 | 0 |
| nautobot-cve-2023-50263 | GNN | 2 | 850 | 0 |
| nautobot-cve-2023-51649 | GNN | 0 | 852 | 1 |
| pretix-cve-2025-14881 | GNN | 1 | 775 | 0 |
| sentry-cve-2026-26004 | GNN | 0 | 262 | 1 |
| weblate-cve-2026-27457 | GNN | 2 | 287 | 0 |
| wger-cve-2026-27839 | GNN | 3 | 484 | 0 |
| wger-cve-2026-40474 | GNN | 0 | 405 | 1 |
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
