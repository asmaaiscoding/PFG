# Synthetic-Only Training → Real-World Evaluation

## Methodology

Model B (PathAnalyzer) trained entirely on synthetic PFGs, then evaluated
on all real-world apps. No real data used in training.

## Synthetic Dataset

- Total samples: 734
- Train / Val / Test: 587 / 73 / 74
- Class distribution: {'SAFE': 362, 'MISSING_AUTH': 45, 'MISSING_ROLE': 31, 'IDOR': 69, 'TENANT_ISOLATION_FAILURE': 31, 'OBJECT_LEVEL_PERMISSION_BYPASS': 31, 'COMBINED': 42, 'INTENTIONALLY_PUBLIC': 123}

## Synthetic Test Metrics (capability proof)

- Accuracy: 0.7027
- Macro F1: 0.7607
- Vuln Precision: 0.5686
- Vuln Recall: 1.0000
- Vuln F1: 0.7250

## Real-World Evaluation

| System | Precision | Recall | F1 |
| --- | ---: | ---: | ---: |
| GNN (synthetic) | 0.0142 | 1.0000 | 0.0280 |
| Rule baseline | 0.5000 | 1.0000 | 0.6667 |

### Per-App Breakdown

| App | System | TP | FP | FN |
| --- | --- | ---: | ---: | ---: |
| django-mdeditor-cve-2025-13030 | GNN | 1 | 4 | 0 |
| nautobot-cve-2023-50263 | GNN | 2 | 171 | 0 |
| wger-cve-2026-27839 | GNN | 3 | 241 | 0 |
| django-mdeditor-cve-2025-13030 | Rule | 1 | 0 | 0 |
| nautobot-cve-2023-50263 | Rule | 2 | 5 | 0 |
| wger-cve-2026-27839 | Rule | 3 | 1 | 0 |

## Conclusion

Detailed per-endpoint predictions are in `synthetic_experiment_metrics.json`.
