# Synthetic-Only Training → Real-World Evaluation

## Methodology

Model B (PathAnalyzer) trained entirely on synthetic PFGs, then evaluated
on all real-world apps. No real data used in training.

## Synthetic Dataset

- Total samples: 774
- Train / Val / Test: 619 / 77 / 78
- Class distribution: {'SAFE': 399, 'MISSING_AUTH': 58, 'MISSING_ROLE': 46, 'IDOR': 99, 'COMBINED': 60, 'INTENTIONALLY_PUBLIC': 112}

## Synthetic Test Metrics (capability proof)

- Accuracy: 0.8974
- Macro F1: 0.8542
- Vuln Precision: 0.8049
- Vuln Recall: 1.0000
- Vuln F1: 0.8919

## Real-World Evaluation

| System | Precision | Recall | F1 |
| --- | ---: | ---: | ---: |
| GNN (synthetic) | 0.0577 | 1.0000 | 0.1091 |
| Rule baseline | 0.5000 | 1.0000 | 0.6667 |

### Per-App Breakdown

| App | System | TP | FP | FN |
| --- | --- | ---: | ---: | ---: |
| django-mdeditor-cve-2025-13030 | GNN | 1 | 1 | 0 |
| nautobot-cve-2023-50263 | GNN | 2 | 10 | 0 |
| wger-cve-2026-27839 | GNN | 3 | 87 | 0 |
| django-mdeditor-cve-2025-13030 | Rule | 1 | 0 | 0 |
| nautobot-cve-2023-50263 | Rule | 2 | 5 | 0 |
| wger-cve-2026-27839 | Rule | 3 | 1 | 0 |

## Conclusion

Detailed per-endpoint predictions are in `synthetic_experiment_metrics.json`.
