# Synthetic-Only Training → Real-World Evaluation

## Methodology

Model B (PathAnalyzer) trained entirely on synthetic PFGs, then evaluated
on all real-world apps. No real data used in training.

## Synthetic Dataset

- Total samples: 774
- Train / Val / Test: 619 / 77 / 78
- Class distribution: {'SAFE': 399, 'MISSING_AUTH': 58, 'MISSING_ROLE': 46, 'IDOR': 99, 'COMBINED': 60, 'INTENTIONALLY_PUBLIC': 112}

## Synthetic Test Metrics (capability proof)

- Accuracy: 0.8718
- Macro F1: 0.8266
- Vuln Precision: 0.8108
- Vuln Recall: 0.9091
- Vuln F1: 0.8571

## Real-World Evaluation

| System | Precision | Recall | F1 |
| --- | ---: | ---: | ---: |
| GNN (synthetic) | 0.0374 | 0.6667 | 0.0708 |
| Rule baseline | 0.4000 | 0.6667 | 0.5000 |

### Per-App Breakdown

| App | System | TP | FP | FN |
| --- | --- | ---: | ---: | ---: |
| django-mdeditor-cve-2025-13030 | GNN | 1 | 1 | 0 |
| nautobot-cve-2023-50263 | GNN | 0 | 9 | 2 |
| wger-cve-2026-27839 | GNN | 3 | 93 | 0 |
| django-mdeditor-cve-2025-13030 | Rule | 1 | 0 | 0 |
| nautobot-cve-2023-50263 | Rule | 0 | 5 | 2 |
| wger-cve-2026-27839 | Rule | 3 | 1 | 0 |

## Conclusion

Detailed per-endpoint predictions are in `synthetic_experiment_metrics.json`.
