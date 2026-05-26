# Synthetic-Only Training → Real-World Evaluation

## Methodology

Model B (PathAnalyzer) trained entirely on synthetic PFGs, then evaluated
on all real-world apps. No real data used in training.

## Synthetic Dataset

- Total samples: 636
- Train / Val / Test: 508 / 63 / 65
- Class distribution: {'SAFE': 335, 'MISSING_AUTH': 38, 'MISSING_ROLE': 24, 'IDOR': 57, 'TENANT_ISOLATION_FAILURE': 24, 'OBJECT_LEVEL_PERMISSION_BYPASS': 24, 'COMBINED': 49, 'INTENTIONALLY_PUBLIC': 85}

## Synthetic Test Metrics (capability proof)

- Accuracy: 0.6769
- Macro F1: 0.7232
- Vuln Precision: 0.5333
- Vuln Recall: 1.0000
- Vuln F1: 0.6957

## Real-World Evaluation

| System | Precision | Recall | F1 |
| --- | ---: | ---: | ---: |
| GNN (synthetic) | 0.0011 | 0.2708 | 0.0022 |
| Rule baseline | 0.0396 | 0.1667 | 0.0640 |

### Per-App Breakdown

| App | System | TP | FP | FN |
| --- | --- | ---: | ---: | ---: |
| django-cve-2016-2048 | GNN | 0 | 103 | 1 |
| django-cve-2018-16984 | GNN | 0 | 125 | 1 |
| django-mdeditor-cve-2025-13030 | GNN | 1 | 1 | 0 |
| django-unicorn-cve-2026-31815 | GNN | 0 | 2 | 1 |
| firefighter-cve-2026-42864 | GNN | 0 | 32 | 1 |
| label-studio-cve-2023-47117 | GNN | 0 | 48 | 1 |
| modoboa-cve-2023-0777 | GNN | 0 | 254 | 1 |
| modoboa-cve-2023-2227 | GNN | 0 | 258 | 1 |
| nautobot-cve-2023-50263 | GNN | 0 | 701 | 2 |
| nautobot-cve-2023-51649 | GNN | 1 | 702 | 0 |
| nautobot-cve-2024-29199 | GNN | 0 | 702 | 1 |
| nautobot-cve-2024-36112 | GNN | 1 | 699 | 0 |
| nautobot-cve-2025-49143 | GNN | 0 | 1122 | 1 |
| nautobot-cve-2026-44794 | GNN | 1 | 1447 | 0 |
| plane-cve-2026-30244 | GNN | 0 | 0 | 1 |
| pretix-cve-2025-14881 | GNN | 0 | 680 | 1 |
| pretix-cve-2025-14882 | GNN | 0 | 0 | 1 |
| saleor-cve-2020-7964 | GNN | 0 | 2 | 1 |
| saleor-cve-2022-0932 | GNN | 0 | 5 | 1 |
| sentry-cve-2023-36826 | GNN | 0 | 81 | 1 |
| sentry-cve-2024-45605 | GNN | 0 | 96 | 1 |
| sentry-cve-2024-45606 | GNN | 0 | 96 | 1 |
| sentry-cve-2026-26004 | GNN | 0 | 183 | 1 |
| wagtail-cve-2024-32882 | GNN | 0 | 49 | 1 |
| wagtail-cve-2026-25517 | GNN | 0 | 53 | 1 |
| wagtail-cve-2026-44197 | GNN | 0 | 0 | 1 |
| wagtail-cve-2026-44198 | GNN | 0 | 0 | 1 |
| wagtail-cve-2026-44199 | GNN | 0 | 0 | 1 |
| wagtail-cve-2026-44200 | GNN | 0 | 0 | 1 |
| weblate-cve-2025-67715 | GNN | 0 | 205 | 2 |
| weblate-cve-2026-21889 | GNN | 1 | 205 | 0 |
| weblate-cve-2026-27457 | GNN | 0 | 207 | 2 |
| weblate-cve-2026-33212 | GNN | 0 | 212 | 1 |
| weblate-cve-2026-33214 | GNN | 0 | 212 | 1 |
| weblate-cve-2026-34393 | GNN | 1 | 213 | 0 |
| weblate-cve-2026-44263 | GNN | 1 | 221 | 0 |
| wger-cve-2026-27835 | GNN | 2 | 365 | 0 |
| wger-cve-2026-27838 | GNN | 1 | 369 | 0 |
| wger-cve-2026-27839 | GNN | 3 | 479 | 0 |
| wger-cve-2026-40474 | GNN | 0 | 428 | 1 |
| wger-cve-2026-43948 | GNN | 0 | 482 | 1 |
| wger-cve-2026-43978 | GNN | 0 | 482 | 1 |
| django-cve-2016-2048 | Rule | 0 | 8 | 1 |
| django-cve-2018-16984 | Rule | 0 | 7 | 1 |
| django-mdeditor-cve-2025-13030 | Rule | 1 | 0 | 0 |
| django-unicorn-cve-2026-31815 | Rule | 0 | 0 | 1 |
| firefighter-cve-2026-42864 | Rule | 0 | 0 | 1 |
| label-studio-cve-2023-47117 | Rule | 0 | 5 | 1 |
| modoboa-cve-2023-0777 | Rule | 0 | 11 | 1 |
| modoboa-cve-2023-2227 | Rule | 0 | 11 | 1 |
| nautobot-cve-2023-50263 | Rule | 2 | 3 | 0 |
| nautobot-cve-2023-51649 | Rule | 1 | 2 | 0 |
| nautobot-cve-2024-29199 | Rule | 0 | 2 | 1 |
| nautobot-cve-2024-36112 | Rule | 0 | 2 | 1 |
| nautobot-cve-2025-49143 | Rule | 0 | 4 | 1 |
| nautobot-cve-2026-44794 | Rule | 0 | 1 | 1 |
| plane-cve-2026-30244 | Rule | 0 | 0 | 1 |
| pretix-cve-2025-14881 | Rule | 0 | 1 | 1 |
| pretix-cve-2025-14882 | Rule | 0 | 0 | 1 |
| saleor-cve-2020-7964 | Rule | 0 | 1 | 1 |
| saleor-cve-2022-0932 | Rule | 0 | 1 | 1 |
| sentry-cve-2023-36826 | Rule | 0 | 4 | 1 |
| sentry-cve-2024-45605 | Rule | 0 | 7 | 1 |
| sentry-cve-2024-45606 | Rule | 0 | 7 | 1 |
| sentry-cve-2026-26004 | Rule | 1 | 10 | 0 |
| wagtail-cve-2024-32882 | Rule | 0 | 11 | 1 |
| wagtail-cve-2026-25517 | Rule | 0 | 11 | 1 |
| wagtail-cve-2026-44197 | Rule | 0 | 0 | 1 |
| wagtail-cve-2026-44198 | Rule | 0 | 0 | 1 |
| wagtail-cve-2026-44199 | Rule | 0 | 0 | 1 |
| wagtail-cve-2026-44200 | Rule | 0 | 0 | 1 |
| weblate-cve-2025-67715 | Rule | 0 | 6 | 2 |
| weblate-cve-2026-21889 | Rule | 0 | 6 | 1 |
| weblate-cve-2026-27457 | Rule | 0 | 8 | 2 |
| weblate-cve-2026-33212 | Rule | 0 | 7 | 1 |
| weblate-cve-2026-33214 | Rule | 0 | 7 | 1 |
| weblate-cve-2026-34393 | Rule | 0 | 7 | 1 |
| weblate-cve-2026-44263 | Rule | 0 | 7 | 1 |
| wger-cve-2026-27835 | Rule | 0 | 10 | 2 |
| wger-cve-2026-27838 | Rule | 0 | 13 | 1 |
| wger-cve-2026-27839 | Rule | 3 | 2 | 0 |
| wger-cve-2026-40474 | Rule | 0 | 2 | 1 |
| wger-cve-2026-43948 | Rule | 0 | 5 | 1 |
| wger-cve-2026-43978 | Rule | 0 | 5 | 1 |

## Conclusion

Detailed per-endpoint predictions are in `synthetic_experiment_metrics.json`.
