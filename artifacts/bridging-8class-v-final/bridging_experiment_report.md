# Bridging Experiment: Synthetic Pretrain → Real Fine-tune

## Methodology

Leave-one-app-out cross-validation. For each fold the holdout app is
unseen during fine-tuning. The synthetic-pretrained model provides the
initial weights; fine-tuning mixes real data with synthetic vulnerable
samples (knowledge anchors) to prevent catastrophic forgetting.

Synthetic vuln anchors: 84 samples

## Aggregate Results (across all holdout folds)

| System | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned GNN | 4 | 1030 | 8 | 0.0039 | 0.3333 | 0.0076 |
| Fine-tuned GNN (validated) | 3 | 34 | 9 | 0.0811 | 0.2500 | 0.1224 |
| Synthetic-only GNN | 9 | 3916 | 3 | 0.0023 | 0.7500 | 0.0046 |
| Rule baseline | 8 | 81 | 4 | 0.0899 | 0.6667 | 0.1584 |

## Per-Fold Breakdown

### Holdout: django-mdeditor
- Training: 3381 real + 84 synth vuln = 3465 total, Val: 846, Test: 5

| System | TP | FP | FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned (django-mdeditor-cve-2025-13030) | 0 | 1 | 1 | 0.000 | 0.000 | 0.000 |
| FT+validated (django-mdeditor-cve-2025-13030) | 0 | 0 | 1 | 0.000 | 0.000 | 0.000 |
| Synthetic-only (django-mdeditor-cve-2025-13030) | 1 | 1 | 0 | 0.500 | 1.000 | 0.667 |
| Rule (django-mdeditor-cve-2025-13030) | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |

### Holdout: nautobot
- Training: 2012 real + 84 synth vuln = 2096 total, Val: 504, Test: 1716

| System | TP | FP | FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned (nautobot-cve-2023-50263) | 0 | 78 | 2 | 0.000 | 0.000 | 0.000 |
| Fine-tuned (nautobot-cve-2023-51649) | 0 | 78 | 1 | 0.000 | 0.000 | 0.000 |
| FT+validated (nautobot-cve-2023-50263) | 0 | 0 | 2 | 0.000 | 0.000 | 0.000 |
| FT+validated (nautobot-cve-2023-51649) | 0 | 0 | 1 | 0.000 | 0.000 | 0.000 |
| Synthetic-only (nautobot-cve-2023-50263) | 2 | 850 | 0 | 0.002 | 1.000 | 0.005 |
| Synthetic-only (nautobot-cve-2023-51649) | 0 | 852 | 1 | 0.000 | 0.000 | 0.000 |
| Rule (nautobot-cve-2023-50263) | 2 | 8 | 0 | 0.200 | 1.000 | 0.333 |
| Rule (nautobot-cve-2023-51649) | 1 | 7 | 0 | 0.125 | 1.000 | 0.222 |

### Holdout: pretix
- Training: 2714 real + 84 synth vuln = 2798 total, Val: 679, Test: 839

| System | TP | FP | FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned (pretix-cve-2025-14881) | 0 | 46 | 1 | 0.000 | 0.000 | 0.000 |
| FT+validated (pretix-cve-2025-14881) | 0 | 0 | 1 | 0.000 | 0.000 | 0.000 |
| Synthetic-only (pretix-cve-2025-14881) | 1 | 775 | 0 | 0.001 | 1.000 | 0.003 |
| Rule (pretix-cve-2025-14881) | 0 | 5 | 1 | 0.000 | 0.000 | 0.000 |

### Holdout: sentry
- Training: 3167 real + 84 synth vuln = 3251 total, Val: 792, Test: 273

| System | TP | FP | FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned (sentry-cve-2026-26004) | 0 | 107 | 1 | 0.000 | 0.000 | 0.000 |
| FT+validated (sentry-cve-2026-26004) | 0 | 19 | 1 | 0.000 | 0.000 | 0.000 |
| Synthetic-only (sentry-cve-2026-26004) | 0 | 262 | 1 | 0.000 | 0.000 | 0.000 |
| Rule (sentry-cve-2026-26004) | 1 | 36 | 0 | 0.027 | 1.000 | 0.053 |

### Holdout: weblate
- Training: 3136 real + 84 synth vuln = 3220 total, Val: 785, Test: 311

| System | TP | FP | FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned (weblate-cve-2026-27457) | 1 | 176 | 1 | 0.006 | 0.500 | 0.011 |
| FT+validated (weblate-cve-2026-27457) | 0 | 4 | 2 | 0.000 | 0.000 | 0.000 |
| Synthetic-only (weblate-cve-2026-27457) | 2 | 287 | 0 | 0.007 | 1.000 | 0.014 |
| Rule (weblate-cve-2026-27457) | 0 | 6 | 2 | 0.000 | 0.000 | 0.000 |

### Holdout: wger
- Training: 2515 real + 84 synth vuln = 2599 total, Val: 629, Test: 1088

| System | TP | FP | FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned (wger-cve-2026-27839) | 3 | 225 | 0 | 0.013 | 1.000 | 0.026 |
| Fine-tuned (wger-cve-2026-40474) | 0 | 319 | 1 | 0.000 | 0.000 | 0.000 |
| FT+validated (wger-cve-2026-27839) | 3 | 7 | 0 | 0.300 | 1.000 | 0.462 |
| FT+validated (wger-cve-2026-40474) | 0 | 4 | 1 | 0.000 | 0.000 | 0.000 |
| Synthetic-only (wger-cve-2026-27839) | 3 | 484 | 0 | 0.006 | 1.000 | 0.012 |
| Synthetic-only (wger-cve-2026-40474) | 0 | 405 | 1 | 0.000 | 0.000 | 0.000 |
| Rule (wger-cve-2026-27839) | 3 | 17 | 0 | 0.150 | 1.000 | 0.261 |
| Rule (wger-cve-2026-40474) | 0 | 2 | 1 | 0.000 | 0.000 | 0.000 |

## Conclusion

Detailed metrics in `bridging_experiment_metrics.json`.
