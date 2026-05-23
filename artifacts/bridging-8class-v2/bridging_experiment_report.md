# Bridging Experiment: Synthetic Pretrain → Real Fine-tune

## Methodology

Leave-one-app-out cross-validation. For each fold the holdout app is
unseen during fine-tuning. The synthetic-pretrained model provides the
initial weights; fine-tuning mixes real data with synthetic vulnerable
samples (knowledge anchors) to prevent catastrophic forgetting.

Synthetic vuln anchors: 331 samples

## Aggregate Results (across all holdout folds)

| System | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned GNN | 5 | 1377 | 7 | 0.0036 | 0.4167 | 0.0072 |
| Fine-tuned GNN (validated) | 5 | 77 | 7 | 0.0610 | 0.4167 | 0.1064 |
| Synthetic-only GNN | 10 | 3983 | 2 | 0.0025 | 0.8333 | 0.0050 |
| Synthetic-only GNN (validated) | 8 | 116 | 4 | 0.0645 | 0.6667 | 0.1176 |
| Rule baseline | 8 | 81 | 4 | 0.0899 | 0.6667 | 0.1584 |

## Per-Fold Breakdown

### Holdout: django-mdeditor
- Training: 3381 real + 331 synth vuln = 3712 total, Val: 846, Test: 5

| System | TP | FP | FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned (django-mdeditor-cve-2025-13030) | 0 | 1 | 1 | 0.000 | 0.000 | 0.000 |
| FT+validated (django-mdeditor-cve-2025-13030) | 0 | 0 | 1 | 0.000 | 0.000 | 0.000 |
| Synthetic-only (django-mdeditor-cve-2025-13030) | 1 | 4 | 0 | 0.200 | 1.000 | 0.333 |
| Synth+validated (django-mdeditor-cve-2025-13030) | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Rule (django-mdeditor-cve-2025-13030) | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |

### Holdout: nautobot
- Training: 2012 real + 331 synth vuln = 2343 total, Val: 504, Test: 1716

| System | TP | FP | FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned (nautobot-cve-2023-50263) | 2 | 8 | 0 | 0.200 | 1.000 | 0.333 |
| Fine-tuned (nautobot-cve-2023-51649) | 0 | 8 | 1 | 0.000 | 0.000 | 0.000 |
| FT+validated (nautobot-cve-2023-50263) | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| FT+validated (nautobot-cve-2023-51649) | 0 | 0 | 1 | 0.000 | 0.000 | 0.000 |
| Synthetic-only (nautobot-cve-2023-50263) | 2 | 837 | 0 | 0.002 | 1.000 | 0.005 |
| Synthetic-only (nautobot-cve-2023-51649) | 1 | 838 | 0 | 0.001 | 1.000 | 0.002 |
| Synth+validated (nautobot-cve-2023-50263) | 2 | 10 | 0 | 0.167 | 1.000 | 0.286 |
| Synth+validated (nautobot-cve-2023-51649) | 1 | 9 | 0 | 0.100 | 1.000 | 0.182 |
| Rule (nautobot-cve-2023-50263) | 2 | 8 | 0 | 0.200 | 1.000 | 0.333 |
| Rule (nautobot-cve-2023-51649) | 1 | 7 | 0 | 0.125 | 1.000 | 0.222 |

### Holdout: pretix
- Training: 2714 real + 331 synth vuln = 3045 total, Val: 679, Test: 839

| System | TP | FP | FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned (pretix-cve-2025-14881) | 0 | 52 | 1 | 0.000 | 0.000 | 0.000 |
| FT+validated (pretix-cve-2025-14881) | 0 | 5 | 1 | 0.000 | 0.000 | 0.000 |
| Synthetic-only (pretix-cve-2025-14881) | 1 | 807 | 0 | 0.001 | 1.000 | 0.002 |
| Synth+validated (pretix-cve-2025-14881) | 0 | 19 | 1 | 0.000 | 0.000 | 0.000 |
| Rule (pretix-cve-2025-14881) | 0 | 5 | 1 | 0.000 | 0.000 | 0.000 |

### Holdout: sentry
- Training: 3167 real + 331 synth vuln = 3498 total, Val: 792, Test: 273

| System | TP | FP | FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned (sentry-cve-2026-26004) | 0 | 114 | 1 | 0.000 | 0.000 | 0.000 |
| FT+validated (sentry-cve-2026-26004) | 0 | 30 | 1 | 0.000 | 0.000 | 0.000 |
| Synthetic-only (sentry-cve-2026-26004) | 1 | 268 | 0 | 0.004 | 1.000 | 0.007 |
| Synth+validated (sentry-cve-2026-26004) | 1 | 34 | 0 | 0.029 | 1.000 | 0.056 |
| Rule (sentry-cve-2026-26004) | 1 | 36 | 0 | 0.027 | 1.000 | 0.053 |

### Holdout: weblate
- Training: 3136 real + 331 synth vuln = 3467 total, Val: 785, Test: 311

| System | TP | FP | FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned (weblate-cve-2026-27457) | 0 | 116 | 2 | 0.000 | 0.000 | 0.000 |
| FT+validated (weblate-cve-2026-27457) | 0 | 5 | 2 | 0.000 | 0.000 | 0.000 |
| Synthetic-only (weblate-cve-2026-27457) | 1 | 295 | 1 | 0.003 | 0.500 | 0.007 |
| Synth+validated (weblate-cve-2026-27457) | 0 | 7 | 2 | 0.000 | 0.000 | 0.000 |
| Rule (weblate-cve-2026-27457) | 0 | 6 | 2 | 0.000 | 0.000 | 0.000 |

### Holdout: wger
- Training: 2515 real + 331 synth vuln = 2846 total, Val: 629, Test: 1088

| System | TP | FP | FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned (wger-cve-2026-27839) | 3 | 551 | 0 | 0.005 | 1.000 | 0.011 |
| Fine-tuned (wger-cve-2026-40474) | 0 | 527 | 1 | 0.000 | 0.000 | 0.000 |
| FT+validated (wger-cve-2026-27839) | 3 | 33 | 0 | 0.083 | 1.000 | 0.154 |
| FT+validated (wger-cve-2026-40474) | 0 | 4 | 1 | 0.000 | 0.000 | 0.000 |
| Synthetic-only (wger-cve-2026-27839) | 3 | 491 | 0 | 0.006 | 1.000 | 0.012 |
| Synthetic-only (wger-cve-2026-40474) | 0 | 443 | 1 | 0.000 | 0.000 | 0.000 |
| Synth+validated (wger-cve-2026-27839) | 3 | 33 | 0 | 0.083 | 1.000 | 0.154 |
| Synth+validated (wger-cve-2026-40474) | 0 | 4 | 1 | 0.000 | 0.000 | 0.000 |
| Rule (wger-cve-2026-27839) | 3 | 17 | 0 | 0.150 | 1.000 | 0.261 |
| Rule (wger-cve-2026-40474) | 0 | 2 | 1 | 0.000 | 0.000 | 0.000 |

## Conclusion

Detailed metrics in `bridging_experiment_metrics.json`.
