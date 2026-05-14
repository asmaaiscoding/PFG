# Bridging Experiment: Synthetic Pretrain → Real Fine-tune

## Methodology

Leave-one-app-out cross-validation. For each fold the holdout app is
unseen during fine-tuning. The synthetic-pretrained model provides the
initial weights; fine-tuning mixes real data with synthetic vulnerable
samples (knowledge anchors) to prevent catastrophic forgetting.

Synthetic vuln anchors: 91 samples

## Aggregate Results (across all holdout folds)

| System | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned GNN | 6 | 25 | 0 | 0.1935 | 1.0000 | 0.3243 |
| Synthetic-only GNN | 6 | 72 | 0 | 0.0769 | 1.0000 | 0.1429 |
| Rule baseline | 6 | 6 | 0 | 0.5000 | 1.0000 | 0.6667 |

## Per-Fold Breakdown

### Holdout: django-mdeditor
- Training: 372 real + 91 synth vuln = 463 total, Val: 94, Test: 5

| System | TP | FP | FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned (django-mdeditor-cve-2025-13030) | 1 | 3 | 0 | 0.250 | 1.000 | 0.400 |
| Synthetic-only (django-mdeditor-cve-2025-13030) | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Rule (django-mdeditor-cve-2025-13030) | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |

### Holdout: nautobot
- Training: 230 real + 91 synth vuln = 321 total, Val: 58, Test: 183

| System | TP | FP | FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned (nautobot-cve-2023-50263) | 2 | 10 | 0 | 0.167 | 1.000 | 0.286 |
| Synthetic-only (nautobot-cve-2023-50263) | 2 | 10 | 0 | 0.167 | 1.000 | 0.286 |
| Rule (nautobot-cve-2023-50263) | 2 | 5 | 0 | 0.286 | 1.000 | 0.444 |

### Holdout: wger
- Training: 150 real + 91 synth vuln = 241 total, Val: 38, Test: 283

| System | TP | FP | FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned (wger-cve-2026-27839) | 3 | 12 | 0 | 0.200 | 1.000 | 0.333 |
| Synthetic-only (wger-cve-2026-27839) | 3 | 62 | 0 | 0.046 | 1.000 | 0.088 |
| Rule (wger-cve-2026-27839) | 3 | 1 | 0 | 0.750 | 1.000 | 0.857 |

## Conclusion

Detailed metrics in `bridging_experiment_metrics.json`.
