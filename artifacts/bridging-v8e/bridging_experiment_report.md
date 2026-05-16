# Bridging Experiment: Synthetic Pretrain → Real Fine-tune

## Methodology

Leave-one-app-out cross-validation. For each fold the holdout app is
unseen during fine-tuning. The synthetic-pretrained model provides the
initial weights; fine-tuning mixes real data with synthetic vulnerable
samples (knowledge anchors) to prevent catastrophic forgetting.

Synthetic vuln anchors: 79 samples

## Aggregate Results (across all holdout folds)

| System | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned GNN | 4 | 179 | 2 | 0.0219 | 0.6667 | 0.0423 |
| Fine-tuned GNN (validated) | 4 | 10 | 2 | 0.2857 | 0.6667 | 0.4000 |
| Synthetic-only GNN | 4 | 179 | 2 | 0.0219 | 0.6667 | 0.0423 |
| Rule baseline | 6 | 6 | 0 | 0.5000 | 1.0000 | 0.6667 |

## Per-Fold Breakdown

### Holdout: django-mdeditor
- Training: 372 real + 79 synth vuln = 451 total, Val: 94, Test: 5

| System | TP | FP | FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned (django-mdeditor-cve-2025-13030) | 1 | 4 | 0 | 0.200 | 1.000 | 0.333 |
| FT+validated (django-mdeditor-cve-2025-13030) | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Synthetic-only (django-mdeditor-cve-2025-13030) | 1 | 4 | 0 | 0.200 | 1.000 | 0.333 |
| Rule (django-mdeditor-cve-2025-13030) | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |

### Holdout: nautobot
- Training: 230 real + 79 synth vuln = 309 total, Val: 58, Test: 183

| System | TP | FP | FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned (nautobot-cve-2023-50263) | 2 | 171 | 0 | 0.012 | 1.000 | 0.023 |
| FT+validated (nautobot-cve-2023-50263) | 2 | 6 | 0 | 0.250 | 1.000 | 0.400 |
| Synthetic-only (nautobot-cve-2023-50263) | 2 | 171 | 0 | 0.012 | 1.000 | 0.023 |
| Rule (nautobot-cve-2023-50263) | 2 | 5 | 0 | 0.286 | 1.000 | 0.444 |

### Holdout: wger
- Training: 150 real + 79 synth vuln = 229 total, Val: 38, Test: 283

| System | TP | FP | FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned (wger-cve-2026-27839) | 1 | 4 | 2 | 0.200 | 0.333 | 0.250 |
| FT+validated (wger-cve-2026-27839) | 1 | 4 | 2 | 0.200 | 0.333 | 0.250 |
| Synthetic-only (wger-cve-2026-27839) | 1 | 4 | 2 | 0.200 | 0.333 | 0.250 |
| Rule (wger-cve-2026-27839) | 3 | 1 | 0 | 0.750 | 1.000 | 0.857 |

## Conclusion

Detailed metrics in `bridging_experiment_metrics.json`.
