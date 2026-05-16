# Bridging Experiment: Synthetic Pretrain → Real Fine-tune

## Methodology

Leave-one-app-out cross-validation. For each fold the holdout app is
unseen during fine-tuning. The synthetic-pretrained model provides the
initial weights; fine-tuning mixes real data with synthetic vulnerable
samples (knowledge anchors) to prevent catastrophic forgetting.

Synthetic vuln anchors: 78 samples

## Aggregate Results (across all holdout folds)

| System | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned GNN | 5 | 240 | 1 | 0.0204 | 0.8333 | 0.0398 |
| Fine-tuned GNN (validated) | 5 | 7 | 1 | 0.4167 | 0.8333 | 0.5556 |
| Synthetic-only GNN | 6 | 416 | 0 | 0.0142 | 1.0000 | 0.0280 |
| Rule baseline | 6 | 6 | 0 | 0.5000 | 1.0000 | 0.6667 |

## Per-Fold Breakdown

### Holdout: django-mdeditor
- Training: 372 real + 78 synth vuln = 450 total, Val: 94, Test: 5

| System | TP | FP | FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned (django-mdeditor-cve-2025-13030) | 0 | 1 | 1 | 0.000 | 0.000 | 0.000 |
| FT+validated (django-mdeditor-cve-2025-13030) | 0 | 0 | 1 | 0.000 | 0.000 | 0.000 |
| Synthetic-only (django-mdeditor-cve-2025-13030) | 1 | 4 | 0 | 0.200 | 1.000 | 0.333 |
| Rule (django-mdeditor-cve-2025-13030) | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |

### Holdout: nautobot
- Training: 230 real + 78 synth vuln = 308 total, Val: 58, Test: 183

| System | TP | FP | FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned (nautobot-cve-2023-50263) | 2 | 35 | 0 | 0.054 | 1.000 | 0.103 |
| FT+validated (nautobot-cve-2023-50263) | 2 | 6 | 0 | 0.250 | 1.000 | 0.400 |
| Synthetic-only (nautobot-cve-2023-50263) | 2 | 171 | 0 | 0.012 | 1.000 | 0.023 |
| Rule (nautobot-cve-2023-50263) | 2 | 5 | 0 | 0.286 | 1.000 | 0.444 |

### Holdout: wger
- Training: 150 real + 78 synth vuln = 228 total, Val: 38, Test: 283

| System | TP | FP | FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fine-tuned (wger-cve-2026-27839) | 3 | 204 | 0 | 0.014 | 1.000 | 0.029 |
| FT+validated (wger-cve-2026-27839) | 3 | 1 | 0 | 0.750 | 1.000 | 0.857 |
| Synthetic-only (wger-cve-2026-27839) | 3 | 241 | 0 | 0.012 | 1.000 | 0.024 |
| Rule (wger-cve-2026-27839) | 3 | 1 | 0 | 0.750 | 1.000 | 0.857 |

## Conclusion

Detailed metrics in `bridging_experiment_metrics.json`.
