# PathAnalyzer Final Real-Corpus Report (v2)

## Methodology

This report evaluates Model B / PathAnalyzer with three training strategies:
1. **Real-only** — baseline trained on real extracted PFGs only.
2. **Real + Augmented** — real PFGs plus capped real-derived augmentations with focal loss.
3. **Two-stage** — contrastive synthetic pre-training then fine-tuning on real+augmented.

Validation and test are always real-only.

> Warning: The selected training split produced zero augmented samples; real+augmented metrics are therefore not an augmentation comparison.

## Dataset Split

- Train groups: django-mdeditor
- Validation groups: nautobot
- Test groups: wger
- Real train samples: 5
- Augmented train samples: 0
- Synthetic contrastive samples: 360
- Real validation samples: 183
- Real test samples: 283

## Model Comparison

| System | Accuracy | Macro F1 | Vuln Precision | Vuln Recall | Vuln F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| PathAnalyzer real-only | 0.5371 | 0.1165 | 0.0000 | 0.0000 | 0.0000 |
| PathAnalyzer real + augmented | 0.3710 | 0.0902 | 0.0000 | 0.0000 | 0.0000 |
| PathAnalyzer two-stage | 0.9859 | 0.1655 | 0.0000 | 0.0000 | 0.0000 |

## Augmentation Delta (vs real-only)

- Macro F1 delta: -0.0263
- Accuracy delta: -0.1661
- Vulnerability recall delta: 0.0000
- Vulnerability precision delta: 0.0000

## Two-Stage Delta (vs real-only)

- Macro F1 delta: 0.0490
- Accuracy delta: 0.4488
- Vulnerability recall delta: 0.0000
- Vulnerability precision delta: 0.0000

## Baselines

- Rule baseline on held-out test groups: precision=0.7500, recall=1.0000, F1=0.8571
- Semgrep: not_run
- CodeQL: not_run

## Error Analysis

- PathAnalyzer real-only errors: 131
- PathAnalyzer real + augmented errors: 178
- PathAnalyzer two-stage errors: 4

Detailed endpoint-level predictions, explanations, and confusion matrices are in `final_metrics.json`.

## Limitations

External-tool results are marked `not_run` unless normalized Semgrep/CodeQL findings are provided. Large real apps may still expose extractor false positives that are tracked in error analysis rather than hidden.
