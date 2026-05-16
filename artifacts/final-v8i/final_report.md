# PathAnalyzer Final Real-Corpus Report (v2)

## Methodology

This report evaluates Model B / PathAnalyzer with three training strategies:
1. **Real-only** — baseline trained on real extracted PFGs only.
2. **Real + Augmented** — real PFGs plus capped real-derived augmentations with focal loss.
3. **Two-stage** — contrastive synthetic pre-training then fine-tuning on real+augmented.

Validation and test are always real-only.

## Dataset Split

- Train groups: nautobot
- Validation groups: django-mdeditor
- Test groups: wger
- Real train samples: 183
- Augmented train samples: 10
- Weak-supervision train samples: 0
- Synthetic contrastive samples: 360
- Real validation samples: 5
- Real test samples: 283

## Model Comparison

| System | Accuracy | Macro F1 | Vuln Precision | Vuln Recall | Vuln F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| PathAnalyzer real-only | 0.9894 | 0.1243 | 0.0000 | 0.0000 | 0.0000 |
| PathAnalyzer real + augmented | 0.9470 | 0.1220 | 0.1429 | 0.6667 | 0.2353 |
| PathAnalyzer two-stage | 0.9788 | 0.1237 | 0.0000 | 0.0000 | 0.0000 |

## Augmentation Delta (vs real-only)

- Macro F1 delta: -0.0023
- Accuracy delta: -0.0424
- Vulnerability recall delta: 0.6667
- Vulnerability precision delta: 0.1429

## Two-Stage Delta (vs real-only)

- Macro F1 delta: -0.0007
- Accuracy delta: -0.0106
- Vulnerability recall delta: 0.0000
- Vulnerability precision delta: 0.0000

## Baselines

- Rule baseline on held-out test groups: precision=0.7500, recall=1.0000, F1=0.8571
- Semgrep: not_run
- CodeQL: not_run

## Error Analysis

- PathAnalyzer real-only errors: 3
- PathAnalyzer real + augmented errors: 15
- PathAnalyzer two-stage errors: 6

Detailed endpoint-level predictions, explanations, and confusion matrices are in `final_metrics.json`.

## Limitations

External-tool results are marked `not_run` unless normalized Semgrep/CodeQL findings are provided. Large real apps may still expose extractor false positives that are tracked in error analysis rather than hidden.
