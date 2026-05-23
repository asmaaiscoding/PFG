# PathAnalyzer Final Real-Corpus Report (v2)

## Methodology

This report evaluates Model B / PathAnalyzer with three training strategies:
1. **Real-only** — baseline trained on real extracted PFGs only.
2. **Real + Augmented** — real PFGs plus capped real-derived augmentations with focal loss.
3. **Two-stage** — contrastive synthetic pre-training then fine-tuning on real+augmented.

Validation and test are always real-only.

## Dataset Split

- Train groups: django-mdeditor, nautobot, pretix, weblate
- Validation groups: wger
- Test groups: sentry
- Real train samples: 2871
- Augmented train samples: 40
- Weak-supervision train samples: 0
- Synthetic contrastive samples: 360
- Real validation samples: 1088
- Real test samples: 273

## Model Comparison

| System | Accuracy | Macro F1 | Vuln Precision | Vuln Recall | Vuln F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| PathAnalyzer real-only | 0.9963 | 0.1248 | 0.0000 | 0.0000 | 0.0000 |
| PathAnalyzer real + augmented | 0.0293 | 0.0071 | 0.0038 | 1.0000 | 0.0075 |
| PathAnalyzer two-stage | 0.0623 | 0.0147 | 0.0039 | 1.0000 | 0.0078 |

## Augmentation Delta (vs real-only)

- Macro F1 delta: -0.1176
- Accuracy delta: -0.9670
- Vulnerability recall delta: 1.0000
- Vulnerability precision delta: 0.0038

## Two-Stage Delta (vs real-only)

- Macro F1 delta: -0.1101
- Accuracy delta: -0.9341
- Vulnerability recall delta: 1.0000
- Vulnerability precision delta: 0.0039

## Baselines

- Rule baseline on held-out test groups: precision=0.0270, recall=1.0000, F1=0.0526
- Semgrep: not_run
- CodeQL: not_run

## Error Analysis

- PathAnalyzer real-only errors: 1
- PathAnalyzer real + augmented errors: 265
- PathAnalyzer two-stage errors: 256

Detailed endpoint-level predictions, explanations, and confusion matrices are in `final_metrics.json`.

## Limitations

External-tool results are marked `not_run` unless normalized Semgrep/CodeQL findings are provided. Large real apps may still expose extractor false positives that are tracked in error analysis rather than hidden.
