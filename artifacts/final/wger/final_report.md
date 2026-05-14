# PathAnalyzer Final Real-Corpus Report

## Methodology

This report evaluates Model B / PathAnalyzer only. Augmented samples are derived from real extracted PFGs and are used only in training; validation and test are real-only.

## Dataset Split

- Train groups: nautobot
- Validation groups: django-mdeditor
- Test groups: wger
- Real train samples: 183
- Augmented train samples: 21
- Real validation samples: 5
- Real test samples: 283

## Model Comparison

| System | Accuracy | Macro F1 | Vuln Precision | Vuln Recall | Vuln F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| PathAnalyzer real-only | 0.9894 | 0.1658 | 0.0000 | 0.0000 | 0.0000 |
| PathAnalyzer real + augmented | 0.2297 | 0.0661 | 0.0136 | 1.0000 | 0.0268 |

## Augmentation Delta

- Macro F1 delta: -0.0996
- Accuracy delta: -0.7597
- Vulnerability recall delta: 1.0000
- Vulnerability precision delta: 0.0136

## Baselines

- Rule baseline on held-out test groups: precision=0.7500, recall=1.0000, F1=0.8571
- Semgrep: provided
- CodeQL: provided

## Error Analysis

- PathAnalyzer real-only errors: 3
- PathAnalyzer real + augmented errors: 218

Detailed endpoint-level predictions, explanations, and confusion matrices are in `final_metrics.json`.

## Limitations

External-tool results are marked `not_run` unless normalized Semgrep/CodeQL findings are provided. Large real apps may still expose extractor false positives that are tracked in error analysis rather than hidden.
