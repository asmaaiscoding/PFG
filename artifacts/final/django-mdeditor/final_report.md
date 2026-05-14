# PathAnalyzer Final Real-Corpus Report

## Methodology

This report evaluates Model B / PathAnalyzer only. Augmented samples are derived from real extracted PFGs and are used only in training; validation and test are real-only.

## Dataset Split

- Train groups: wger
- Validation groups: nautobot
- Test groups: django-mdeditor
- Real train samples: 283
- Augmented train samples: 17
- Real validation samples: 183
- Real test samples: 5

## Model Comparison

| System | Accuracy | Macro F1 | Vuln Precision | Vuln Recall | Vuln F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| PathAnalyzer real-only | 0.8000 | 0.1481 | 0.0000 | 0.0000 | 0.0000 |
| PathAnalyzer real + augmented | 0.2000 | 0.0556 | 0.2000 | 1.0000 | 0.3333 |

## Augmentation Delta

- Macro F1 delta: -0.0926
- Accuracy delta: -0.6000
- Vulnerability recall delta: 1.0000
- Vulnerability precision delta: 0.2000

## Baselines

- Rule baseline on held-out test groups: precision=1.0000, recall=1.0000, F1=1.0000
- Semgrep: provided
- CodeQL: provided

## Error Analysis

- PathAnalyzer real-only errors: 1
- PathAnalyzer real + augmented errors: 4

Detailed endpoint-level predictions, explanations, and confusion matrices are in `final_metrics.json`.

## Limitations

External-tool results are marked `not_run` unless normalized Semgrep/CodeQL findings are provided. Large real apps may still expose extractor false positives that are tracked in error analysis rather than hidden.
