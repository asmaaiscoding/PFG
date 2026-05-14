# PathAnalyzer Final Real-Corpus Report

## Methodology

This report evaluates Model B / PathAnalyzer only. Augmented samples are derived from real extracted PFGs and are used only in training; validation and test are real-only.

## Dataset Split

- Train groups: wger
- Validation groups: django-mdeditor
- Test groups: nautobot
- Real train samples: 283
- Augmented train samples: 17
- Real validation samples: 5
- Real test samples: 183

## Model Comparison

| System | Accuracy | Macro F1 | Vuln Precision | Vuln Recall | Vuln F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| PathAnalyzer real-only | 0.9891 | 0.1658 | 0.0000 | 0.0000 | 0.0000 |
| PathAnalyzer real + augmented | 0.0109 | 0.0042 | 0.0109 | 1.0000 | 0.0216 |

## Augmentation Delta

- Macro F1 delta: -0.1616
- Accuracy delta: -0.9781
- Vulnerability recall delta: 1.0000
- Vulnerability precision delta: 0.0109

## Baselines

- Rule baseline on held-out test groups: precision=0.0153, recall=1.0000, F1=0.0301
- Semgrep: provided
- CodeQL: provided

## Error Analysis

- PathAnalyzer real-only errors: 2
- PathAnalyzer real + augmented errors: 181

Detailed endpoint-level predictions, explanations, and confusion matrices are in `final_metrics.json`.

## Limitations

External-tool results are marked `not_run` unless normalized Semgrep/CodeQL findings are provided. Large real apps may still expose extractor false positives that are tracked in error analysis rather than hidden.
