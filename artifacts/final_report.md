# PathAnalyzer Final Real-Corpus Results

Date: 2026-05-14

## Protocol

- Model scope: Model B / PathAnalyzer only.
- Evaluation: leave-one-dataset-split-group-out over `wger`, `nautobot`, and `django-mdeditor`.
- Training variants: real-only vs real + real-derived augmentation.
- Augmentation is train-only; validation and test folds are real advisory-backed samples only.
- External tools: Semgrep `p/django` + `p/python`; CodeQL `codeql/python-queries:codeql-suites/python-security-and-quality.qls`.

## Aggregate Model Results

| System | Accuracy | Macro F1 | Vuln Precision | Vuln Recall | Vuln F1 | Vuln TP | Vuln FP | Vuln FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| PathAnalyzer real-only | 0.987 | 0.166 | 0.000 | 0.000 | 0.000 | 0 | 0 | 6 |
| PathAnalyzer real + augmented | 0.144 | 0.049 | 0.015 | 1.000 | 0.029 | 6 | 403 | 0 |

## Augmentation Delta

- Accuracy delta: -0.843
- Macro F1 delta: -0.117
- Vulnerability precision delta: +0.015
- Vulnerability recall delta: +1.000
- Vulnerability F1 delta: +0.029

## Baseline Results

| System | Precision | Recall | F1 | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule baseline | 0.044 | 1.000 | 0.085 | 6 | 130 | 0 |
| Semgrep normalized | 0.000 | 0.000 | 0.000 | 0 | 0 | 6 |
| CodeQL normalized | 0.000 | 0.000 | 0.000 | 0 | 0 | 6 |

## External Tool Raw Counts

| Tool | App | Raw findings | Normalized endpoint findings |
| --- | --- | ---: | ---: |
| semgrep | django-mdeditor | 0 | 0 |
| semgrep | wger | 22 | 0 |
| semgrep | nautobot | 17 | 0 |
| codeql | django-mdeditor | 7 | 0 |
| codeql | wger | 157 | 0 |
| codeql | nautobot | 298 | 0 |

## Interpretation

- The rule baseline is currently the strongest detector on this small corpus: it found all 6 advisory labels with 130 false positives, mostly from Nautobot over-approximation.
- Real-only PathAnalyzer has high aggregate accuracy because the corpus is dominated by SAFE endpoints, but it has 0 vulnerable-endpoint recall. It is behaving like a conservative SAFE classifier.
- Real + augmented PathAnalyzer found all 6 vulnerable endpoints, but produced 403 vulnerable false positives. Augmentation improved recall but hurt precision, macro F1, and accuracy.
- Semgrep and CodeQL standard rule/query suites produced raw findings, but none normalized to the six endpoint-level privilege-flow labels. For this thesis task, that is a baseline limitation rather than missing data.

## Files

- Machine-readable aggregate: `artifacts/final_metrics.json`
- Per-fold metrics/reports/checkpoints: `artifacts/final/<holdout-group>/`
- Corpus validation: `artifacts/corpus_validation.json`
