# PFG 8-Class Final Tables

Generated from the expanded advisory-backed corpus artifacts. Semgrep/CodeQL rows are marked `not_run` because no normalized endpoint-level findings file was provided for the expanded corpus run.

## Corpus

| App | CVE/GHSA | Subtype(s) | CWE | Expected endpoints | Vulnerable ref | Fixed ref |
| --- | --- | --- | --- | ---: | --- | --- |
| django-mdeditor-cve-2025-13030 | CVE-2025-13030, GHSA-qp2c-xqv6-phh6 | MISSING_AUTH | CWE-306 | 1 | `e8dd73fb8571` | `3e80f9edcabc` |
| nautobot-cve-2023-50263 | CVE-2023-50263, GHSA-75mc-3pjc-727q | MISSING_AUTH | CWE-200 | 2 | `b639fca03854` | `458280c359a4` |
| nautobot-cve-2023-51649 | CVE-2023-51649, GHSA-vf5m-xrhm-v999 | OBJECT_LEVEL_PERMISSION_BYPASS | CWE-863 | 1 | `4b9ff9be205d` | `3d964f996f49` |
| pretix-cve-2025-14881 | CVE-2025-14881, GHSA-r2h2-g46h-8mx8 | IDOR | CWE-639 | 1 | `703be2ebb82c` | `4b5651862c57` |
| sentry-cve-2026-26004 | CVE-2026-26004, GHSL-2025-130 | TENANT_ISOLATION_FAILURE | CWE-639 | 1 | `7eddaa942f08` | `45bc78fd5751` |
| weblate-cve-2026-27457 | CVE-2026-27457, GHSA-wppc-7cq7-cgfv | OBJECT_LEVEL_PERMISSION_BYPASS, TENANT_ISOLATION_FAILURE | CWE-862 | 2 | `b49b70bea874` | `3f58f9a4152b` |
| wger-cve-2026-27839 | CVE-2026-27839, GHSA-g8gc-6c4h-jg86 | IDOR | CWE-639 | 3 | `9c162dc82813` | `29876a1954fe` |
| wger-cve-2026-40474 | CVE-2026-40474, GHSA-xppv-4jrx-qf8m | MISSING_ROLE | CWE-284, CWE-862 | 1 | `a742dc7b8a67` | `47ee5af93b3c` |

## Main Results (Leave-One-Group-Out, Expanded Corpus)

| System | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Semgrep | n/a | n/a | n/a | n/a | n/a | not_run |
| CodeQL | n/a | n/a | n/a | n/a | n/a | not_run |
| PFG rules | 8 | 81 | 4 | 0.090 | 0.667 | 0.158 |
| Raw GNN (synthetic-only) | 9 | 3916 | 3 | 0.002 | 0.750 | 0.005 |
| Synthetic GNN + validation | 6 | 32 | 6 | 0.158 | 0.500 | 0.240 |
| Fine-tuned GNN | 4 | 1030 | 8 | 0.004 | 0.333 | 0.008 |
| Fine-tuned GNN + validation | 3 | 34 | 9 | 0.081 | 0.250 | 0.122 |

## Final Split Models (Sentry Holdout)

Train groups: django-mdeditor, nautobot, pretix, weblate; validation groups: wger; test groups: sentry.

| Weak supervision | Model | Accuracy | Macro F1 | Vuln TP | Vuln FP | Vuln FN | Vuln P | Vuln R | Vuln F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| on | real-only | 0.996 | 0.125 | 0 | 0 | 1 | 0.000 | 0.000 | 0.000 |
| on | real+augmented | 0.007 | 0.002 | 1 | 270 | 0 | 0.004 | 1.000 | 0.007 |
| on | two-stage | 0.103 | 0.023 | 1 | 244 | 0 | 0.004 | 1.000 | 0.008 |
| off | real-only | 0.996 | 0.125 | 0 | 0 | 1 | 0.000 | 0.000 | 0.000 |
| off | real+augmented | 0.029 | 0.007 | 1 | 264 | 0 | 0.004 | 1.000 | 0.008 |
| off | two-stage | 0.062 | 0.015 | 1 | 255 | 0 | 0.004 | 1.000 | 0.008 |

## Ablations

| Ablation | Condition | TP | FP | FN | Precision | Recall | F1 | Notes |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Raw vs validated | raw synthetic-only GNN | 9 | 3916 | 3 | 0.002 | 0.750 | 0.005 | expanded corpus |
| Raw vs validated | same model with PFG structural validation | 6 | 32 | 6 | 0.158 | 0.500 | 0.240 | expanded corpus |
| Raw vs validated | raw fine-tuned GNN | 4 | 1030 | 8 | 0.004 | 0.333 | 0.008 | expanded corpus |
| Raw vs validated | same fine-tuned model with PFG structural validation | 3 | 34 | 9 | 0.081 | 0.250 | 0.122 | expanded corpus |
| Fine-tuning vs synthetic-only | synthetic-only validated | 6 | 32 | 6 | 0.158 | 0.500 | 0.240 | expanded corpus |
| Fine-tuning vs synthetic-only | fine-tuned validated | 3 | 34 | 9 | 0.081 | 0.250 | 0.122 | expanded corpus |
| Weak supervision | weak on: real_augmented | 1 | 270 | 0 | 0.004 | 1.000 | 0.007 | final Sentry holdout |
| Weak supervision | weak on: twostage | 1 | 244 | 0 | 0.004 | 1.000 | 0.008 | final Sentry holdout |
| Weak supervision | weak off: real_augmented | 1 | 264 | 0 | 0.004 | 1.000 | 0.008 | final Sentry holdout |
| Weak supervision | weak off: twostage | 1 | 255 | 0 | 0.004 | 1.000 | 0.008 | final Sentry holdout |
| Synthetic data alignment | historical synth-v1 | n/a | n/a | n/a | 0.007 | 0.500 | 0.014 | artifact scopes differ; do not compare as final claim |
| Synthetic data alignment | historical synth-v2 | n/a | n/a | n/a | 0.037 | 0.667 | 0.071 | artifact scopes differ; do not compare as final claim |
| Synthetic data alignment | historical synth-v6 | n/a | n/a | n/a | 0.014 | 1.000 | 0.028 | artifact scopes differ; do not compare as final claim |
| Synthetic data alignment | current expanded synthetic | n/a | n/a | n/a | 0.002 | 0.750 | 0.005 | artifact scopes differ; do not compare as final claim |

## Per-Subtype Metrics (Expanded Corpus)

| System | Subtype | Support | TP | FP | FN | Precision | Recall | F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| PFG rules | MISSING_AUTH | 3 | 3 | 24 | 0 | 0.111 | 1.000 | 0.200 |
| PFG rules | MISSING_ROLE | 1 | 0 | 0 | 1 | 0.000 | 0.000 | 0.000 |
| PFG rules | IDOR | 4 | 3 | 19 | 1 | 0.136 | 0.750 | 0.231 |
| PFG rules | TENANT_ISOLATION_FAILURE | 2 | 1 | 8 | 1 | 0.111 | 0.500 | 0.182 |
| PFG rules | OBJECT_LEVEL_PERMISSION_BYPASS | 2 | 1 | 30 | 1 | 0.032 | 0.500 | 0.061 |
| PFG rules | COMBINED | 0 | 0 | 0 | 0 | 0.000 | 0.000 | 0.000 |
| Synthetic+validated | MISSING_AUTH | 3 | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Synthetic+validated | MISSING_ROLE | 1 | 0 | 0 | 1 | 0.000 | 0.000 | 0.000 |
| Synthetic+validated | IDOR | 4 | 3 | 16 | 1 | 0.158 | 0.750 | 0.261 |
| Synthetic+validated | TENANT_ISOLATION_FAILURE | 2 | 0 | 0 | 2 | 0.000 | 0.000 | 0.000 |
| Synthetic+validated | OBJECT_LEVEL_PERMISSION_BYPASS | 2 | 0 | 0 | 2 | 0.000 | 0.000 | 0.000 |
| Synthetic+validated | COMBINED | 0 | 0 | 16 | 0 | 0.000 | 0.000 | 0.000 |
| Fine-tuned+validated | MISSING_AUTH | 3 | 0 | 13 | 3 | 0.000 | 0.000 | 0.000 |
| Fine-tuned+validated | MISSING_ROLE | 1 | 0 | 0 | 1 | 0.000 | 0.000 | 0.000 |
| Fine-tuned+validated | IDOR | 4 | 3 | 15 | 1 | 0.167 | 0.750 | 0.273 |
| Fine-tuned+validated | TENANT_ISOLATION_FAILURE | 2 | 0 | 1 | 2 | 0.000 | 0.000 | 0.000 |
| Fine-tuned+validated | OBJECT_LEVEL_PERMISSION_BYPASS | 2 | 0 | 0 | 2 | 0.000 | 0.000 | 0.000 |
| Fine-tuned+validated | COMBINED | 0 | 0 | 5 | 0 | 0.000 | 0.000 | 0.000 |

## Per-App TP/FP/FN (Expanded Corpus)

| System | App | TP | FP | FN |
| --- | --- | ---: | ---: | ---: |
| PFG rules | django-mdeditor-cve-2025-13030 | 1 | 0 | 0 |
| PFG rules | nautobot-cve-2023-50263 | 2 | 8 | 0 |
| PFG rules | nautobot-cve-2023-51649 | 1 | 7 | 0 |
| PFG rules | pretix-cve-2025-14881 | 0 | 5 | 1 |
| PFG rules | sentry-cve-2026-26004 | 1 | 36 | 0 |
| PFG rules | weblate-cve-2026-27457 | 0 | 6 | 2 |
| PFG rules | wger-cve-2026-27839 | 3 | 17 | 0 |
| PFG rules | wger-cve-2026-40474 | 0 | 2 | 1 |
| Synthetic+validated | django-mdeditor-cve-2025-13030 | 1 | 0 | 0 |
| Synthetic+validated | nautobot-cve-2023-50263 | 2 | 0 | 0 |
| Synthetic+validated | nautobot-cve-2023-51649 | 0 | 0 | 1 |
| Synthetic+validated | pretix-cve-2025-14881 | 0 | 0 | 1 |
| Synthetic+validated | sentry-cve-2026-26004 | 0 | 21 | 1 |
| Synthetic+validated | weblate-cve-2026-27457 | 0 | 3 | 2 |
| Synthetic+validated | wger-cve-2026-27839 | 3 | 4 | 0 |
| Synthetic+validated | wger-cve-2026-40474 | 0 | 4 | 1 |
| Fine-tuned+validated | django-mdeditor-cve-2025-13030 | 0 | 0 | 1 |
| Fine-tuned+validated | nautobot-cve-2023-50263 | 0 | 0 | 2 |
| Fine-tuned+validated | nautobot-cve-2023-51649 | 0 | 0 | 1 |
| Fine-tuned+validated | pretix-cve-2025-14881 | 0 | 0 | 1 |
| Fine-tuned+validated | sentry-cve-2026-26004 | 0 | 19 | 1 |
| Fine-tuned+validated | weblate-cve-2026-27457 | 0 | 4 | 2 |
| Fine-tuned+validated | wger-cve-2026-27839 | 3 | 7 | 0 |
| Fine-tuned+validated | wger-cve-2026-40474 | 0 | 4 | 1 |

## FP/FN Error Analysis Summary

| System | FP count by subtype | FN expected endpoints |
| --- | --- | --- |
| PFG rules | IDOR=19, MISSING_AUTH=24, OBJECT_LEVEL_PERMISSION_BYPASS=30, TENANT_ISOLATION_FAILURE=8 | pretix-cve-2025-14881:endpoint__GET___download__id__ (IDOR)<br>weblate-cve-2026-27457:endpoint__GET___api_addons_ (TENANT_ISOLATION_FAILURE)<br>weblate-cve-2026-27457:endpoint__GET___api_addons__pk__ (OBJECT_LEVEL_PERMISSION_BYPASS)<br>wger-cve-2026-40474:endpoint__POST___config_gym_config_edit (MISSING_ROLE) |
| Synthetic+validated | COMBINED=16, IDOR=16 | nautobot-cve-2023-51649:endpoint__POST___extras_job_button__pk__run_ (OBJECT_LEVEL_PERMISSION_BYPASS)<br>pretix-cve-2025-14881:endpoint__GET___download__id__ (IDOR)<br>sentry-cve-2026-26004:endpoint__GET____organization_slug__issues__group_id__events__event_id_or_latest__json_ (TENANT_ISOLATION_FAILURE)<br>weblate-cve-2026-27457:endpoint__GET___api_addons_ (TENANT_ISOLATION_FAILURE)<br>weblate-cve-2026-27457:endpoint__GET___api_addons__pk__ (OBJECT_LEVEL_PERMISSION_BYPASS)<br>wger-cve-2026-40474:endpoint__POST___config_gym_config_edit (MISSING_ROLE) |
| Fine-tuned+validated | COMBINED=5, IDOR=15, MISSING_AUTH=13, TENANT_ISOLATION_FAILURE=1 | django-mdeditor-cve-2025-13030:endpoint__POST___mdeditor_uploads_ (MISSING_AUTH)<br>nautobot-cve-2023-50263:endpoint__GET___files_get_ (MISSING_AUTH)<br>nautobot-cve-2023-50263:endpoint__GET___files_download_ (MISSING_AUTH)<br>nautobot-cve-2023-51649:endpoint__POST___extras_job_button__pk__run_ (OBJECT_LEVEL_PERMISSION_BYPASS)<br>pretix-cve-2025-14881:endpoint__GET___download__id__ (IDOR)<br>sentry-cve-2026-26004:endpoint__GET____organization_slug__issues__group_id__events__event_id_or_latest__json_ (TENANT_ISOLATION_FAILURE)<br>weblate-cve-2026-27457:endpoint__GET___api_addons_ (TENANT_ISOLATION_FAILURE)<br>weblate-cve-2026-27457:endpoint__GET___api_addons__pk__ (OBJECT_LEVEL_PERMISSION_BYPASS)<br>wger-cve-2026-40474:endpoint__POST___config_gym_config_edit (MISSING_ROLE) |

## Notes

- The expanded corpus validation status is OK and contains 8 manifests / 4,232 endpoints / 12 advisory-backed expected findings.
- No synthetic or pseudo-label data is present in validation/test labels; weak supervision is generated only from training manifests in the final split.
- Semgrep and CodeQL were not rerun with normalized endpoint-level findings for the expanded corpus in these commands.
- Historical synthetic alignment rows are retained as provenance only; use the expanded-corpus rows above for final claims.
