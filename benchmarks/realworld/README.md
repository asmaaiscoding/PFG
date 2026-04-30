# Real-world evaluation corpus (Phase 4 W18)

This directory holds per-application ground truth used by `pfg eval`.

## Layout

```
benchmarks/realworld/
  README.md                       <- this file
  <app-slug>/
    manifest.yaml                 <- ground truth + provenance
    src/                          <- the actual Django source code
                                     (or a symlink / submodule)
```

`pfg eval benchmarks/realworld --detector rule` will discover every
`manifest.yaml` recursively, build a PFG for each `source_root`, run the
chosen detector, and score predictions against `expected_findings`.

## Required minimum (per Implementation Plan v2, Phase 4 W18)

- 3 reproducible Django CVE apps (CWE-862 or CWE-639, locally buildable)
- 3 GitHub Django apps with >=20 endpoints

A starter manifest is provided at `_template/manifest.yaml`. Copy it,
rename the directory, drop the source code into `src/`, and fill in
the expected findings.
