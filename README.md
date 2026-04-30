# Privilege Flow Graphs (PFG)

Detecting access-control vulnerabilities (incl. IDOR) in web applications via a purpose-built program representation and Graph Neural Networks.

## Quick start
```powershell
uv sync --all-extras
uv run pytest
uv run pfg --help
```

## Status

Phase 0 / 1 — repo bootstrap, PFG schema, hand-authored corpus, rule baseline.

## Layout

```
src/pfg/                # Python package
benchmarks/             # synthetic + hand-written + real-world apps
schemas/pfg-1.0.json    # frozen PFG JSON Schema
tests/golden/           # PFG snapshot tests
docs/                   # spec, related work, auth-pattern catalog, thesis
experiments/            # YAML configs, MLflow runs
```
