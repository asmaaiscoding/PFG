"""Phase 4 W21: external-tool adapters (Semgrep / CodeQL).

These adapters normalize findings from third-party static analysers into the
`[{"endpoint_id": ..., "subtype": ...}]` JSON format consumed by
`pfg eval --detector external`.

Why JSON-in-JSON-out instead of shelling out to the tools?

  * Tool installation (CodeQL CLI in particular) is ~3 GB and not appropriate
    to take as a hard dependency in this repo.
  * The thesis evaluation needs to be reproducible from artifacts, not from
    re-running closed-source toolchains.
  * The user produces tool output once (per Phase 4 W21 protocol) and the
    adapter normalizes it deterministically.

Each adapter takes:
  * the path to the tool's JSON output, and
  * a `PFG` (used to resolve file:line locations -> endpoint_id).

The mapping from tool rule-id -> PFG subtype is configurable so future
rule packs can be added without touching the harness.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from pfg.pfg.graph import PFG
from pfg.pfg.nodes import EndpointAttrs, NodeType

# --- subtype mappings -----------------------------------------------------


_DEFAULT_SEMGREP_RULE_TO_SUBTYPE: Mapping[str, str] = {
    # Community / contrib rules — adjust to whatever the user actually runs.
    "python.django.security.audit.unvalidated-objects-pk": "IDOR",
    "python.django.security.audit.missing-authentication": "MISSING_AUTH",
    "python.django.security.audit.missing-permission-class": "MISSING_ROLE",
    "python.django.security.audit.broken-object-level-authorization": "IDOR",
    # Generic CWE-based fall-throughs.
    "cwe-639": "IDOR",
    "cwe-862": "MISSING_AUTH",
    "cwe-863": "MISSING_ROLE",
}

_DEFAULT_CODEQL_RULE_TO_SUBTYPE: Mapping[str, str] = {
    # CodeQL Python security pack identifiers.
    "py/missing-authentication": "MISSING_AUTH",
    "py/missing-authorization": "MISSING_ROLE",
    "py/idor": "IDOR",
    "py/insecure-direct-object-reference": "IDOR",
    "py/cwe-639": "IDOR",
    "py/cwe-862": "MISSING_AUTH",
    "py/cwe-863": "MISSING_ROLE",
}


# --- file:line -> endpoint_id resolution ---------------------------------


def _endpoint_locations(pfg: PFG) -> list[tuple[str, int, str]]:
    """Return [(file_path, lineno, endpoint_id), ...] sorted by (file, line).

    Only endpoint nodes with parseable `source_location` strings (`file:line`)
    contribute. Endpoints without source locations are excluded — adapters
    cannot hit them. This is by design: the audit cares about reachable
    endpoints only.
    """
    out: list[tuple[str, int, str]] = []
    for node in pfg.nodes:
        if node.type != NodeType.ENDPOINT.value:
            continue
        attrs = node.attrs
        if not isinstance(attrs, EndpointAttrs):
            continue
        loc = attrs.source_location
        if not loc:
            continue
        # Format produced by the Django extractor: 'relative/path.py:LINE'.
        if ":" not in loc:
            continue
        file_str, _, line_str = loc.rpartition(":")
        try:
            lineno = int(line_str)
        except ValueError:
            continue
        if lineno <= 0:
            continue
        out.append((str(Path(file_str).as_posix()), lineno, node.id))
    out.sort()
    return out


def _resolve_endpoint(
    locations: list[tuple[str, int, str]], file_path: str, lineno: int, *, window: int = 50
) -> str | None:
    """Map a file:line finding to the nearest enclosing endpoint id.

    Uses the *closest endpoint above or within `window` lines below* the
    reported location, on the same file (matched by suffix to be path-prefix
    agnostic). Returns None if no endpoint qualifies.
    """
    needle = Path(file_path).as_posix()
    best: tuple[int, str] | None = None  # (distance_score, endpoint_id)
    for fp, ep_line, ep_id in locations:
        if not (needle.endswith(fp) or fp.endswith(needle)):
            continue
        if ep_line <= lineno:
            dist = lineno - ep_line
        elif ep_line - lineno <= window:
            dist = (ep_line - lineno) + window  # prefer above-finding endpoints
        else:
            continue
        if best is None or dist < best[0]:
            best = (dist, ep_id)
    return best[1] if best else None


# --- normalization --------------------------------------------------------


Normalizer = Callable[[Path, PFG], list[dict[str, str]]]


def _to_subtype(rule_id: str, mapping: Mapping[str, str]) -> str | None:
    if rule_id in mapping:
        return mapping[rule_id]
    rid = rule_id.lower()
    for k, v in mapping.items():
        if k.lower() in rid or rid in k.lower():
            return v
    return None


def normalize_semgrep(
    findings_path: str | Path,
    pfg: PFG,
    *,
    rule_mapping: Mapping[str, str] | None = None,
) -> list[dict[str, str]]:
    """Convert Semgrep `--json` output to `[{endpoint_id, subtype}, ...]`.

    Semgrep schema (relevant fields):
      results: [
        {check_id: 'python.django...', path: 'apps/orders/views.py',
         start: {line: 42, col: ...}, ...},
      ]
    """
    mapping = rule_mapping or _DEFAULT_SEMGREP_RULE_TO_SUBTYPE
    raw: dict[str, Any] = json.loads(Path(findings_path).read_text(encoding="utf-8"))
    locations = _endpoint_locations(pfg)
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for r in raw.get("results", []):
        sub = _to_subtype(r.get("check_id", ""), mapping)
        if sub is None:
            continue
        path = r.get("path", "")
        line = (r.get("start") or {}).get("line", 0)
        ep = _resolve_endpoint(locations, path, int(line))
        if ep is None:
            continue
        key = (ep, sub)
        if key in seen:
            continue
        seen.add(key)
        out.append({"endpoint_id": ep, "subtype": sub})
    return out


def normalize_codeql(
    findings_path: str | Path,
    pfg: PFG,
    *,
    rule_mapping: Mapping[str, str] | None = None,
) -> list[dict[str, str]]:
    """Convert CodeQL SARIF (`codeql database analyze --format=sarifv2.1.0`).

    SARIF schema (relevant fields):
      runs: [{ results: [{
          ruleId: 'py/missing-authorization',
          locations: [{physicalLocation: {
              artifactLocation: {uri: 'apps/orders/views.py'},
              region: {startLine: 42}}}],
      }]}]
    """
    mapping = rule_mapping or _DEFAULT_CODEQL_RULE_TO_SUBTYPE
    raw: dict[str, Any] = json.loads(Path(findings_path).read_text(encoding="utf-8"))
    locations = _endpoint_locations(pfg)
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for run in raw.get("runs", []):
        for r in run.get("results", []):
            sub = _to_subtype(r.get("ruleId", ""), mapping)
            if sub is None:
                continue
            for loc in r.get("locations", []) or []:
                phys = loc.get("physicalLocation") or {}
                artifact = phys.get("artifactLocation") or {}
                region = phys.get("region") or {}
                path = artifact.get("uri", "")
                line = region.get("startLine", 0)
                ep = _resolve_endpoint(locations, path, int(line))
                if ep is None:
                    continue
                key = (ep, sub)
                if key in seen:
                    continue
                seen.add(key)
                out.append({"endpoint_id": ep, "subtype": sub})
                break
    return out


def write_normalized(records: list[dict[str, str]], out_path: str | Path) -> Path:
    """Persist normalized findings as JSON. Returns the resolved output path."""
    p = Path(out_path).resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(records, indent=2), encoding="utf-8")
    return p


__all__ = [
    "Normalizer",
    "normalize_codeql",
    "normalize_semgrep",
    "write_normalized",
]
