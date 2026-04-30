"""Phase 4 W23: error analysis for eval reports.

Given a `Manifest` and the predictions of a detector on the matching PFG,
classify every false positive and false negative into one of four
categories so the thesis can produce a "where do errors come from?" table:

* ``extraction_error`` — the expected (or predicted) endpoint id does not
  appear in the extracted PFG at all. The extractor is at fault.
* ``intentional_public`` — the endpoint is annotated as intentionally
  public in the manifest (predictions are normally suppressed by the
  harness; this category captures any leakage and any mis-labeled
  expectations).
* ``label_noise`` — the manifest expects a finding on an endpoint that
  the rule baseline does not flag *and* that has neither identifier-flow
  nor a missing auth/role attribute consistent with the expected
  subtype. Suggests the manifest may be wrong.
* ``model_error`` — default bucket: PFG is fine, manifest is plausible,
  the detector simply missed (or hallucinated) the finding.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from pfg.detectors.rule_baseline import detect_all
from pfg.eval.harness import AppScore, evaluate_app
from pfg.eval.manifest import Manifest
from pfg.extractors.django.build import build_pfg
from pfg.pfg.graph import PFG

ErrorCategory = str  # "extraction_error" | "intentional_public" | "label_noise" | "model_error"

_VULN_SUBTYPES = {"MISSING_AUTH", "MISSING_ROLE", "IDOR", "COMBINED"}


@dataclass(frozen=True)
class ErrorRecord:
    """One classified false-positive or false-negative."""

    kind: str  # "fp" | "fn"
    endpoint_id: str
    subtype: str
    category: ErrorCategory
    rationale: str


@dataclass
class AppErrorAnalysis:
    application: str
    tp: int
    fp: int
    fn: int
    errors: list[ErrorRecord] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)


@dataclass
class ErrorAnalysisReport:
    detector_name: str
    apps: list[AppErrorAnalysis] = field(default_factory=list)
    totals: dict[str, int] = field(default_factory=dict)


# --- helpers --------------------------------------------------------------


def _endpoint_index(pfg: PFG) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for n in pfg.nodes:
        ntype = getattr(n.type, "value", n.type)
        if ntype == "endpoint":
            out[n.id] = n
    return out


def _has_idflow_to(pfg: PFG, endpoint_id: str) -> bool:
    for e in pfg.edges:
        etype = getattr(e.type, "value", e.type)
        if etype == "identifier_flow" and e.src == endpoint_id:
            return True
    return False


def _attrs(node: Any) -> dict[str, Any]:
    a = getattr(node, "attrs", None)
    if a is None:
        return {}
    if hasattr(a, "model_dump"):
        return dict(a.model_dump())
    if isinstance(a, dict):
        return dict(a)
    return {}


def _label_consistent_with_pfg(pfg: PFG, endpoint_id: str, subtype: str) -> bool:
    """Heuristic: does the PFG carry signal compatible with this expected subtype?

    Returns True if at least one piece of evidence supports the label, False
    if the PFG looks "safe" (used for the label_noise bucket).
    """
    eps = _endpoint_index(pfg)
    node = eps.get(endpoint_id)
    if node is None:
        # Caller should have classified extraction_error already; be safe.
        return True
    attrs = _attrs(node)
    requires_auth = bool(attrs.get("requires_auth", True))
    required_role = str(attrs.get("required_role", "NONE"))
    has_owner = bool(attrs.get("ownership_check_present", False))

    if subtype == "MISSING_AUTH":
        return not requires_auth
    if subtype == "MISSING_ROLE":
        return required_role in {"NONE", ""} or not requires_auth
    if subtype == "IDOR":
        return _has_idflow_to(pfg, endpoint_id) and not has_owner
    if subtype == "COMBINED":
        return (not requires_auth) or _has_idflow_to(pfg, endpoint_id)
    return True


# --- classification -------------------------------------------------------


def _classify_fn(
    pfg: PFG,
    endpoint_id: str,
    subtype: str,
    *,
    intentional: set[str],
    rule_preds: set[tuple[str, str]],
) -> tuple[ErrorCategory, str]:
    eps = _endpoint_index(pfg)
    if endpoint_id not in eps:
        return "extraction_error", f"endpoint id {endpoint_id!r} not in extracted PFG"
    if endpoint_id in intentional:
        return (
            "intentional_public",
            "endpoint is annotated intentional_public — likely manifest mistake",
        )
    if (endpoint_id, subtype) in rule_preds:
        return (
            "model_error",
            "rule baseline flagged it; ML detector missed",
        )
    if not _label_consistent_with_pfg(pfg, endpoint_id, subtype):
        return (
            "label_noise",
            f"PFG attributes inconsistent with expected subtype {subtype}",
        )
    return "model_error", "PFG plausible but detector did not flag"


def _classify_fp(
    pfg: PFG,
    endpoint_id: str,
    subtype: str,
    *,
    intentional: set[str],
) -> tuple[ErrorCategory, str]:
    eps = _endpoint_index(pfg)
    if endpoint_id not in eps:
        return (
            "extraction_error",
            f"predicted endpoint id {endpoint_id!r} not in extracted PFG",
        )
    if endpoint_id in intentional:
        return (
            "intentional_public",
            "predicted on intentional_public endpoint",
        )
    return "model_error", f"detector emitted {subtype} but no expected finding"


def _matched_pairs(score: AppScore) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    """Reconstruct (matched_predictions, matched_expected) from an AppScore.

    Mirrors the COMBINED-flexible matching used in `harness._score_one`.
    """
    predicted = {(p["endpoint_id"], p["subtype"]) for p in score.predictions}
    expected = {(e["endpoint_id"], e["subtype"]) for e in score.expected}

    matched_pred: set[tuple[str, str]] = set()
    matched_exp: set[tuple[str, str]] = set()

    for p in predicted:
        if p in expected:
            matched_pred.add(p)
            matched_exp.add(p)

    def _combined_match(a: tuple[str, str], b: tuple[str, str]) -> bool:
        if a[0] != b[0]:
            return False
        return "COMBINED" in {a[1], b[1]} and {a[1], b[1]} <= {
            "COMBINED",
            "MISSING_AUTH",
            "MISSING_ROLE",
            "IDOR",
        }

    for p in predicted - matched_pred:
        for e in expected - matched_exp:
            if _combined_match(p, e):
                matched_pred.add(p)
                matched_exp.add(e)
                break

    return matched_pred, matched_exp


# --- public API -----------------------------------------------------------


def analyze_app(
    manifest: Manifest,
    pfg: PFG,
    score: AppScore,
) -> AppErrorAnalysis:
    """Classify every FP/FN in `score` against `manifest` + extracted `pfg`."""
    intentional = set(manifest.intentional_public_endpoints)
    predicted = {(p["endpoint_id"], p["subtype"]) for p in score.predictions}
    expected = {(e["endpoint_id"], e["subtype"]) for e in score.expected}
    matched_pred, matched_exp = _matched_pairs(score)
    rule_preds = {(f.endpoint_id, f.subtype.value) for f in detect_all(pfg)}

    errors: list[ErrorRecord] = []
    for ep_id, sub in sorted(expected - matched_exp):
        cat, why = _classify_fn(
            pfg, ep_id, sub, intentional=intentional, rule_preds=rule_preds
        )
        errors.append(ErrorRecord("fn", ep_id, sub, cat, why))
    for ep_id, sub in sorted(predicted - matched_pred):
        cat, why = _classify_fp(pfg, ep_id, sub, intentional=intentional)
        errors.append(ErrorRecord("fp", ep_id, sub, cat, why))

    counts: dict[str, int] = {}
    for r in errors:
        key = f"{r.kind}.{r.category}"
        counts[key] = counts.get(key, 0) + 1

    return AppErrorAnalysis(
        application=manifest.application,
        tp=score.tp,
        fp=score.fp,
        fn=score.fn,
        errors=errors,
        counts=counts,
    )


def analyze_corpus(
    manifests: Iterable[Manifest],
    detector: Any,
    *,
    detector_name: str = "rule_baseline",
) -> ErrorAnalysisReport:
    """Run the detector on each manifest and produce a classified error report."""
    apps: list[AppErrorAnalysis] = []
    totals: dict[str, int] = {}
    for m in manifests:
        pfg = build_pfg(m.project_root, application=m.application)

        def _builder(_root: Path, _p: PFG = pfg) -> PFG:
            return _p

        score = evaluate_app(m, detector, build=_builder)
        analysis = analyze_app(m, pfg, score)
        apps.append(analysis)
        for k, v in analysis.counts.items():
            totals[k] = totals.get(k, 0) + v
    return ErrorAnalysisReport(detector_name=detector_name, apps=apps, totals=totals)


def report_to_dict(report: ErrorAnalysisReport) -> dict[str, Any]:
    return {
        "detector": report.detector_name,
        "totals": report.totals,
        "apps": [asdict(a) for a in report.apps],
    }


def write_report(report: ErrorAnalysisReport, out_path: Path) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report_to_dict(report), indent=2), encoding="utf-8")
    return out_path
