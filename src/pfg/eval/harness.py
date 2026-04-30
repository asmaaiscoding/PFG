"""Phase 4 W19-W21: per-app evaluation harness.

Given a list of `Manifest` objects and a detector callable that maps a PFG to
a set of `(endpoint_id, subtype)` predictions, computes per-app and aggregate
precision / recall / F1 against the manifest ground truth.

Detectors provided:
  * `rule_detector`: thin wrapper over `pfg.detectors.rule_baseline.detect_all`
  * `gnn_detector(model)`: wraps a trained `PfgAnomalyDetector` or `PathAnalyzer`
  * `external_findings_detector(path)`: ingests a JSON file of pre-computed
                                         findings (Semgrep / CodeQL adapter).

External-tool integration is intentionally JSON-based: we do not shell out to
Semgrep or CodeQL from this harness — we read whatever JSON the user has
already produced via their own toolchain. This keeps the eval reproducible
and CI-friendly.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from pfg.detectors.rule_baseline import detect_all
from pfg.eval.manifest import ExpectedFinding, Manifest
from pfg.extractors.django.build import build_pfg
from pfg.pfg.graph import PFG

Prediction = tuple[str, str]  # (endpoint_id, subtype)
Detector = Callable[[PFG], set[Prediction]]


# --- detectors ------------------------------------------------------------


def rule_detector(pfg: PFG) -> set[Prediction]:
    """Pure-Python rule baseline: returns {(endpoint_id, subtype), ...}."""
    return {(f.endpoint_id, f.subtype.value) for f in detect_all(pfg)}


def external_findings_detector(findings_path: str | Path) -> Detector:
    """Load a JSON file shaped like:

        [{"endpoint_id": "...", "subtype": "IDOR"}, ...]

    Returns a detector that ignores the PFG and returns those predictions.
    Used to plug Semgrep / CodeQL output into the same evaluation pipeline.
    """
    raw = json.loads(Path(findings_path).read_text(encoding="utf-8"))
    preds: set[Prediction] = {(f["endpoint_id"], f["subtype"]) for f in raw}

    def _detect(_pfg: PFG) -> set[Prediction]:
        return preds

    return _detect


def gnn_detector(model: Any, *, threshold: float = 0.5) -> Detector:
    """Wrap a trained PathAnalyzer (multi-class) into a Detector.

    For each endpoint node in the PFG we build a single-graph PyG `Data` with
    `target_mask` set on that endpoint, run the model, and emit a prediction
    iff the argmax class is one of the four vulnerability subtypes (1..4) and
    its softmax probability exceeds `threshold`. SAFE / INTENTIONALLY_PUBLIC
    are not emitted.
    """
    import torch
    from torch.nn import functional as F  # noqa: N812

    from pfg.pfg.features import EDGE_FEATURE_DIM, NODE_FEATURE_DIM, encode_edge, encode_node
    from pfg.pfg.nodes import NodeType
    from pfg.synthetic.dataset import _SUBTYPE_INDEX

    inv_subtype = {v: k for k, v in _SUBTYPE_INDEX.items()}

    def _detect(pfg: PFG) -> set[Prediction]:
        if not pfg.nodes:
            return set()
        try:
            from torch_geometric.data import Data
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("torch_geometric required for gnn_detector") from exc

        node_id_to_idx = {n.id: i for i, n in enumerate(pfg.nodes)}
        x = torch.tensor([encode_node(n) for n in pfg.nodes], dtype=torch.float32)
        assert x.shape[1] == NODE_FEATURE_DIM
        if pfg.edges:
            src = [node_id_to_idx[e.src] for e in pfg.edges]
            dst = [node_id_to_idx[e.dst] for e in pfg.edges]
            edge_index = torch.tensor([src, dst], dtype=torch.long)
            edge_attr = torch.tensor(
                [encode_edge(e.type) for e in pfg.edges], dtype=torch.float32
            )
            assert edge_attr.shape[1] == EDGE_FEATURE_DIM
        else:
            edge_index = torch.zeros((2, 0), dtype=torch.long)
            edge_attr = torch.zeros((0, EDGE_FEATURE_DIM), dtype=torch.float32)

        endpoint_ids = [n.id for n in pfg.nodes if n.type == NodeType.ENDPOINT.value]
        preds: set[Prediction] = set()
        model.eval()
        with torch.no_grad():
            for ep_id in endpoint_ids:
                target_mask = torch.zeros(len(pfg.nodes), dtype=torch.float32)
                target_mask[node_id_to_idx[ep_id]] = 1.0
                data = Data(
                    x=x.clone(),
                    edge_index=edge_index.clone(),
                    edge_attr=edge_attr.clone(),
                    target_mask=target_mask,
                )
                logits = model(data)
                probs = F.softmax(logits, dim=-1).squeeze(0)
                cls = int(probs.argmax().item())
                conf = float(probs[cls].item())
                name = inv_subtype.get(cls, "SAFE")
                if name in {"MISSING_AUTH", "MISSING_ROLE", "IDOR", "COMBINED"} and conf >= threshold:
                    preds.add((ep_id, name))
        return preds

    return _detect


# --- scoring --------------------------------------------------------------


@dataclass
class AppScore:
    application: str
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    predictions: list[dict[str, str]] = field(default_factory=list)
    expected: list[dict[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _score_one(
    expected: Iterable[ExpectedFinding],
    predicted: set[Prediction],
    intentional_public: Iterable[str],
) -> tuple[int, int, int, list[str]]:
    """Compute (tp, fp, fn, notes). Predictions on intentional_public are dropped.

    Match key is (endpoint_id, subtype). COMBINED matches in either direction
    against MISSING_AUTH or MISSING_ROLE on the same endpoint (a COMBINED
    prediction satisfies a MISSING_AUTH expected finding and vice versa).
    """
    intentional = set(intentional_public)
    predicted = {p for p in predicted if p[0] not in intentional}
    expected_set: set[Prediction] = {(e.endpoint_id, e.subtype) for e in expected}

    notes: list[str] = []
    matched_expected: set[Prediction] = set()
    matched_predicted: set[Prediction] = set()

    # 1) exact matches
    for p in predicted:
        if p in expected_set:
            matched_expected.add(p)
            matched_predicted.add(p)

    # 2) COMBINED-flexibility: a COMBINED on endpoint X matches any expected
    #    MISSING_AUTH/MISSING_ROLE/IDOR on X. Symmetric.
    def _combined_match(a: Prediction, b: Prediction) -> bool:
        if a[0] != b[0]:
            return False
        return "COMBINED" in {a[1], b[1]} and {a[1], b[1]} <= {
            "COMBINED", "MISSING_AUTH", "MISSING_ROLE", "IDOR"
        }

    for p in predicted - matched_predicted:
        for e in expected_set - matched_expected:
            if _combined_match(p, e):
                matched_predicted.add(p)
                matched_expected.add(e)
                notes.append(f"matched {p} <-> {e} via COMBINED rule")
                break

    tp = len(matched_predicted)
    fp = len(predicted) - tp
    fn = len(expected_set) - len(matched_expected)
    return tp, fp, fn, notes


def evaluate_app(
    manifest: Manifest, detector: Detector, *, build: Callable[[Path], PFG] | None = None
) -> AppScore:
    """Run the detector on one app and score it."""
    builder = build or (lambda root: build_pfg(root))
    pfg = builder(manifest.project_root)
    predicted = detector(pfg)
    tp, fp, fn, notes = _score_one(
        manifest.expected_findings, predicted, manifest.intentional_public_endpoints
    )
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
    return AppScore(
        application=manifest.application,
        tp=tp,
        fp=fp,
        fn=fn,
        precision=prec,
        recall=rec,
        f1=f1,
        predictions=[{"endpoint_id": e, "subtype": s} for e, s in sorted(predicted)],
        expected=[
            {"endpoint_id": ef.endpoint_id, "subtype": ef.subtype}
            for ef in manifest.expected_findings
        ],
        notes=notes,
    )


@dataclass
class CorpusReport:
    detector_name: str
    apps: list[AppScore] = field(default_factory=list)
    micro_precision: float = 0.0
    micro_recall: float = 0.0
    micro_f1: float = 0.0


def evaluate_corpus(
    manifests: Iterable[Manifest],
    detector: Detector,
    *,
    detector_name: str = "rule_baseline",
    build: Callable[[Path], PFG] | None = None,
) -> CorpusReport:
    apps = [evaluate_app(m, detector, build=build) for m in manifests]
    tp = sum(a.tp for a in apps)
    fp = sum(a.fp for a in apps)
    fn = sum(a.fn for a in apps)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
    return CorpusReport(
        detector_name=detector_name,
        apps=apps,
        micro_precision=prec,
        micro_recall=rec,
        micro_f1=f1,
    )


def report_to_dict(report: CorpusReport) -> dict[str, Any]:
    return {
        "detector": report.detector_name,
        "micro_precision": report.micro_precision,
        "micro_recall": report.micro_recall,
        "micro_f1": report.micro_f1,
        "apps": [asdict(a) for a in report.apps],
    }
