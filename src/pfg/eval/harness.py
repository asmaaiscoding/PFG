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
    iff the argmax class is one of the vulnerability subtypes and
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
                if name not in {"SAFE", "INTENTIONALLY_PUBLIC"} and conf >= threshold:
                    preds.add((ep_id, name))
        return preds

    return _detect


def validated_gnn_detector(model: Any, *, threshold: float = 0.5) -> Detector:
    """GNN detector with structural post-validation.

    Applies the same model as ``gnn_detector`` but suppresses predictions
    that lack structural evidence:

    * MISSING_AUTH: suppressed unless the endpoint reaches at least one
      ``data_access`` node via call edges.
    * MISSING_ROLE: suppressed unless the endpoint reaches a privileged
      mutation without an endpoint role/role middleware.
    * IDOR: suppressed unless the endpoint has route params AND an
      ``identifier_flow`` edge reaches a ``data_access`` node without
      an ownership predicate.
    * TENANT_ISOLATION_FAILURE: suppressed unless tenant-scoped data is
      reachable without a tenant predicate.
    * OBJECT_LEVEL_PERMISSION_BYPASS: suppressed unless model-level permission
      evidence exists and object-level permission evidence is absent.

    This hybridises the GNN's learned patterns with the rule baseline's
    structural constraints, keeping the GNN's recall advantage while
    reducing false positives.
    """
    from collections import deque

    from pfg.pfg.nodes import (
        DataAccessAttrs,
        EdgeType,
        EndpointAttrs,
        GuardType,
        MiddlewareAttrs,
        NodeType,
        OperationType,
    )

    base = gnn_detector(model, threshold=threshold)

    def _reaches_data_access(pfg: PFG, ep_id: str) -> bool:
        """True if ep_id reaches any data_access node via call edges."""
        call_types = {EdgeType.CALL.value}
        seen: set[str] = {ep_id}
        q: deque[str] = deque([ep_id])
        while q:
            cur = q.popleft()
            for e in pfg.edges:
                if e.src == cur and e.type in call_types and e.dst not in seen:
                    seen.add(e.dst)
                    q.append(e.dst)
        idx = pfg.node_index()
        return any(idx[n].type == NodeType.DATA_ACCESS.value for n in seen if n in idx)

    def _has_unprotected_id_flow(pfg: PFG, ep_id: str) -> bool:
        """True if endpoint has route params and id_flow reaches data_access w/o ownership."""
        idx = pfg.node_index()
        ep = idx.get(ep_id)
        if ep is None:
            return False
        if not isinstance(ep.attrs, EndpointAttrs) or not ep.attrs.route_params:
            return False
        # BFS via identifier_flow
        flow_types = {EdgeType.IDENTIFIER_FLOW.value}
        seen: set[str] = {ep_id}
        q: deque[str] = deque([ep_id])
        while q:
            cur = q.popleft()
            for e in pfg.edges:
                if e.src == cur and e.type in flow_types and e.dst not in seen:
                    seen.add(e.dst)
                    q.append(e.dst)
        for nid in seen:
            n = idx.get(nid)
            if n is None or n.type != NodeType.DATA_ACCESS.value:
                continue
            if (
                isinstance(n.attrs, DataAccessAttrs)
                and not n.attrs.has_ownership_predicate
                and not n.attrs.requires_tenant_isolation
                and not n.attrs.requires_object_permission
            ):
                return True
        return False

    def _has_missing_role_shape(pfg: PFG, ep_id: str) -> bool:
        idx = pfg.node_index()
        ep = idx.get(ep_id)
        if ep is None or not isinstance(ep.attrs, EndpointAttrs):
            return False
        if ep.attrs.role_check_present or ep.attrs.required_role not in {"NONE", None}:
            return False
        reached = _reachable_call_nodes(pfg, ep_id)
        privileged = {OperationType.WRITE.value, OperationType.UPDATE.value, OperationType.DELETE.value}
        for nid in reached:
            n = idx.get(nid)
            if n is None:
                continue
            if isinstance(n.attrs, MiddlewareAttrs) and n.attrs.guard_type == GuardType.ROLE_CHECK.value:
                return False
            if isinstance(n.attrs, DataAccessAttrs):
                op = n.attrs.operation if isinstance(n.attrs.operation, str) else n.attrs.operation.value
                if op in privileged:
                    return True
        return False

    def _reachable_call_nodes(pfg: PFG, ep_id: str) -> set[str]:
        seen: set[str] = {ep_id}
        q: deque[str] = deque([ep_id])
        while q:
            cur = q.popleft()
            for e in pfg.edges:
                if e.src == cur and e.type == EdgeType.CALL.value and e.dst not in seen:
                    seen.add(e.dst)
                    q.append(e.dst)
        return seen

    def _has_unscoped_tenant_access(pfg: PFG, ep_id: str) -> bool:
        idx = pfg.node_index()
        ep = idx.get(ep_id)
        if ep is None or not isinstance(ep.attrs, EndpointAttrs):
            return False
        if ep.attrs.tenant_check_present:
            return False
        for nid in _reachable_call_nodes(pfg, ep_id):
            n = idx.get(nid)
            attrs = getattr(n, "attrs", None)
            if isinstance(attrs, MiddlewareAttrs) and attrs.guard_type == GuardType.TENANT_CHECK.value:
                return False
            if (
                isinstance(attrs, DataAccessAttrs)
                and attrs.requires_tenant_isolation
                and not attrs.has_tenant_predicate
            ):
                return True
        return False

    def _has_object_permission_bypass_shape(pfg: PFG, ep_id: str) -> bool:
        idx = pfg.node_index()
        ep = idx.get(ep_id)
        if ep is None or not isinstance(ep.attrs, EndpointAttrs):
            return False
        if not ep.attrs.model_permission_check_present:
            return False
        if ep.attrs.object_permission_check_present:
            return False
        if not ep.attrs.route_params:
            return False
        for nid in _reachable_call_nodes(pfg, ep_id):
            n = idx.get(nid)
            attrs = getattr(n, "attrs", None)
            if isinstance(attrs, MiddlewareAttrs) and attrs.guard_type == GuardType.OBJECT_PERMISSION_CHECK.value:
                return False
            if (
                isinstance(attrs, DataAccessAttrs)
                and attrs.requires_object_permission
                and not attrs.has_object_permission_check
            ):
                return True
        return False

    def _detect(pfg: PFG) -> set[Prediction]:
        raw = base(pfg)
        validated: set[Prediction] = set()
        for ep_id, subtype in raw:
            if subtype == "MISSING_AUTH":
                if _reaches_data_access(pfg, ep_id):
                    validated.add((ep_id, subtype))
            elif subtype == "MISSING_ROLE":
                if _has_missing_role_shape(pfg, ep_id):
                    validated.add((ep_id, subtype))
            elif subtype == "IDOR":
                if _has_unprotected_id_flow(pfg, ep_id):
                    validated.add((ep_id, subtype))
            elif subtype == "TENANT_ISOLATION_FAILURE":
                if _has_unscoped_tenant_access(pfg, ep_id):
                    validated.add((ep_id, subtype))
            elif subtype == "OBJECT_LEVEL_PERMISSION_BYPASS":
                if _has_object_permission_bypass_shape(pfg, ep_id):
                    validated.add((ep_id, subtype))
            else:
                # COMBINED: keep if either condition is met
                if (
                    _reaches_data_access(pfg, ep_id)
                    or _has_unprotected_id_flow(pfg, ep_id)
                    or _has_unscoped_tenant_access(pfg, ep_id)
                    or _has_object_permission_bypass_shape(pfg, ep_id)
                ):
                    validated.add((ep_id, subtype))
        return validated

    return _detect


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
    against any concrete vulnerability subtype on the same endpoint.
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
    #    concrete vulnerability subtype on X. Symmetric.
    def _combined_match(a: Prediction, b: Prediction) -> bool:
        if a[0] != b[0]:
            return False
        return "COMBINED" in {a[1], b[1]} and {a[1], b[1]} <= {
            "COMBINED",
            "MISSING_AUTH",
            "MISSING_ROLE",
            "IDOR",
            "TENANT_ISOLATION_FAILURE",
            "OBJECT_LEVEL_PERMISSION_BYPASS",
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
