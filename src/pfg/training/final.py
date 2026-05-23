"""Final real-corpus experiment for PathAnalyzer (Model B only)."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

import torch

from pfg.eval.harness import (
    AppScore,
    CorpusReport,
    evaluate_app,
    evaluate_corpus,
    report_to_dict,
    rule_detector,
)
from pfg.eval.manifest import Manifest, discover_manifests
from pfg.extractors.django.build import build_pfg
from pfg.models.checkpoint import save_model
from pfg.models.gnn import PathAnalyzer
from pfg.pfg.nodes import EndpointAttrs
from pfg.synthetic import label_to_targets, pfg_to_pyg
from pfg.synthetic.generator import Sample
from pfg.training.augmentation import AugmentationConfig, augmented_samples_from_manifests
from pfg.training.corpus import PfgCache, samples_from_manifests, split_manifests_by_group
from pfg.training.trainer import TrainResult, pretrain_path_analyzer, train_path_analyzer_split
from pfg.training.weak_supervision import (
    WeakSupervisionConfig,
    pseudo_labeled_samples_from_manifests,
)

CLASS_NAMES = [
    "SAFE",
    "MISSING_AUTH",
    "MISSING_ROLE",
    "IDOR",
    "TENANT_ISOLATION_FAILURE",
    "OBJECT_LEVEL_PERMISSION_BYPASS",
    "COMBINED",
    "INTENTIONALLY_PUBLIC",
]
VULNERABLE_CLASS_IDS = {1, 2, 3, 4, 5, 6}


@dataclass(frozen=True)
class FinalExperimentOutputs:
    metrics_path: Path
    report_path: Path
    real_only_model_path: Path
    augmented_model_path: Path
    twostage_model_path: Path | None
    metrics: dict[str, Any]


def _class_counts(samples: list[Sample]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for sample in samples:
        _, y = label_to_targets(sample)
        counts[CLASS_NAMES[y]] += 1
    return {name: counts.get(name, 0) for name in CLASS_NAMES}


def _metrics_from_confusion(cm: list[list[int]]) -> dict[str, Any]:
    if len(cm) < len(CLASS_NAMES):
        width = max((len(row) for row in cm), default=0)
        padded = [row + [0] * (len(CLASS_NAMES) - len(row)) for row in cm]
        padded.extend([[0] * max(len(CLASS_NAMES), width) for _ in range(len(CLASS_NAMES) - len(cm))])
        cm = [row[: len(CLASS_NAMES)] for row in padded]
    per_class: dict[str, dict[str, float | int]] = {}
    total = sum(sum(row) for row in cm)
    correct = sum(cm[i][i] for i in range(len(cm)))
    f1s: list[float] = []
    for i, name in enumerate(CLASS_NAMES):
        tp = cm[i][i]
        fp = sum(cm[r][i] for r in range(len(cm)) if r != i)
        fn = sum(cm[i][c] for c in range(len(cm)) if c != i)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        f1s.append(f1)
        per_class[name] = {
            "support": sum(cm[i]),
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }

    vuln_tp = sum(cm[i][j] for i in VULNERABLE_CLASS_IDS for j in VULNERABLE_CLASS_IDS)
    vuln_fp = sum(
        cm[i][j]
        for i in range(len(cm))
        for j in VULNERABLE_CLASS_IDS
        if i not in VULNERABLE_CLASS_IDS
    )
    vuln_fn = sum(
        cm[i][j]
        for i in VULNERABLE_CLASS_IDS
        for j in range(len(cm))
        if j not in VULNERABLE_CLASS_IDS
    )
    vuln_precision = vuln_tp / (vuln_tp + vuln_fp) if (vuln_tp + vuln_fp) else 0.0
    vuln_recall = vuln_tp / (vuln_tp + vuln_fn) if (vuln_tp + vuln_fn) else 0.0
    vuln_f1 = (
        2 * vuln_precision * vuln_recall / (vuln_precision + vuln_recall)
        if (vuln_precision + vuln_recall)
        else 0.0
    )
    return {
        "accuracy": correct / total if total else 0.0,
        "macro_f1": sum(f1s) / len(f1s) if f1s else 0.0,
        "per_class": per_class,
        "vulnerability_finding": {
            "precision": vuln_precision,
            "recall": vuln_recall,
            "f1": vuln_f1,
            "tp": vuln_tp,
            "fp": vuln_fp,
            "fn": vuln_fn,
        },
        "confusion": cm,
    }


def _train_result_to_dict(result: TrainResult) -> dict[str, Any]:
    metrics = _metrics_from_confusion(result.confusion)
    metrics.update(
        {
            "test_accuracy": result.test_accuracy,
            "test_macro_f1": result.test_macro_f1,
            "best_val_loss": result.best_val_loss,
            "history": result.history,
        }
    )
    return metrics


def _predict_samples(model: PathAnalyzer, samples: list[Sample]) -> list[dict[str, Any]]:
    model.eval()
    out: list[dict[str, Any]] = []
    with torch.no_grad():
        for sample in samples:
            data = pfg_to_pyg(sample)
            logits, attn = model.forward_with_attention(data)
            probs = torch.softmax(logits, dim=-1).squeeze(0)
            predicted_idx = int(probs.argmax().item())
            _, expected_idx = label_to_targets(sample)
            out.append(
                {
                    "endpoint_id": sample.target_endpoint_id,
                    "expected": CLASS_NAMES[expected_idx],
                    "predicted": CLASS_NAMES[predicted_idx],
                    "confidence": float(probs[predicted_idx].item()),
                    "correct": expected_idx == predicted_idx,
                    "explanation": _explain_sample(sample, attn.cpu().tolist()),
                }
            )
    return out


def _explain_sample(sample: Sample, attention: list[float]) -> dict[str, Any]:
    pfg = sample.pfg
    node_by_id = {node.id: node for node in pfg.nodes}
    endpoint = node_by_id.get(sample.target_endpoint_id)
    endpoint_attrs = endpoint.attrs if endpoint is not None else None
    if not isinstance(endpoint_attrs, EndpointAttrs):
        source_location = None
        route = None
    else:
        source_location = endpoint_attrs.source_location
        route = endpoint_attrs.route

    top_nodes = sorted(
        (
            {
                "node_id": node.id,
                "type": str(node.type),
                "attention": attention[idx] if idx < len(attention) else 0.0,
            }
            for idx, node in enumerate(pfg.nodes)
        ),
        key=lambda item: cast(float, item["attention"]),
        reverse=True,
    )[:8]
    identifier_flow = [
        {"dst": edge.dst, "param": edge.param}
        for edge in pfg.edges
        if edge.src == sample.target_endpoint_id and edge.type == "identifier_flow"
    ]
    reachable_data_access = [
        node.id
        for node in pfg.data_accesses()
        if _has_call_path(pfg, sample.target_endpoint_id, node.id)
    ][:12]
    return {
        "route": route,
        "source_location": source_location,
        "attention_ranked_nodes": top_nodes,
        "identifier_flow": identifier_flow,
        "reachable_data_access": reachable_data_access,
    }


def _has_call_path(pfg: Any, src: str, dst: str) -> bool:
    succ: dict[str, list[str]] = {}
    for edge in pfg.edges:
        if edge.type == "call":
            succ.setdefault(edge.src, []).append(edge.dst)
    seen = {src}
    stack = [src]
    while stack:
        cur = stack.pop()
        if cur == dst:
            return True
        for nxt in succ.get(cur, []):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return False


def _external_system_report(
    path: Path | None,
    manifests: list[Manifest],
    *,
    detector_name: str,
) -> dict[str, Any]:
    if path is None:
        return {
            "status": "not_run",
            "reason": "No normalized endpoint-level findings file was provided.",
        }
    records = json.loads(path.read_text(encoding="utf-8"))
    has_scope = any(
        "application" in record
        or "app" in record
        or "dataset_split_group" in record
        or "group" in record
        for record in records
    )
    apps: list[AppScore] = []
    for manifest in manifests:
        preds = {
            (record["endpoint_id"], record["subtype"])
            for record in records
            if _external_record_applies(record, manifest, scoped=has_scope)
        }

        def detector(_pfg: Any, preds: set[tuple[str, str]] = preds) -> set[tuple[str, str]]:
            return preds

        def builder(root: Path, app: str = manifest.application) -> Any:
            return build_pfg(root, application=app)

        apps.append(
            evaluate_app(
                manifest,
                detector,
                build=builder,
            )
        )

    tp = sum(app.tp for app in apps)
    fp = sum(app.fp for app in apps)
    fn = sum(app.fn for app in apps)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    report = CorpusReport(
        detector_name=detector_name,
        apps=apps,
        micro_precision=precision,
        micro_recall=recall,
        micro_f1=f1,
    )
    data = report_to_dict(report)
    data.update(
        {
            "status": "provided",
            "findings_path": str(path),
            "n_findings": len(records),
            "record_scope": "application_or_group" if has_scope else "flat_endpoint_list",
            "note": (
                "Flat normalized findings are interpreted as belonging to the held-out "
                "manifest set. Add `application` or `dataset_split_group` when combining "
                "findings from multiple apps."
            ),
        }
    )
    return data


def _external_record_applies(record: dict[str, Any], manifest: Manifest, *, scoped: bool) -> bool:
    if not scoped:
        return True
    app = record.get("application") or record.get("app")
    group = record.get("dataset_split_group") or record.get("group")
    return app == manifest.application or group == (manifest.dataset_split_group or manifest.application)


def run_final_experiment(
    corpus_root: str | Path,
    *,
    holdout_group: str | None = None,
    epochs: int = 30,
    pretrain_epochs: int = 20,
    seed: int = 0,
    batch_size: int = 32,
    hidden_dim: int = 64,
    num_layers: int = 3,
    heads: int = 4,
    focal_gamma: float = 2.0,
    augmentation_cap: int = 10,
    weak_supervision: bool = False,
    weak_supervision_cap: int = 32,
    contrastive_pairs: int = 150,
    out_dir: str | Path = "artifacts",
    semgrep_findings: str | Path | None = None,
    codeql_findings: str | Path | None = None,
) -> FinalExperimentOutputs:
    from pfg.synthetic.contrastive import generate_contrastive_dataset

    manifests = discover_manifests(corpus_root)
    train_m, val_m, test_m = split_manifests_by_group(
        manifests, seed=seed, holdout_group=holdout_group
    )
    if not train_m or not val_m or not test_m:
        raise ValueError("Need non-empty train/val/test split groups for final experiment")

    pfg_cache: PfgCache = {}

    def cached_build(root: Path):
        resolved = str(Path(root).resolve())
        for (cached_root, _application), pfg in pfg_cache.items():
            if cached_root == resolved:
                return pfg
        return build_pfg(root)

    train_samples = samples_from_manifests(train_m, cache=pfg_cache)
    val_samples = samples_from_manifests(val_m, cache=pfg_cache)
    test_samples = samples_from_manifests(test_m, cache=pfg_cache)
    augmented_train_samples = augmented_samples_from_manifests(
        train_m, config=AugmentationConfig(max_per_manifest=augmentation_cap), cache=pfg_cache
    )
    weak_train_samples = pseudo_labeled_samples_from_manifests(
        train_m,
        config=WeakSupervisionConfig(
            enabled=weak_supervision,
            max_per_manifest=weak_supervision_cap,
        ),
        cache=pfg_cache,
    )

    # --- Model 1: real-only (baseline) ---
    real_only_model, real_only_result = train_path_analyzer_split(
        train_samples,
        val_samples,
        test_samples,
        epochs=epochs,
        seed=seed,
        batch_size=batch_size,
        hidden_dim=hidden_dim,
        num_layers=num_layers,
        heads=heads,
    )

    # --- Model 2: real + augmented with focal loss ---
    augmented_model, augmented_result = train_path_analyzer_split(
        [*train_samples, *augmented_train_samples, *weak_train_samples],
        val_samples,
        test_samples,
        epochs=epochs,
        seed=seed,
        batch_size=batch_size,
        hidden_dim=hidden_dim,
        num_layers=num_layers,
        heads=heads,
        focal_gamma=focal_gamma,
    )

    # --- Model 3: two-stage (contrastive pretrain -> fine-tune on real+augmented) ---
    synthetic_samples = generate_contrastive_dataset(
        n_pairs=contrastive_pairs, seed=seed
    )
    pretrained_state = pretrain_path_analyzer(
        synthetic_samples,
        epochs=pretrain_epochs,
        seed=seed,
        batch_size=batch_size,
        hidden_dim=hidden_dim,
        num_layers=num_layers,
        heads=heads,
        focal_gamma=focal_gamma,
    )
    twostage_model, twostage_result = train_path_analyzer_split(
        [*train_samples, *augmented_train_samples, *weak_train_samples],
        val_samples,
        test_samples,
        epochs=epochs,
        seed=seed,
        batch_size=batch_size,
        hidden_dim=hidden_dim,
        num_layers=num_layers,
        heads=heads,
        focal_gamma=focal_gamma,
        pretrained_state=pretrained_state,
    )

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    real_only_model_path = out / "path_analyzer_real_only.pt"
    augmented_model_path = out / "path_analyzer_real_augmented.pt"
    twostage_model_path = out / "path_analyzer_twostage.pt"
    hparams = {"hidden_dim": hidden_dim, "num_layers": num_layers, "heads": heads}
    save_model(real_only_model, real_only_model_path, kind="path", hparams=hparams)
    save_model(augmented_model, augmented_model_path, kind="path", hparams=hparams)
    save_model(twostage_model, twostage_model_path, kind="path", hparams=hparams)

    rule_report = evaluate_corpus(
        test_m, rule_detector, detector_name="rule_baseline", build=cached_build
    )
    real_only_metrics = _train_result_to_dict(real_only_result)
    augmented_metrics = _train_result_to_dict(augmented_result)
    twostage_metrics = _train_result_to_dict(twostage_result)

    delta_aug = {
        "macro_f1": augmented_metrics["macro_f1"] - real_only_metrics["macro_f1"],
        "accuracy": augmented_metrics["accuracy"] - real_only_metrics["accuracy"],
        "vulnerability_recall": (
            augmented_metrics["vulnerability_finding"]["recall"]
            - real_only_metrics["vulnerability_finding"]["recall"]
        ),
        "vulnerability_precision": (
            augmented_metrics["vulnerability_finding"]["precision"]
            - real_only_metrics["vulnerability_finding"]["precision"]
        ),
    }
    delta_twostage = {
        "macro_f1": twostage_metrics["macro_f1"] - real_only_metrics["macro_f1"],
        "accuracy": twostage_metrics["accuracy"] - real_only_metrics["accuracy"],
        "vulnerability_recall": (
            twostage_metrics["vulnerability_finding"]["recall"]
            - real_only_metrics["vulnerability_finding"]["recall"]
        ),
        "vulnerability_precision": (
            twostage_metrics["vulnerability_finding"]["precision"]
            - real_only_metrics["vulnerability_finding"]["precision"]
        ),
    }

    real_only_predictions = _predict_samples(real_only_model, test_samples)
    augmented_predictions = _predict_samples(augmented_model, test_samples)
    twostage_predictions = _predict_samples(twostage_model, test_samples)

    warnings = []
    if not augmented_train_samples:
        warnings.append(
            "The selected training split produced zero augmented samples; "
            "real+augmented metrics are therefore not an augmentation comparison."
        )
    metrics: dict[str, Any] = {
        "experiment": "path_analyzer_final_real_corpus_v2",
        "model_scope": "Model B / PathAnalyzer only",
        "config": {
            "holdout_group": holdout_group,
            "seed": seed,
            "epochs": epochs,
            "pretrain_epochs": pretrain_epochs,
            "batch_size": batch_size,
            "hidden_dim": hidden_dim,
            "num_layers": num_layers,
            "heads": heads,
            "focal_gamma": focal_gamma,
            "augmentation_cap": augmentation_cap,
            "weak_supervision": weak_supervision,
            "weak_supervision_cap": weak_supervision_cap,
            "contrastive_pairs": contrastive_pairs,
        },
        "warnings": warnings,
        "split": {
            "train_groups": sorted({m.dataset_split_group or m.application for m in train_m}),
            "val_groups": sorted({m.dataset_split_group or m.application for m in val_m}),
            "test_groups": sorted({m.dataset_split_group or m.application for m in test_m}),
            "n_train_real_samples": len(train_samples),
            "n_train_augmented_samples": len(augmented_train_samples),
            "n_train_weak_supervision_samples": len(weak_train_samples),
            "n_synthetic_contrastive_samples": len(synthetic_samples),
            "n_val_real_samples": len(val_samples),
            "n_test_real_samples": len(test_samples),
            "test_is_real_only": True,
        },
        "class_distribution": {
            "train_real": _class_counts(train_samples),
            "train_augmented": _class_counts(augmented_train_samples),
            "train_weak_supervision": _class_counts(weak_train_samples),
            "synthetic_contrastive": _class_counts(synthetic_samples),
            "val_real": _class_counts(val_samples),
            "test_real": _class_counts(test_samples),
        },
        "models": {
            "path_analyzer_real_only": real_only_metrics,
            "path_analyzer_real_augmented": augmented_metrics,
            "path_analyzer_twostage": twostage_metrics,
            "real_augmented_delta": delta_aug,
            "twostage_delta": delta_twostage,
        },
        "baselines": {
            "rule_baseline": report_to_dict(rule_report),
            "semgrep": _external_system_report(
                Path(semgrep_findings) if semgrep_findings else None,
                test_m,
                detector_name="semgrep",
            ),
            "codeql": _external_system_report(
                Path(codeql_findings) if codeql_findings else None,
                test_m,
                detector_name="codeql",
            ),
        },
        "predictions": {
            "path_analyzer_real_only": real_only_predictions,
            "path_analyzer_real_augmented": augmented_predictions,
            "path_analyzer_twostage": twostage_predictions,
        },
        "error_analysis": {
            "path_analyzer_real_only": [p for p in real_only_predictions if not p["correct"]],
            "path_analyzer_real_augmented": [p for p in augmented_predictions if not p["correct"]],
            "path_analyzer_twostage": [p for p in twostage_predictions if not p["correct"]],
        },
        "augmentation": {
            "policy": "real-derived training-only augmentation (capped)",
            "held_out_test_contains_augmented_samples": False,
            "max_per_manifest": augmentation_cap,
            "types": [
                "remove_auth_guard",
                "remove_role_guard",
                "remove_ownership_predicate",
                "remove_tenant_predicate",
                "remove_object_permission_check",
            ],
            "sample_metadata_keys": [
                "augmented",
                "origin_manifest",
                "origin_endpoint_id",
                "augmentation_type",
            ],
        },
        "weak_supervision": {
            "enabled": weak_supervision,
            "policy": (
                "PFG rule pseudo-labels are generated from training manifests only; "
                "validation and test remain real advisory-backed samples."
            ),
            "held_out_test_contains_pseudo_labels": False,
            "max_per_manifest": weak_supervision_cap,
            "n_samples": len(weak_train_samples),
        },
    }

    metrics_path = out / "final_metrics.json"
    report_path = out / "final_report.md"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    report_path.write_text(_render_markdown_report(metrics), encoding="utf-8")
    return FinalExperimentOutputs(
        metrics_path=metrics_path,
        report_path=report_path,
        real_only_model_path=real_only_model_path,
        augmented_model_path=augmented_model_path,
        twostage_model_path=twostage_model_path,
        metrics=metrics,
    )


def _render_markdown_report(metrics: dict[str, Any]) -> str:
    split = metrics["split"]
    real = metrics["models"]["path_analyzer_real_only"]
    aug = metrics["models"]["path_analyzer_real_augmented"]
    twostage = metrics["models"].get("path_analyzer_twostage")
    delta_aug = metrics["models"]["real_augmented_delta"]
    delta_ts = metrics["models"].get("twostage_delta", {})
    rule = metrics["baselines"]["rule_baseline"]
    lines = [
        "# PathAnalyzer Final Real-Corpus Report (v2)",
        "",
        "## Methodology",
        "",
        "This report evaluates Model B / PathAnalyzer with three training strategies:",
        "1. **Real-only** — baseline trained on real extracted PFGs only.",
        "2. **Real + Augmented** — real PFGs plus capped real-derived augmentations with focal loss.",
        "3. **Two-stage** — contrastive synthetic pre-training then fine-tuning on real+augmented.",
        "",
        "Validation and test are always real-only.",
        "",
    ]
    for warning in metrics.get("warnings", []):
        lines.append(f"> Warning: {warning}")
    if metrics.get("warnings"):
        lines.append("")
    lines.extend(
        [
            "## Dataset Split",
            "",
            f"- Train groups: {', '.join(split['train_groups'])}",
            f"- Validation groups: {', '.join(split['val_groups'])}",
            f"- Test groups: {', '.join(split['test_groups'])}",
            f"- Real train samples: {split['n_train_real_samples']}",
            f"- Augmented train samples: {split['n_train_augmented_samples']}",
            f"- Weak-supervision train samples: {split.get('n_train_weak_supervision_samples', 0)}",
            f"- Synthetic contrastive samples: {split.get('n_synthetic_contrastive_samples', 'N/A')}",
            f"- Real validation samples: {split['n_val_real_samples']}",
            f"- Real test samples: {split['n_test_real_samples']}",
            "",
            "## Model Comparison",
            "",
            "| System | Accuracy | Macro F1 | Vuln Precision | Vuln Recall | Vuln F1 |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
            _metric_row("PathAnalyzer real-only", real),
            _metric_row("PathAnalyzer real + augmented", aug),
        ]
    )
    if twostage:
        lines.append(_metric_row("PathAnalyzer two-stage", twostage))
    lines.extend(
        [
            "",
            "## Augmentation Delta (vs real-only)",
            "",
            f"- Macro F1 delta: {delta_aug['macro_f1']:.4f}",
            f"- Accuracy delta: {delta_aug['accuracy']:.4f}",
            f"- Vulnerability recall delta: {delta_aug['vulnerability_recall']:.4f}",
            f"- Vulnerability precision delta: {delta_aug['vulnerability_precision']:.4f}",
            "",
        ]
    )
    if delta_ts:
        lines.extend(
            [
                "## Two-Stage Delta (vs real-only)",
                "",
                f"- Macro F1 delta: {delta_ts['macro_f1']:.4f}",
                f"- Accuracy delta: {delta_ts['accuracy']:.4f}",
                f"- Vulnerability recall delta: {delta_ts['vulnerability_recall']:.4f}",
                f"- Vulnerability precision delta: {delta_ts['vulnerability_precision']:.4f}",
                "",
            ]
        )
    lines.extend(
        [
            "## Baselines",
            "",
            f"- Rule baseline on held-out test groups: precision={rule['micro_precision']:.4f}, recall={rule['micro_recall']:.4f}, F1={rule['micro_f1']:.4f}",
            f"- Semgrep: {metrics['baselines']['semgrep']['status']}",
            f"- CodeQL: {metrics['baselines']['codeql']['status']}",
            "",
            "## Error Analysis",
            "",
            f"- PathAnalyzer real-only errors: {len(metrics['error_analysis']['path_analyzer_real_only'])}",
            f"- PathAnalyzer real + augmented errors: {len(metrics['error_analysis']['path_analyzer_real_augmented'])}",
        ]
    )
    if "path_analyzer_twostage" in metrics["error_analysis"]:
        lines.append(f"- PathAnalyzer two-stage errors: {len(metrics['error_analysis']['path_analyzer_twostage'])}")
    lines.extend(
        [
            "",
            "Detailed endpoint-level predictions, explanations, and confusion matrices are in `final_metrics.json`.",
            "",
            "## Limitations",
            "",
            "External-tool results are marked `not_run` unless normalized Semgrep/CodeQL findings are provided. Large real apps may still expose extractor false positives that are tracked in error analysis rather than hidden.",
            "",
        ]
    )
    return "\n".join(lines)


def _metric_row(name: str, metrics: dict[str, Any]) -> str:
    vuln = metrics["vulnerability_finding"]
    return (
        f"| {name} | {metrics['accuracy']:.4f} | {metrics['macro_f1']:.4f} | "
        f"{vuln['precision']:.4f} | {vuln['recall']:.4f} | {vuln['f1']:.4f} |"
    )


def final_outputs_to_dict(outputs: FinalExperimentOutputs) -> dict[str, Any]:
    data = asdict(outputs)
    data["metrics_path"] = str(outputs.metrics_path)
    data["report_path"] = str(outputs.report_path)
    data["real_only_model_path"] = str(outputs.real_only_model_path)
    data["augmented_model_path"] = str(outputs.augmented_model_path)
    return data


__all__ = [
    "CLASS_NAMES",
    "FinalExperimentOutputs",
    "final_outputs_to_dict",
    "run_final_experiment",
]
