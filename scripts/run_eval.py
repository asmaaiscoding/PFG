#!/usr/bin/env python3
"""Run the evaluation pipeline on evaluation-ready manifests.

Evaluates rule_baseline detector on all manifests that:
1. Have evaluation_ready != false (or don't have the field)
2. Have source code available (project_root exists)

Usage:
    python scripts/run_eval.py [--detector rule|gnn] [--framework django|spring|all]
"""
import json
import sys
import yaml
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pfg.eval.manifest import Manifest, load_manifest
from pfg.eval.harness import (
    evaluate_app,
    evaluate_corpus,
    rule_detector,
    report_to_dict,
    AppScore,
    CorpusReport,
)


def make_builder(manifest: Manifest):
    """Create a build function that takes a Path and uses the correct extractor."""
    def _build(root):
        if manifest.framework == "django":
            from pfg.extractors.django.build import build_pfg
            return build_pfg(root, application=manifest.application)
        elif manifest.framework == "spring":
            from pfg.extractors.spring.build import build_pfg
            # For Spring, source_subdir specifies the actual Java source directory
            extract_root = root / manifest.source_subdir if manifest.source_subdir else root
            return build_pfg(extract_root, application=manifest.application)
        else:
            raise ValueError(f"Unsupported framework: {manifest.framework}")
    return _build

CORPUS_ROOT = Path("benchmarks/realworld")


def load_evaluation_manifests(framework_filter: str = "all") -> list[Manifest]:
    """Load manifests, filtering out evaluation_ready: false."""
    manifests = []
    for mpath in sorted(CORPUS_ROOT.rglob("manifest.yaml")):
        if any(part.startswith("_") for part in mpath.relative_to(CORPUS_ROOT).parts):
            continue
        try:
            raw = yaml.safe_load(mpath.read_text())
            if raw.get("evaluation_ready") is False:
                continue
            if framework_filter != "all" and raw.get("framework") != framework_filter:
                continue
            m = load_manifest(mpath)
            manifests.append(m)
        except Exception as e:
            print(f"  [skip] {mpath.parent.name}: {e}")
            continue
    return sorted(manifests, key=lambda m: m.application)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--detector", choices=["rule", "gnn"], default="rule")
    parser.add_argument("--framework", choices=["django", "spring", "all"], default="all")
    parser.add_argument("--output", type=str, default=None)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    print(f"Loading manifests (framework={args.framework})...")
    manifests = load_evaluation_manifests(args.framework)
    print(f"  Evaluation-ready manifests: {len(manifests)}")

    if not manifests:
        print("No manifests to evaluate!")
        return

    # Select detector
    if args.detector == "rule":
        detector = rule_detector
        detector_name = "rule_baseline"
    else:
        # Load GNN model
        import torch
        from pfg.eval.harness import validated_gnn_detector
        model_path = Path("artifacts/path_analyzer.pt")
        if not model_path.exists():
            print(f"ERROR: GNN model not found at {model_path}")
            return
        from pfg.models.gnn import PathAnalyzer
        model = PathAnalyzer()
        model.load_state_dict(torch.load(model_path, map_location="cpu", weights_only=True))
        detector = validated_gnn_detector(model)
        detector_name = "gnn_validated"

    # Run evaluation per-app with error handling
    print(f"\nRunning evaluation with detector={detector_name}...")
    print("=" * 70)

    apps: list[AppScore] = []
    errors: list[tuple[str, str]] = []

    for m in manifests:
        try:
            # Check project_root exists
            if not m.project_root.exists():
                if args.verbose:
                    print(f"  [skip] {m.application}: project_root not found")
                errors.append((m.application, "project_root not found"))
                continue

            score = evaluate_app(m, detector, build=make_builder(m))
            apps.append(score)

            status = "✓" if score.tp > 0 else ("○" if score.fn == 0 else "✗")
            if args.verbose or score.tp > 0 or score.fn > 0:
                print(f"  {status} {m.application:45} P={score.precision:.2f} R={score.recall:.2f} F1={score.f1:.2f} (TP={score.tp} FP={score.fp} FN={score.fn})")
        except Exception as e:
            errors.append((m.application, str(e)[:100]))
            if args.verbose:
                print(f"  [err] {m.application}: {e}")

    # Compute aggregate
    total_tp = sum(a.tp for a in apps)
    total_fp = sum(a.fp for a in apps)
    total_fn = sum(a.fn for a in apps)
    prec = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 0.0
    rec = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 0.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0

    print("\n" + "=" * 70)
    print(f"RESULTS ({detector_name})")
    print(f"  Apps evaluated: {len(apps)}")
    print(f"  Apps skipped/errored: {len(errors)}")
    print(f"  Micro Precision: {prec:.4f}")
    print(f"  Micro Recall:    {rec:.4f}")
    print(f"  Micro F1:        {f1:.4f}")
    print(f"  Total TP={total_tp}  FP={total_fp}  FN={total_fn}")

    # Per-framework breakdown
    django_apps = [a for a in apps if any(m.application == a.application and m.framework == "django" for m in manifests)]
    spring_apps = [a for a in apps if any(m.application == a.application and m.framework == "spring" for m in manifests)]

    for label, subset in [("Django", django_apps), ("Spring/Java", spring_apps)]:
        if not subset:
            continue
        tp = sum(a.tp for a in subset)
        fp = sum(a.fp for a in subset)
        fn = sum(a.fn for a in subset)
        p = tp / (tp + fp) if (tp + fp) else 0.0
        r = tp / (tp + fn) if (tp + fn) else 0.0
        f = (2 * p * r / (p + r)) if (p + r) else 0.0
        print(f"\n  {label} ({len(subset)} apps):")
        print(f"    P={p:.4f} R={r:.4f} F1={f:.4f} (TP={tp} FP={fp} FN={fn})")

    if errors and args.verbose:
        print(f"\n  Errors:")
        for app, err in errors:
            print(f"    {app}: {err}")

    # Save report
    if args.output:
        report = {
            "detector": detector_name,
            "framework_filter": args.framework,
            "apps_evaluated": len(apps),
            "micro_precision": prec,
            "micro_recall": rec,
            "micro_f1": f1,
            "total_tp": total_tp,
            "total_fp": total_fp,
            "total_fn": total_fn,
            "per_app": [
                {
                    "application": a.application,
                    "tp": a.tp, "fp": a.fp, "fn": a.fn,
                    "precision": a.precision,
                    "recall": a.recall,
                    "f1": a.f1,
                    "predictions": a.predictions,
                    "expected": a.expected,
                    "notes": a.notes,
                }
                for a in apps
            ],
            "errors": [{"app": a, "error": e} for a, e in errors],
        }
        Path(args.output).write_text(json.dumps(report, indent=2))
        print(f"\n  Report saved to: {args.output}")


if __name__ == "__main__":
    main()
