"""`pfg` CLI entry point. Phase-0 stub; real subcommands added per phase."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from pfg import __version__
from pfg.detectors.rule_baseline import detect_all
from pfg.pfg.graph import load_pfg, save_pfg


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Privilege Flow Graph: detect access-control vulnerabilities."""


@main.command()
@click.argument("pfg_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def validate(pfg_path: Path) -> None:
    """Validate a PFG JSON file against the schema."""
    pfg = load_pfg(pfg_path)
    click.echo(
        f"OK: {pfg.application} ({pfg.framework}) — "
        f"{len(pfg.nodes)} nodes, {len(pfg.edges)} edges"
    )


@main.command(name="rules")
@click.argument("pfg_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of a table.")
def run_rules(pfg_path: Path, as_json: bool) -> None:
    """Run the rule baseline against a PFG and print findings."""
    pfg = load_pfg(pfg_path)
    findings = detect_all(pfg)
    if as_json:
        click.echo(json.dumps([f.to_dict() for f in findings], indent=2))
        return
    if not findings:
        click.echo("No findings.")
        return
    for f in findings:
        click.echo(f"[{f.subtype.value:13}] {f.endpoint_id:20} -> {f.data_access_id or '-':12}  {f.explanation}")


@main.command(name="build")
@click.argument("project_root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--out", "out_path", type=click.Path(dir_okay=False, path_type=Path), required=True)
@click.option("--app", "app_name", default=None, help="Application name (default: project dir name).")
@click.option("--framework", default="django", type=click.Choice(["django", "spring"]))
def build_cmd(project_root: Path, out_path: Path, app_name: str | None, framework: str) -> None:
    """Build a PFG by statically analyzing PROJECT_ROOT and write it to --out."""
    if framework == "django":
        from pfg.extractors.django.build import build_pfg

        pfg = build_pfg(project_root, application=app_name)
    elif framework == "spring":
        from pfg.extractors.spring.build import build_pfg as build_spring

        pfg = build_spring(project_root, application=app_name)
    else:  # pragma: no cover - guarded by click.Choice
        raise click.BadParameter(f"unsupported framework: {framework}")
    save_pfg(pfg, out_path)
    click.echo(f"OK: wrote {out_path} — {len(pfg.nodes)} nodes, {len(pfg.edges)} edges")


@main.command(name="dot")
@click.argument("pfg_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def dot_cmd(pfg_path: Path) -> None:
    """Print the PFG as a Graphviz DOT description to stdout."""
    from pfg.pfg.viz import to_dot

    pfg = load_pfg(pfg_path)
    click.echo(to_dot(pfg), nl=False)


@main.command(name="viz")
@click.argument("pfg_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--out", "out_path", type=click.Path(dir_okay=False, path_type=Path), required=True)
@click.option("--format", "fmt", default="png", show_default=True)
def viz_cmd(pfg_path: Path, out_path: Path, fmt: str) -> None:
    """Render the PFG to an image using Graphviz."""
    from pfg.pfg.viz import render

    pfg = load_pfg(pfg_path)
    rendered = render(pfg, out_path, format=fmt)
    click.echo(f"OK: rendered {rendered}")


@main.command(name="train")
@click.option("--n", "n_samples", default=600, show_default=True, type=int)
@click.option("--epochs", default=30, show_default=True, type=int)
@click.option("--seed", default=0, show_default=True, type=int)
@click.option("--batch-size", default=32, show_default=True, type=int)
@click.option("--hidden-dim", default=64, show_default=True, type=int)
@click.option("--num-layers", default=3, show_default=True, type=int)
@click.option("--heads", default=4, show_default=True, type=int)
@click.option("--mlflow", "use_mlflow", is_flag=True, help="Log to MLflow.")
@click.option("--out", "out_path", type=click.Path(dir_okay=False, path_type=Path), default=None)
def train_cmd(
    n_samples: int,
    epochs: int,
    seed: int,
    batch_size: int,
    hidden_dim: int,
    num_layers: int,
    heads: int,
    use_mlflow: bool,
    out_path: Path | None,
) -> None:
    """Train both GNN models on synthetic data and benchmark vs the rule baseline."""
    from pfg.training import run_experiment

    report = run_experiment(
        n_samples=n_samples,
        seed=seed,
        epochs=epochs,
        batch_size=batch_size,
        hidden_dim=hidden_dim,
        num_layers=num_layers,
        heads=heads,
        use_mlflow=use_mlflow,
        out_path=out_path,
    )
    click.echo(f"=== Phase 3 W15: synthetic-data benchmark (n={report.n_samples}, seed={report.seed}) ===")
    a = report.anomaly
    p = report.path_analyzer
    r = report.rule_baseline
    click.echo(f"Model A (anomaly):     acc={a['test_accuracy']:.3f}  macroF1={a['test_macro_f1']:.3f}")
    click.echo(f"Model B (path/subtype): acc={p['test_accuracy']:.3f}  macroF1={p['test_macro_f1']:.3f}")
    click.echo(
        "Rule baseline:         "
        f"binary acc={r['test_accuracy_binary']:.3f}  binary macroF1={r['test_macro_f1_binary']:.3f}  "
        f"subtype acc={r['test_accuracy_subtype']:.3f}  subtype macroF1={r['test_macro_f1_subtype']:.3f}"
    )
    if out_path is not None:
        click.echo(f"Wrote report -> {out_path}")


@main.command(name="sweep")
@click.option("--n", "n_samples", default=300, show_default=True, type=int)
@click.option("--epochs", default=15, show_default=True, type=int)
@click.option("--seed", default=0, show_default=True, type=int)
@click.option("--batch-size", default=32, show_default=True, type=int)
@click.option("--mlflow", "use_mlflow", is_flag=True, help="Log to MLflow.")
@click.option(
    "--out", "out_path", type=click.Path(dir_okay=False, path_type=Path), default=None
)
@click.option(
    "--ablations/--no-ablations",
    default=True,
    show_default=True,
    help="Also run W17 ablation studies.",
)
def sweep_cmd(
    n_samples: int,
    epochs: int,
    seed: int,
    batch_size: int,
    use_mlflow: bool,
    out_path: Path | None,
    ablations: bool,
) -> None:
    """Phase 3 W16+W17: hyperparameter sweep + ablation studies."""
    from pfg.synthetic import generate_dataset
    from pfg.training import report_to_dict, run_ablations, run_hparam_sweep

    samples = generate_dataset(n_samples, seed=seed)
    sweep = run_hparam_sweep(
        samples, epochs=epochs, batch_size=batch_size, seed=seed, use_mlflow=use_mlflow
    )
    abl = (
        run_ablations(
            samples, epochs=epochs, batch_size=batch_size, seed=seed, use_mlflow=use_mlflow
        )
        if ablations
        else []
    )
    click.echo("=== W16 hyperparameter sweep ===")
    for e in sweep.grid:
        click.echo(
            f"lr={e.config['lr']:.0e} h={e.config['hidden_dim']} L={e.config['num_layers']} "
            f"  A_f1={e.anomaly['test_macro_f1']:.3f}  B_f1={e.path_analyzer['test_macro_f1']:.3f}"
        )
    click.echo(f"BEST A: {sweep.best_anomaly['config']}  f1={sweep.best_anomaly['test_macro_f1']:.3f}")
    click.echo(f"BEST B: {sweep.best_path_analyzer['config']}  f1={sweep.best_path_analyzer['test_macro_f1']:.3f}")
    if abl:
        click.echo("=== W17 ablations ===")
        for o in abl:
            click.echo(
                f"{o.ablation:25} A_f1={o.anomaly['test_macro_f1']:.3f}  "
                f"B_f1={o.path_analyzer['test_macro_f1']:.3f}"
            )
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report_to_dict(sweep, abl), indent=2), encoding="utf-8")
        click.echo(f"Wrote sweep report -> {out_path}")


@main.command(name="train-and-save")
@click.option("--n", "n_samples", default=600, show_default=True, type=int)
@click.option("--epochs", default=30, show_default=True, type=int)
@click.option("--seed", default=0, show_default=True, type=int)
@click.option("--hidden-dim", default=64, show_default=True, type=int)
@click.option("--num-layers", default=2, show_default=True, type=int)
@click.option("--heads", default=4, show_default=True, type=int)
@click.option(
    "--out-anomaly",
    type=click.Path(dir_okay=False, path_type=Path),
    default=Path("artifacts/anomaly.pt"),
    show_default=True,
)
@click.option(
    "--out-path",
    "out_path_model",
    type=click.Path(dir_okay=False, path_type=Path),
    default=Path("artifacts/path_analyzer.pt"),
    show_default=True,
)
def train_and_save_cmd(
    n_samples: int,
    epochs: int,
    seed: int,
    hidden_dim: int,
    num_layers: int,
    heads: int,
    out_anomaly: Path,
    out_path_model: Path,
) -> None:
    """Train both GNN models on synthetic data and persist checkpoints."""
    from pfg.models.checkpoint import save_model
    from pfg.synthetic import generate_dataset
    from pfg.training import train_anomaly_detector, train_path_analyzer

    samples = generate_dataset(n_samples, seed=seed)
    am, am_metrics = train_anomaly_detector(
        samples, epochs=epochs, hidden_dim=hidden_dim, num_layers=num_layers, seed=seed
    )
    pm, pm_metrics = train_path_analyzer(
        samples,
        epochs=epochs,
        hidden_dim=hidden_dim,
        num_layers=num_layers,
        heads=heads,
        seed=seed,
    )
    save_model(am, out_anomaly, kind="anomaly", hparams={"hidden_dim": hidden_dim, "num_layers": num_layers})
    save_model(
        pm,
        out_path_model,
        kind="path",
        hparams={"hidden_dim": hidden_dim, "num_layers": num_layers, "heads": heads},
    )
    click.echo(f"Anomaly: f1={am_metrics.test_macro_f1:.3f} -> {out_anomaly}")
    click.echo(f"Path:    f1={pm_metrics.test_macro_f1:.3f} -> {out_path_model}")


@main.command(name="eval")
@click.argument("corpus_root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--detector",
    type=click.Choice(["rule", "gnn", "external"]),
    default="rule",
    show_default=True,
)
@click.option("--checkpoint", type=click.Path(exists=True, dir_okay=False, path_type=Path), default=None)
@click.option(
    "--external-findings",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="JSON file with external-tool findings (Semgrep / CodeQL adapter).",
)
@click.option("--out", "out_path", type=click.Path(dir_okay=False, path_type=Path), default=None)
def eval_cmd(
    corpus_root: Path,
    detector: str,
    checkpoint: Path | None,
    external_findings: Path | None,
    out_path: Path | None,
) -> None:
    """Phase 4: evaluate a detector on a real-world corpus of manifests."""
    from pfg.eval import (
        Detector,
        discover_manifests,
        evaluate_corpus,
        external_findings_detector,
        gnn_detector,
        report_to_dict,
        rule_detector,
    )

    manifests = discover_manifests(corpus_root)
    if not manifests:
        raise click.ClickException(f"no manifest.yaml found under {corpus_root}")

    if detector == "rule":
        det: Detector = rule_detector
        name = "rule_baseline"
    elif detector == "gnn":
        if checkpoint is None:
            raise click.UsageError("--checkpoint is required when --detector gnn")
        from pfg.models.checkpoint import load_model

        model, _ = load_model(checkpoint)
        det = gnn_detector(model)
        name = f"gnn::{checkpoint.name}"
    else:  # external
        if external_findings is None:
            raise click.UsageError("--external-findings is required when --detector external")
        det = external_findings_detector(external_findings)
        name = f"external::{external_findings.name}"

    report = evaluate_corpus(manifests, det, detector_name=name)
    click.echo(f"=== Phase 4 eval ({name}) — {len(report.apps)} apps ===")
    click.echo(f"micro precision={report.micro_precision:.3f}  recall={report.micro_recall:.3f}  f1={report.micro_f1:.3f}")
    for a in report.apps:
        click.echo(
            f"  {a.application:30}  TP={a.tp} FP={a.fp} FN={a.fn}  "
            f"P={a.precision:.2f} R={a.recall:.2f} F1={a.f1:.2f}"
        )
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report_to_dict(report), indent=2), encoding="utf-8")
        click.echo(f"Wrote eval report -> {out_path}")


@main.command(name="corpus-fetch")
@click.argument("corpus_root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--force", is_flag=True, help="Fetch updates even when a checkout already exists.")
def corpus_fetch_cmd(corpus_root: Path, force: bool) -> None:
    """Fetch pinned source checkouts for every real-corpus manifest."""
    from pfg.corpus import fetch_corpus

    paths = fetch_corpus(corpus_root, force=force)
    for path in paths:
        click.echo(f"OK: {path}")


@main.command(name="corpus-validate")
@click.argument("corpus_root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--out", "out_path", type=click.Path(dir_okay=False, path_type=Path), default=None)
def corpus_validate_cmd(corpus_root: Path, out_path: Path | None) -> None:
    """Validate real-corpus manifests, source checkouts, labels, and detector coverage."""
    from pfg.corpus import validate_corpus, validation_report_to_dict

    report = validate_corpus(corpus_root)
    data = validation_report_to_dict(report)

    click.echo(f"=== Real corpus validation — {report.manifest_count} manifests ===")
    click.echo(f"status={'OK' if report.ok else 'FAILED'}")
    if report.errors:
        for err in report.errors:
            click.echo(f"ERROR: {err}")

    classes = " ".join(f"{label}={count}" for label, count in report.class_distribution.items())
    click.echo(f"class distribution: {classes}")
    click.echo("split groups:")
    if report.split_groups:
        for group, apps in report.split_groups.items():
            click.echo(f"  {group}: {', '.join(apps)}")
    else:
        click.echo("  (none)")

    for validation in report.manifests:
        status = "OK" if validation.ok else "FAIL"
        click.echo(
            f"  {status:4} {validation.application:30} "
            f"endpoints={validation.endpoint_count} expected={validation.expected_endpoint_count} "
            f"missing={len(validation.missing_expected_endpoints)} "
            f"unlabeled_findings={len(validation.unlabeled_detector_findings)}"
        )
        for err in validation.errors:
            click.echo(f"       ERROR: {err}")
        for warning in validation.warnings:
            click.echo(f"       WARN: {warning}")

    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        click.echo(f"Wrote validation report -> {out_path}")

    if not report.ok:
        raise click.ClickException("corpus validation failed")


@main.command(name="train-corpus")
@click.argument("corpus_root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--holdout-group", default=None, help="Dataset split group to reserve for test.")
@click.option("--epochs", default=30, show_default=True, type=int)
@click.option("--seed", default=0, show_default=True, type=int)
@click.option("--batch-size", default=32, show_default=True, type=int)
@click.option("--hidden-dim", default=64, show_default=True, type=int)
@click.option("--num-layers", default=3, show_default=True, type=int)
@click.option("--heads", default=4, show_default=True, type=int)
@click.option(
    "--out-model",
    type=click.Path(dir_okay=False, path_type=Path),
    default=Path("artifacts/path_analyzer_real.pt"),
    show_default=True,
)
@click.option("--out-report", type=click.Path(dir_okay=False, path_type=Path), default=None)
def train_corpus_cmd(
    corpus_root: Path,
    holdout_group: str | None,
    epochs: int,
    seed: int,
    batch_size: int,
    hidden_dim: int,
    num_layers: int,
    heads: int,
    out_model: Path,
    out_report: Path | None,
) -> None:
    """Train Model B on manifest-labeled real corpus samples with group splits."""
    from pfg.eval.manifest import discover_manifests
    from pfg.models.checkpoint import save_model
    from pfg.training import (
        samples_from_manifests,
        split_manifests_by_group,
        train_path_analyzer_split,
    )

    manifests = discover_manifests(corpus_root)
    train_m, val_m, test_m = split_manifests_by_group(
        manifests, seed=seed, holdout_group=holdout_group
    )
    if not train_m or not val_m or not test_m:
        raise click.ClickException(
            "Need non-empty train/val/test manifest groups. Add more real apps "
            "or pass a holdout group after at least three groups exist."
        )

    train_samples = samples_from_manifests(train_m)
    val_samples = samples_from_manifests(val_m)
    test_samples = samples_from_manifests(test_m)
    model, metrics = train_path_analyzer_split(
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

    out_model.parent.mkdir(parents=True, exist_ok=True)
    save_model(
        model,
        out_model,
        kind="path",
        hparams={"hidden_dim": hidden_dim, "num_layers": num_layers, "heads": heads},
    )

    report_data = {
        "train_groups": [m.dataset_split_group or m.application for m in train_m],
        "val_groups": [m.dataset_split_group or m.application for m in val_m],
        "test_groups": [m.dataset_split_group or m.application for m in test_m],
        "n_train_samples": len(train_samples),
        "n_val_samples": len(val_samples),
        "n_test_samples": len(test_samples),
        "test_accuracy": metrics.test_accuracy,
        "test_macro_f1": metrics.test_macro_f1,
        "confusion": metrics.confusion,
    }
    click.echo(f"Model B real-corpus test accuracy={metrics.test_accuracy:.3f}")
    click.echo(f"Model B real-corpus test macro-F1={metrics.test_macro_f1:.3f}")
    click.echo(f"Saved model -> {out_model}")
    if out_report is not None:
        out_report.parent.mkdir(parents=True, exist_ok=True)
        out_report.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
        click.echo(f"Wrote report -> {out_report}")


@main.command(name="final-experiment")
@click.argument("corpus_root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--holdout-group", default=None, help="Dataset split group to reserve for test.")
@click.option("--epochs", default=30, show_default=True, type=int)
@click.option("--pretrain-epochs", default=20, show_default=True, type=int)
@click.option("--seed", default=0, show_default=True, type=int)
@click.option("--batch-size", default=32, show_default=True, type=int)
@click.option("--hidden-dim", default=64, show_default=True, type=int)
@click.option("--num-layers", default=3, show_default=True, type=int)
@click.option("--heads", default=4, show_default=True, type=int)
@click.option("--focal-gamma", default=2.0, show_default=True, type=float)
@click.option("--augmentation-cap", default=10, show_default=True, type=int)
@click.option("--weak-supervision/--no-weak-supervision", default=False, show_default=True)
@click.option("--weak-supervision-cap", default=32, show_default=True, type=int)
@click.option("--contrastive-pairs", default=150, show_default=True, type=int)
@click.option(
    "--out-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("artifacts"),
    show_default=True,
)
@click.option(
    "--semgrep-findings",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional normalized endpoint-level Semgrep findings JSON.",
)
@click.option(
    "--codeql-findings",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional normalized endpoint-level CodeQL findings JSON.",
)
def final_experiment_cmd(
    corpus_root: Path,
    holdout_group: str | None,
    epochs: int,
    pretrain_epochs: int,
    seed: int,
    batch_size: int,
    hidden_dim: int,
    num_layers: int,
    heads: int,
    focal_gamma: float,
    augmentation_cap: int,
    weak_supervision: bool,
    weak_supervision_cap: int,
    contrastive_pairs: int,
    out_dir: Path,
    semgrep_findings: Path | None,
    codeql_findings: Path | None,
) -> None:
    """Run the final real-corpus Model B comparison: real-only vs augmented vs two-stage."""
    from pfg.training.final import run_final_experiment

    try:
        outputs = run_final_experiment(
            corpus_root,
            holdout_group=holdout_group,
            epochs=epochs,
            pretrain_epochs=pretrain_epochs,
            seed=seed,
            batch_size=batch_size,
            hidden_dim=hidden_dim,
            num_layers=num_layers,
            heads=heads,
            focal_gamma=focal_gamma,
            augmentation_cap=augmentation_cap,
            weak_supervision=weak_supervision,
            weak_supervision_cap=weak_supervision_cap,
            contrastive_pairs=contrastive_pairs,
            out_dir=out_dir,
            semgrep_findings=semgrep_findings,
            codeql_findings=codeql_findings,
        )
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    real = outputs.metrics["models"]["path_analyzer_real_only"]
    aug = outputs.metrics["models"]["path_analyzer_real_augmented"]
    ts = outputs.metrics["models"]["path_analyzer_twostage"]
    delta_aug = outputs.metrics["models"]["real_augmented_delta"]
    delta_ts = outputs.metrics["models"]["twostage_delta"]
    click.echo("=== Final PathAnalyzer real-corpus experiment (v2) ===")
    click.echo(
        f"real-only:        acc={real['accuracy']:.3f} macroF1={real['macro_f1']:.3f}"
    )
    click.echo(
        f"real+augmented:   acc={aug['accuracy']:.3f} macroF1={aug['macro_f1']:.3f}"
    )
    click.echo(
        f"two-stage:        acc={ts['accuracy']:.3f} macroF1={ts['macro_f1']:.3f}"
    )
    click.echo(
        f"augmentation delta: macroF1={delta_aug['macro_f1']:+.3f} "
        f"vuln_recall={delta_aug['vulnerability_recall']:+.3f}"
    )
    click.echo(
        f"two-stage delta:    macroF1={delta_ts['macro_f1']:+.3f} "
        f"vuln_recall={delta_ts['vulnerability_recall']:+.3f}"
    )
    for warning in outputs.metrics.get("warnings", []):
        click.echo(f"WARNING: {warning}")
    click.echo(f"Saved real-only model -> {outputs.real_only_model_path}")
    click.echo(f"Saved augmented model -> {outputs.augmented_model_path}")
    if outputs.twostage_model_path:
        click.echo(f"Saved two-stage model -> {outputs.twostage_model_path}")
    click.echo(f"Wrote metrics -> {outputs.metrics_path}")
    click.echo(f"Wrote report -> {outputs.report_path}")


@main.command(name="synthetic-experiment")
@click.argument("corpus_root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--n-apps", default=15, show_default=True, type=int, help="Number of synthetic apps to generate.")
@click.option("--min-endpoints", default=30, show_default=True, type=int)
@click.option("--max-endpoints", default=70, show_default=True, type=int)
@click.option("--vuln-ratio", default=0.35, show_default=True, type=float)
@click.option("--epochs", default=40, show_default=True, type=int)
@click.option("--seed", default=0, show_default=True, type=int)
@click.option("--batch-size", default=32, show_default=True, type=int)
@click.option("--hidden-dim", default=64, show_default=True, type=int)
@click.option("--num-layers", default=3, show_default=True, type=int)
@click.option("--heads", default=4, show_default=True, type=int)
@click.option("--focal-gamma", default=2.0, show_default=True, type=float)
@click.option("--gnn-threshold", default=0.5, show_default=True, type=float)
@click.option(
    "--out-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("artifacts"),
    show_default=True,
)
def synthetic_experiment_cmd(
    corpus_root: Path,
    n_apps: int,
    min_endpoints: int,
    max_endpoints: int,
    vuln_ratio: float,
    epochs: int,
    seed: int,
    batch_size: int,
    hidden_dim: int,
    num_layers: int,
    heads: int,
    focal_gamma: float,
    gnn_threshold: float,
    out_dir: Path,
) -> None:
    """Train GNN on synthetic data, evaluate on all real apps."""
    from pfg.training.synthetic_experiment import run_synthetic_experiment

    try:
        outputs = run_synthetic_experiment(
            corpus_root,
            n_apps=n_apps,
            endpoints_per_app=(min_endpoints, max_endpoints),
            vuln_ratio=vuln_ratio,
            epochs=epochs,
            seed=seed,
            batch_size=batch_size,
            hidden_dim=hidden_dim,
            num_layers=num_layers,
            heads=heads,
            focal_gamma=focal_gamma,
            gnn_threshold=gnn_threshold,
            out_dir=out_dir,
        )
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    sm = outputs.metrics["synthetic_test_metrics"]
    gnn = outputs.metrics["real_evaluation"]["gnn_synthetic"]
    rule = outputs.metrics["real_evaluation"]["rule_baseline"]
    sm_vuln = sm["vulnerability_finding"]

    click.echo("=== Synthetic-Only Training → Real-World Evaluation ===")
    click.echo(f"Synthetic dataset: {outputs.metrics['synthetic_dataset']['total_samples']} samples")
    click.echo(f"  Synthetic test: acc={sm['accuracy']:.3f} macroF1={sm['macro_f1']:.3f} "
               f"vuln_P={sm_vuln['precision']:.3f} vuln_R={sm_vuln['recall']:.3f}")
    click.echo(f"Real-world GNN:   P={gnn['micro_precision']:.3f} R={gnn['micro_recall']:.3f} F1={gnn['micro_f1']:.3f}")
    click.echo(f"Real-world Rule:  P={rule['micro_precision']:.3f} R={rule['micro_recall']:.3f} F1={rule['micro_f1']:.3f}")

    for app in gnn.get("apps", []):
        click.echo(f"  GNN  {app['application']}: TP={app['tp']} FP={app['fp']} FN={app['fn']}")
    for app in rule.get("apps", []):
        click.echo(f"  Rule {app['application']}: TP={app['tp']} FP={app['fp']} FN={app['fn']}")

    click.echo(f"Saved model -> {outputs.model_path}")
    click.echo(f"Wrote metrics -> {outputs.metrics_path}")
    click.echo(f"Wrote report -> {outputs.report_path}")


@main.command(name="bridging-experiment")
@click.argument("corpus_root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--synth-model", type=click.Path(exists=True, dir_okay=False, path_type=Path), default=None, help="Path to synthetic-pretrained model checkpoint.")
@click.option("--n-synth-apps", default=5, show_default=True, type=int, help="Synthetic apps for vuln anchors.")
@click.option("--synth-vuln-ratio", default=0.8, show_default=True, type=float, help="Vuln ratio in anchor apps.")
@click.option("--epochs", default=15, show_default=True, type=int)
@click.option("--lr", default=5e-5, show_default=True, type=float)
@click.option("--focal-gamma", default=2.0, show_default=True, type=float)
@click.option("--batch-size", default=16, show_default=True, type=int)
@click.option("--gnn-threshold", default=0.5, show_default=True, type=float)
@click.option("--seed", default=0, show_default=True, type=int)
@click.option(
    "--out-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("artifacts/bridging-v1"),
    show_default=True,
)
def bridging_experiment_cmd(
    corpus_root: Path,
    synth_model: Path | None,
    n_synth_apps: int,
    synth_vuln_ratio: float,
    epochs: int,
    lr: float,
    focal_gamma: float,
    batch_size: int,
    gnn_threshold: float,
    seed: int,
    out_dir: Path,
) -> None:
    """Fine-tune synthetic-pretrained GNN on real data + synth vuln anchors."""
    from pfg.training.bridging_experiment import run_bridging_experiment

    try:
        outputs = run_bridging_experiment(
            corpus_root,
            synth_model_path=synth_model,
            n_synth_apps=n_synth_apps,
            synth_vuln_ratio=synth_vuln_ratio,
            epochs=epochs,
            lr=lr,
            focal_gamma=focal_gamma,
            batch_size=batch_size,
            gnn_threshold=gnn_threshold,
            seed=seed,
            out_dir=out_dir,
        )
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    agg = outputs.metrics["aggregate"]
    cfg = outputs.metrics["config"]
    click.echo("=== Bridging: Synthetic Pretrain → Mixed Fine-tune ===")
    click.echo(f"Synth vuln anchors: {cfg['synth_vuln_anchors']} samples")
    click.echo("")
    click.echo("Aggregate (leave-one-app-out):")
    for name, key in [("Fine-tuned", "finetuned"), ("FT+validated", "finetuned_validated"), ("Synth-only", "synthetic_only"), ("Synth+valid", "synthetic_validated"), ("Rule", "rule_baseline")]:
        a = agg[key]
        click.echo(f"  {name:12s}  TP={a['tp']}  FP={a['fp']}  FN={a['fn']}  "
                    f"P={a['precision']:.3f}  R={a['recall']:.3f}  F1={a['f1']:.3f}")
    click.echo("")
    for fold in outputs.metrics["folds"]:
        click.echo(f"Fold holdout={fold['fold']} "
                    f"(real={fold['n_train_real']}+synth={fold['n_train_synth_vuln']}, "
                    f"val={fold['n_val']}, test={fold['n_test']}):")
        for sys_key, label in [("finetuned", "FT"), ("finetuned_validated", "FT+val"), ("synthetic_only", "Syn"), ("synthetic_validated", "Syn+v"), ("rule_baseline", "Rule")]:
            for app in fold[sys_key]["apps"]:
                click.echo(f"  {label:5s} {app['application']}: TP={app['tp']} FP={app['fp']} FN={app['fn']}")

    click.echo(f"\nWrote metrics -> {outputs.metrics_path}")
    click.echo(f"Wrote report -> {outputs.report_path}")


@main.command(name="normalize")
@click.argument(
    "tool", type=click.Choice(["semgrep", "codeql"])
)
@click.argument(
    "findings_path", type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
@click.option(
    "--manifest",
    "manifest_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Manifest of the app the findings were produced against.",
)
@click.option(
    "--out",
    "out_path",
    type=click.Path(dir_okay=False, path_type=Path),
    required=True,
    help="Where to write normalized [{endpoint_id, subtype}, ...] JSON.",
)
def normalize_cmd(tool: str, findings_path: Path, manifest_path: Path, out_path: Path) -> None:
    """Normalize Semgrep / CodeQL output into the eval-harness JSON format."""
    from pfg.eval import load_manifest, normalize_codeql, normalize_semgrep, write_normalized
    from pfg.extractors.django.build import build_pfg

    m = load_manifest(manifest_path)
    pfg = build_pfg(m.project_root, application=m.application)
    if tool == "semgrep":
        records = normalize_semgrep(findings_path, pfg)
    else:
        records = normalize_codeql(findings_path, pfg)
    written = write_normalized(records, out_path)
    click.echo(f"Wrote {len(records)} normalized findings -> {written}")


@main.command(name="benchmark")
@click.option(
    "--corpus",
    "corpus_root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Optional corpus root: every immediate subdir is treated as a Django app.",
)
@click.option(
    "--app",
    "extra_apps",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    multiple=True,
    help="Extra app root(s) to benchmark (repeatable).",
)
@click.option(
    "--batch-sizes",
    default="1,4,16,64,256",
    show_default=True,
    help="Comma-separated PyG batch sizes for inference timing.",
)
@click.option("--skip-inference", is_flag=True, help="Skip GNN inference timing.")
@click.option(
    "--out",
    "out_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Where to write the JSON scalability report.",
)
def benchmark_cmd(
    corpus_root: Path | None,
    extra_apps: tuple[Path, ...],
    batch_sizes: str,
    skip_inference: bool,
    out_path: Path | None,
) -> None:
    """W22: measure extractor + GNN-inference wall time vs graph size."""
    from pfg.benchmarks import report_to_dict, run_scalability, write_report

    sizes = tuple(int(x) for x in batch_sizes.split(",") if x.strip())
    report = run_scalability(
        corpus_root=corpus_root,
        extra_app_roots=list(extra_apps),
        batch_sizes=sizes,
        skip_inference=skip_inference,
    )
    click.echo(f"extractor rows: {len(report.extractor_rows)}")
    for r in report.extractor_rows:
        click.echo(
            f"  {r.label:30s}  loc={r.loc:6d}  nodes={r.n_nodes:5d}  "
            f"edges={r.n_edges:5d}  t={r.seconds*1000:.1f} ms"
        )
    click.echo(f"inference rows: {len(report.inference_rows)}")
    for r in report.inference_rows:
        click.echo(
            f"  {r.label:20s}  nodes={r.n_nodes:6d}  edges={r.n_edges:6d}  "
            f"t/graph={r.seconds_per_graph*1000:.2f} ms"
        )
    if out_path is not None:
        written = write_report(report, out_path)
        click.echo(f"Wrote scalability report -> {written}")
    else:
        click.echo(json.dumps(report_to_dict(report), indent=2))


@main.command(name="analyze-errors")
@click.argument(
    "corpus_root", type=click.Path(exists=True, file_okay=False, path_type=Path)
)
@click.option(
    "--detector",
    "detector_kind",
    type=click.Choice(["rule", "external"]),
    default="rule",
    show_default=True,
)
@click.option(
    "--external-findings",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Required when --detector external.",
)
@click.option(
    "--out",
    "out_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Where to write the JSON error-analysis report.",
)
def analyze_errors_cmd(
    corpus_root: Path,
    detector_kind: str,
    external_findings: Path | None,
    out_path: Path | None,
) -> None:
    """W23: classify FP/FN as extraction/model/label/intentional errors."""
    from pfg.eval import (
        Detector,
        analyze_corpus,
        discover_manifests,
        external_findings_detector,
        rule_detector,
    )
    from pfg.eval.error_analysis import report_to_dict, write_report

    manifests = discover_manifests(corpus_root)
    if detector_kind == "external":
        if external_findings is None:
            raise click.UsageError("--external-findings required with --detector external")
        det: Detector = external_findings_detector(external_findings)
        name = "external"
    else:
        det = rule_detector
        name = "rule_baseline"

    report = analyze_corpus(manifests, det, detector_name=name)
    click.echo(f"apps analyzed: {len(report.apps)}")
    for app in report.apps:
        click.echo(
            f"  {app.application:30s}  tp={app.tp}  fp={app.fp}  fn={app.fn}  "
            f"counts={app.counts}"
        )
    click.echo(f"totals: {report.totals}")
    if out_path is not None:
        written = write_report(report, out_path)
        click.echo(f"Wrote error analysis report -> {written}")
    else:
        click.echo(json.dumps(report_to_dict(report), indent=2))


@main.command(name="analyze")
@click.argument("project_root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--framework",
    default="django",
    type=click.Choice(["django", "spring"]),
    show_default=True,
)
@click.option("--app", "app_name", default=None, help="Application name override.")
@click.option(
    "--report",
    "report_path",
    type=click.Path(dir_okay=False, path_type=Path),
    required=True,
    help="Where to write the standalone HTML report.",
)
@click.option(
    "--pfg-out",
    "pfg_out",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to also save the underlying PFG JSON.",
)
def analyze_cmd(
    project_root: Path,
    framework: str,
    app_name: str | None,
    report_path: Path,
    pfg_out: Path | None,
) -> None:
    """W26: extract a PFG and produce a standalone HTML report."""
    if framework == "django":
        from pfg.extractors.django.build import build_pfg as _build
    else:
        from pfg.extractors.spring.build import build_pfg as _build

    from pfg.detectors.rule_baseline import detect_all
    from pfg.report import write_report as write_html_report

    pfg = _build(project_root, application=app_name)
    findings = detect_all(pfg)
    if pfg_out is not None:
        save_pfg(pfg, pfg_out)
        click.echo(f"Wrote PFG -> {pfg_out}")
    written = write_html_report(pfg, report_path, findings=findings)
    click.echo(
        f"Analyzed {pfg.application} ({pfg.framework}) — "
        f"{len(pfg.nodes)} nodes, {len(findings)} findings -> {written}"
    )


@main.command(name="dashboard")
@click.argument("corpus_root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--framework",
    default="django",
    type=click.Choice(["django", "spring"]),
    show_default=True,
)
@click.option(
    "--out",
    "out_dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("artifacts/dashboard"),
    show_default=True,
    help="Directory where index.html and per-app reports are written.",
)
@click.option("--title", default=None, help="Optional dashboard title.")
def dashboard_cmd(
    corpus_root: Path,
    framework: str,
    out_dir: Path,
    title: str | None,
) -> None:
    """Build a navigable HTML dashboard for every app under CORPUS_ROOT."""
    from pfg.report.dashboard import build_dashboard

    index = build_dashboard(corpus_root, out_dir, framework=framework, title=title)
    click.echo(f"Wrote dashboard -> {index}")
    click.echo(f"Open in browser:  file:///{index.resolve().as_posix()}")
    click.echo(f"Or serve locally: pfg serve {out_dir}")


@main.command(name="serve")
@click.argument(
    "directory",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=Path("artifacts/dashboard"),
    required=False,
)
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8000, show_default=True, type=int)
def serve_cmd(directory: Path, host: str, port: int) -> None:
    """Serve a directory of HTML reports over a local HTTP server (stdlib only)."""
    import functools
    from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(directory))
    server = ThreadingHTTPServer((host, port), handler)
    url = f"http://{host}:{port}/"
    click.echo(f"Serving {directory} at {url}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        click.echo("\nStopped.")
    finally:
        server.server_close()


@main.command(name="web")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8080, show_default=True, type=int)
def web_cmd(host: str, port: int) -> None:
    """Launch the interactive PFG web UI."""
    from pfg.report.webapp import run

    run(host=host, port=port)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
