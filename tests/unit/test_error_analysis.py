"""Phase 4 W23 tests: error analysis classifier."""
from __future__ import annotations

from pathlib import Path

import yaml

from pfg.eval import (
    Manifest,
    analyze_app,
    analyze_corpus,
    evaluate_app,
    load_manifest,
    rule_detector,
)
from pfg.eval.error_analysis import report_to_dict, write_report
from pfg.synthetic import generate_dataset


def _write_manifest(p: Path, body: dict[str, object]) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(body), encoding="utf-8")
    return p


def _idor_sample() -> object:
    samples = generate_dataset(60, seed=0)
    for s in samples:
        sub = getattr(getattr(s, "label", None), "subtype", None)
        name = sub.value if hasattr(sub, "value") else sub
        if name == "IDOR":
            return s
    raise RuntimeError("no IDOR sample")


def test_analyze_extraction_error(tmp_path: Path) -> None:
    sample = _idor_sample()
    pfg = sample.pfg  # type: ignore[attr-defined]
    manifest = Manifest(
        application="x",
        framework="django",
        source_root=tmp_path,
        expected_findings=[],  # type: ignore[arg-type]
        intentional_public_endpoints=[],
        manifest_path=tmp_path / "manifest.yaml",
    )
    # Inject a synthetic AppScore as if the detector predicted a non-existent endpoint.
    from pfg.eval.harness import AppScore

    score = AppScore(
        application="x",
        tp=0,
        fp=1,
        fn=0,
        precision=0.0,
        recall=0.0,
        f1=0.0,
        predictions=[{"endpoint_id": "ep_does_not_exist", "subtype": "IDOR"}],
        expected=[],
    )
    a = analyze_app(manifest, pfg, score)
    assert a.fp == 1
    assert len(a.errors) == 1
    err = a.errors[0]
    assert err.kind == "fp"
    assert err.category == "extraction_error"
    assert "not in extracted PFG" in err.rationale


def test_analyze_intentional_public_fp(tmp_path: Path) -> None:
    sample = _idor_sample()
    pfg = sample.pfg  # type: ignore[attr-defined]
    target = sample.target_endpoint_id  # type: ignore[attr-defined]
    manifest = Manifest(
        application="x",
        framework="django",
        source_root=tmp_path,
        expected_findings=[],  # type: ignore[arg-type]
        intentional_public_endpoints=[target],
        manifest_path=tmp_path / "manifest.yaml",
    )
    from pfg.eval.harness import AppScore

    score = AppScore(
        application="x",
        tp=0,
        fp=1,
        fn=0,
        precision=0.0,
        recall=0.0,
        f1=0.0,
        predictions=[{"endpoint_id": target, "subtype": "IDOR"}],
        expected=[],
    )
    a = analyze_app(manifest, pfg, score)
    assert a.errors[0].category == "intentional_public"


def test_analyze_label_noise_fn(tmp_path: Path) -> None:
    """Expected MISSING_AUTH on an endpoint whose PFG says requires_auth=True."""
    samples = generate_dataset(120, seed=0)
    safe_sample = next(
        s for s in samples if getattr(s.label, "label", None) == "SAFE"  # type: ignore[attr-defined]
    )
    pfg = safe_sample.pfg
    target = safe_sample.target_endpoint_id

    manifest = Manifest(
        application="x",
        framework="django",
        source_root=tmp_path,
        expected_findings=[],  # populate via dict adapter below
        intentional_public_endpoints=[],
        manifest_path=tmp_path / "manifest.yaml",
    )
    from pfg.eval.harness import AppScore

    score = AppScore(
        application="x",
        tp=0,
        fp=0,
        fn=1,
        precision=0.0,
        recall=0.0,
        f1=0.0,
        predictions=[],
        expected=[{"endpoint_id": target, "subtype": "MISSING_AUTH"}],
    )
    a = analyze_app(manifest, pfg, score)
    assert a.errors[0].kind == "fn"
    # SAFE sample has requires_auth=True (MISSING_AUTH inconsistent with PFG)
    assert a.errors[0].category == "label_noise"


def test_analyze_corpus_end_to_end(tmp_path: Path) -> None:
    sample = _idor_sample()
    pfg = sample.pfg  # type: ignore[attr-defined]
    target = sample.target_endpoint_id  # type: ignore[attr-defined]

    p = _write_manifest(
        tmp_path / "synth" / "manifest.yaml",
        {
            "application": "synth",
            "framework": "django",
            "source_root": ".",
            "expected_findings": [{"endpoint_id": target, "subtype": "IDOR"}],
        },
    )
    m = load_manifest(p)
    # Verify rule baseline gets a TP on this PFG (sanity check the detector wires up).
    score = evaluate_app(m, rule_detector, build=lambda _root: pfg)
    assert score.tp == 1
    # Now run the corpus analyzer with the same fake builder via monkey:
    from pfg.eval import error_analysis as ea

    real_build = ea.build_pfg
    ea.build_pfg = lambda *_a, **_k: pfg  # type: ignore[assignment]
    try:
        report = analyze_corpus([m], rule_detector, detector_name="rule_baseline")
    finally:
        ea.build_pfg = real_build  # type: ignore[assignment]

    assert len(report.apps) == 1
    assert report.apps[0].tp == 1
    # Round-trip JSON.
    out = write_report(report, tmp_path / "errors.json")
    assert out.exists()
    d = report_to_dict(report)
    assert d["detector"] == "rule_baseline"
