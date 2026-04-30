"""Phase 4 W18: manifest loader + eval harness tests."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from pfg.eval import (
    ExpectedFinding,
    evaluate_app,
    evaluate_corpus,
    external_findings_detector,
    load_manifest,
    rule_detector,
)
from pfg.eval.harness import _score_one
from pfg.synthetic import generate_dataset

# --- manifest loader ------------------------------------------------------


def _write_manifest(p: Path, body: dict[str, object]) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(body), encoding="utf-8")
    return p


def test_load_manifest_minimal(tmp_path: Path) -> None:
    p = _write_manifest(
        tmp_path / "app1" / "manifest.yaml",
        {
            "application": "app1",
            "framework": "django",
            "source_root": "src/",
            "expected_findings": [
                {"endpoint_id": "ep_1", "subtype": "IDOR", "url_pattern": "/x/<id>/"}
            ],
        },
    )
    m = load_manifest(p)
    assert m.application == "app1"
    assert m.framework == "django"
    assert m.expected_findings == [
        ExpectedFinding(endpoint_id="ep_1", subtype="IDOR", url_pattern="/x/<id>/")
    ]
    assert m.project_root == (p.parent / "src").resolve()


def test_load_manifest_invalid_subtype(tmp_path: Path) -> None:
    p = _write_manifest(
        tmp_path / "bad" / "manifest.yaml",
        {
            "application": "bad",
            "framework": "django",
            "source_root": ".",
            "expected_findings": [{"endpoint_id": "ep_1", "subtype": "NOT_REAL"}],
        },
    )
    with pytest.raises(ValueError, match="invalid subtype"):
        load_manifest(p)


# --- scoring --------------------------------------------------------------


def test_score_exact_match() -> None:
    expected = [ExpectedFinding("ep_1", "IDOR"), ExpectedFinding("ep_2", "MISSING_AUTH")]
    predicted = {("ep_1", "IDOR"), ("ep_2", "MISSING_AUTH")}
    tp, fp, fn, _ = _score_one(expected, predicted, [])
    assert (tp, fp, fn) == (2, 0, 0)


def test_score_combined_matches_missing_auth() -> None:
    expected = [ExpectedFinding("ep_1", "MISSING_AUTH")]
    predicted = {("ep_1", "COMBINED")}
    tp, fp, fn, notes = _score_one(expected, predicted, [])
    assert (tp, fp, fn) == (1, 0, 0)
    assert any("COMBINED" in n for n in notes)


def test_score_intentional_public_drops_fp() -> None:
    expected: list[ExpectedFinding] = []
    predicted = {("ep_health", "MISSING_AUTH"), ("ep_other", "IDOR")}
    tp, fp, fn, _ = _score_one(expected, predicted, ["ep_health"])
    assert (tp, fp, fn) == (0, 1, 0)


def test_score_partial() -> None:
    expected = [ExpectedFinding("ep_1", "IDOR"), ExpectedFinding("ep_2", "MISSING_ROLE")]
    predicted = {("ep_1", "IDOR"), ("ep_3", "IDOR")}
    tp, fp, fn, _ = _score_one(expected, predicted, [])
    assert (tp, fp, fn) == (1, 1, 1)


# --- end-to-end with synthetic PFG ---------------------------------------


def test_evaluate_app_with_synthetic_idor(tmp_path: Path) -> None:
    """Build a PFG via the synthetic generator; rule baseline should detect IDOR."""
    samples = generate_dataset(60, seed=0)

    def _is_idor(sample: object) -> bool:
        sub = getattr(getattr(sample, "label", None), "subtype", None)
        if sub is None:
            return False
        name = sub.value if hasattr(sub, "value") else sub
        return name == "IDOR"

    idor_sample = next(s for s in samples if _is_idor(s))
    target_id = idor_sample.target_endpoint_id

    p = _write_manifest(
        tmp_path / "synth" / "manifest.yaml",
        {
            "application": "synth",
            "framework": "django",
            "source_root": ".",
            "expected_findings": [{"endpoint_id": target_id, "subtype": "IDOR"}],
        },
    )
    m = load_manifest(p)
    score = evaluate_app(m, rule_detector, build=lambda _root: idor_sample.pfg)
    assert score.tp == 1
    assert score.fn == 0


def test_evaluate_corpus_external_adapter(tmp_path: Path) -> None:
    """The external-findings adapter should reproduce its own JSON content."""
    samples = generate_dataset(20, seed=0)
    sample = samples[0]
    target = sample.target_endpoint_id

    findings_path = tmp_path / "semgrep.json"
    findings_path.write_text(
        '[{"endpoint_id": "' + target + '", "subtype": "IDOR"}]', encoding="utf-8"
    )
    p = _write_manifest(
        tmp_path / "app" / "manifest.yaml",
        {
            "application": "app",
            "framework": "django",
            "source_root": ".",
            "expected_findings": [{"endpoint_id": target, "subtype": "IDOR"}],
        },
    )
    det = external_findings_detector(findings_path)
    report = evaluate_corpus([load_manifest(p)], det, build=lambda _r: sample.pfg)
    assert report.micro_recall == 1.0
    assert report.apps[0].tp == 1


# --- gnn detector + checkpoint round-trip --------------------------------


def test_gnn_detector_and_checkpoint_roundtrip(tmp_path: Path) -> None:
    pytest.importorskip("torch_geometric")
    from pfg.eval import gnn_detector
    from pfg.models.checkpoint import load_model, save_model
    from pfg.training import train_path_analyzer

    samples = generate_dataset(120, seed=0)
    model, _ = train_path_analyzer(
        samples, epochs=4, hidden_dim=16, num_layers=2, heads=2, seed=0
    )
    ckpt = save_model(
        model,
        tmp_path / "path.pt",
        kind="path",
        hparams={"hidden_dim": 16, "num_layers": 2, "heads": 2},
    )
    loaded, payload = load_model(ckpt)
    assert payload["kind"] == "path"

    det = gnn_detector(loaded)
    preds = det(samples[0].pfg)
    assert isinstance(preds, set)
    for ep, sub in preds:
        assert isinstance(ep, str) and sub in {"MISSING_AUTH", "MISSING_ROLE", "IDOR", "COMBINED"}
