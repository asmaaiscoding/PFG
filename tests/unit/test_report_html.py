"""Phase 5 W26 tests: HTML report."""
from __future__ import annotations

from pathlib import Path

from pfg.detectors.rule_baseline import detect_all
from pfg.extractors.django.build import build_pfg as build_django
from pfg.extractors.spring.build import build_pfg as build_spring
from pfg.report import render_report, write_report

REF_DJ = Path(__file__).parents[2] / "benchmarks" / "reference" / "ref_min"
REF_SP = Path(__file__).parents[2] / "benchmarks" / "reference" / "spring_ref_min"


def test_render_report_django_basic() -> None:
    pfg = build_django(REF_DJ, application="ref_min")
    html = render_report(pfg)
    assert "<!doctype html>" in html
    assert "ref_min" in html
    assert "django" in html
    assert "<table>" in html or "No vulnerable" in html
    # Counts must reflect the PFG.
    n_endpoints = sum(
        1 for n in pfg.nodes if getattr(n.type, "value", n.type) == "endpoint"
    )
    assert f">{n_endpoints}<" in html


def test_render_report_spring_with_findings() -> None:
    pfg = build_spring(REF_SP, application="spring_demo")
    findings = detect_all(pfg)
    html = render_report(pfg, findings=findings, title="Spring demo")
    assert "Spring demo" in html
    assert "spring" in html
    if findings:
        # Each finding subtype name should appear at least once.
        for f in findings:
            assert f.subtype.value in html


def test_write_report_creates_file(tmp_path: Path) -> None:
    pfg = build_django(REF_DJ, application="ref_min")
    out = tmp_path / "sub" / "report.html"
    written = write_report(pfg, out)
    assert written.exists()
    text = written.read_text(encoding="utf-8")
    assert text.lstrip().startswith("<!doctype html>")
    # No unsubstituted placeholders.
    assert "{title}" not in text
    assert "{findings_table}" not in text


def test_render_report_escapes_user_data() -> None:
    pfg = build_django(REF_DJ, application="<x&y>")
    html = render_report(pfg)
    assert "&lt;x&amp;y&gt;" in html
    assert "<x&y>" not in html.replace("&lt;x&amp;y&gt;", "")
