"""Tests for the corpus dashboard."""
from __future__ import annotations

from pathlib import Path

from pfg.report.dashboard import (
    DashboardEntry,
    build_dashboard,
    discover_apps,
    render_dashboard,
)

REF = Path(__file__).parents[2] / "benchmarks" / "reference"


def test_render_dashboard_empty() -> None:
    html = render_dashboard([])
    assert "<!doctype html>" in html
    assert "No applications found" in html


def test_render_dashboard_rows() -> None:
    entries = [
        DashboardEntry(app="app_a", framework="django", report_href="app_a.html",
                       n_endpoints=5, n_findings=0),
        DashboardEntry(app="app_b", framework="django", report_href="app_b.html",
                       n_endpoints=3, n_findings=2),
        DashboardEntry(app="broken", framework="django", report_href="",
                       n_endpoints=0, n_findings=0, error="ValueError: oops"),
    ]
    html = render_dashboard(entries, title="Demo")
    assert "Demo" in html
    assert "app_a.html" in html
    assert "CLEAN" in html
    assert "2 findings" in html
    assert "ERROR" in html
    assert "ValueError" in html


def test_discover_apps_single_django() -> None:
    apps = discover_apps(REF / "ref_min", "django")
    assert apps == [REF / "ref_min"]


def test_discover_apps_single_spring() -> None:
    apps = discover_apps(REF / "spring_ref_min", "spring")
    assert apps == [REF / "spring_ref_min"]


def test_build_dashboard_django(tmp_path: Path) -> None:
    import shutil

    corpus = tmp_path / "corpus"
    corpus.mkdir()
    shutil.copytree(REF / "ref_min", corpus / "ref_min")
    out = tmp_path / "dash"
    index = build_dashboard(corpus, out, framework="django", title="Test")
    assert index.exists()
    assert index.name == "index.html"
    text = index.read_text(encoding="utf-8")
    assert "Test" in text
    assert "ref_min" in text
    assert (out / "ref_min.html").exists()


def test_build_dashboard_spring(tmp_path: Path) -> None:
    import shutil

    corpus = tmp_path / "corpus"
    corpus.mkdir()
    shutil.copytree(REF / "spring_ref_min", corpus / "spring_ref_min")
    out = tmp_path / "dash"
    index = build_dashboard(corpus, out, framework="spring")
    assert index.exists()
    assert (out / "spring_ref_min.html").exists()
