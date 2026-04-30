"""Phase 4 W22 tests: scalability harness."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pfg.benchmarks import (
    BenchmarkRow,
    benchmark_extractor,
    report_to_dict,
    run_scalability,
    write_report,
)
from pfg.benchmarks.scalability import _count_python_loc

REF_MIN = Path(__file__).parents[2] / "benchmarks" / "reference" / "ref_min"


def test_count_python_loc_nonempty() -> None:
    loc = _count_python_loc(REF_MIN)
    assert loc > 0


def test_benchmark_extractor_returns_row() -> None:
    row = benchmark_extractor(REF_MIN)
    assert isinstance(row, BenchmarkRow)
    assert row.kind == "extractor"
    assert row.loc > 0
    assert row.n_nodes > 0
    assert row.n_endpoints >= 1
    assert row.seconds >= 0.0
    assert row.seconds_per_graph == row.seconds


def test_run_scalability_skip_inference(tmp_path: Path) -> None:
    report = run_scalability(
        extra_app_roots=[REF_MIN],
        skip_inference=True,
    )
    assert len(report.extractor_rows) == 1
    assert report.inference_rows == []
    out = write_report(report, tmp_path / "report.json")
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["extractor_rows"][0]["label"] == "ref_min"
    assert payload["inference_rows"] == []


def test_run_scalability_with_inference_small_batch() -> None:
    pytest.importorskip("torch")
    pytest.importorskip("torch_geometric")
    report = run_scalability(
        extra_app_roots=[REF_MIN],
        batch_sizes=(1, 4),
        skip_inference=False,
    )
    assert len(report.inference_rows) == 2
    sizes = [r.n_endpoints for r in report.inference_rows]
    assert sizes == [1, 4]
    # Throughput entries must be positive seconds.
    for r in report.inference_rows:
        assert r.seconds > 0.0
        assert r.seconds_per_graph > 0.0
        assert r.n_nodes > 0 and r.n_edges > 0


def test_report_to_dict_round_trip() -> None:
    report = run_scalability(extra_app_roots=[REF_MIN], skip_inference=True)
    d = report_to_dict(report)
    assert set(d) == {"device", "torch_available", "extractor_rows", "inference_rows"}
    assert d["extractor_rows"][0]["kind"] == "extractor"


def test_run_scalability_handles_missing_corpus(tmp_path: Path) -> None:
    # Empty corpus root yields no extractor rows.
    report = run_scalability(corpus_root=tmp_path, skip_inference=True)
    assert report.extractor_rows == []
