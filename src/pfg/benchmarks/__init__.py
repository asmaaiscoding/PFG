"""Phase 4 W22: scalability benchmarks for PFG build + GNN inference."""

from pfg.benchmarks.scalability import (
    BenchmarkRow,
    ScalabilityReport,
    benchmark_extractor,
    benchmark_inference,
    report_to_dict,
    run_scalability,
    write_report,
)

__all__ = [
    "BenchmarkRow",
    "ScalabilityReport",
    "benchmark_extractor",
    "benchmark_inference",
    "report_to_dict",
    "run_scalability",
    "write_report",
]
