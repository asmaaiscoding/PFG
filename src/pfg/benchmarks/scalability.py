"""Phase 4 W22: scalability harness.

Measures (a) PFG-extractor wall time vs LOC and (b) GNN inference wall time
vs graph size, producing a JSON report consumable by the thesis writeup
(plotting deferred — matplotlib is not a project dependency).

Two axes are exercised:

* **Extractor scaling**: time `build_pfg` on Django apps under a corpus
  root (and on the bundled `benchmarks/reference/ref_min`). LOC is counted
  as non-blank, non-comment Python lines under each project root.
* **Inference scaling**: build PyG `Batch` objects of growing size by
  concatenating synthetic samples and time the `PathAnalyzer` forward
  pass (CPU, eval mode). Reports per-graph latency and throughput.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from pfg.extractors.django.build import build_pfg
from pfg.pfg.graph import PFG


@dataclass(frozen=True)
class BenchmarkRow:
    """One measurement (extractor or inference)."""

    kind: str  # "extractor" | "inference"
    label: str  # app name or "synth_batch_<k>"
    loc: int  # python LOC (extractor) or 0 (inference)
    n_nodes: int
    n_edges: int
    n_endpoints: int
    n_graphs: int  # 1 for extractor; batch size for inference
    seconds: float
    seconds_per_graph: float


@dataclass(frozen=True)
class ScalabilityReport:
    """Top-level scalability report."""

    extractor_rows: list[BenchmarkRow]
    inference_rows: list[BenchmarkRow]
    device: str
    torch_available: bool


# --- LOC counting ---------------------------------------------------------


def _count_python_loc(root: Path) -> int:
    total = 0
    for py in root.rglob("*.py"):
        try:
            text = py.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            total += 1
    return total


def _pfg_stats(pfg: PFG) -> tuple[int, int, int]:
    n_endpoints = sum(
        1 for n in pfg.nodes if getattr(n.type, "value", n.type) == "endpoint"
    )
    return len(pfg.nodes), len(pfg.edges), n_endpoints


# --- extractor benchmark --------------------------------------------------


def benchmark_extractor(project_root: Path, *, application: str | None = None) -> BenchmarkRow:
    """Time a single `build_pfg` invocation."""
    root = Path(project_root).resolve()
    app = application or root.name
    loc = _count_python_loc(root)
    t0 = time.perf_counter()
    pfg = build_pfg(root, application=app)
    elapsed = time.perf_counter() - t0
    n_nodes, n_edges, n_endpoints = _pfg_stats(pfg)
    return BenchmarkRow(
        kind="extractor",
        label=app,
        loc=loc,
        n_nodes=n_nodes,
        n_edges=n_edges,
        n_endpoints=n_endpoints,
        n_graphs=1,
        seconds=elapsed,
        seconds_per_graph=elapsed,
    )


def _discover_apps(corpus_root: Path | None) -> list[Path]:
    if corpus_root is None:
        return []
    apps: list[Path] = []
    for child in sorted(corpus_root.iterdir()):
        if not child.is_dir() or child.name.startswith("_") or child.name.startswith("."):
            continue
        # Heuristic: contains at least one *.py and looks like a Django root.
        if any(child.rglob("*.py")):
            apps.append(child)
    return apps


# --- inference benchmark --------------------------------------------------


def _make_path_analyzer(hidden_dim: int = 64, num_layers: int = 3) -> Any:
    from pfg.models.gnn import PathAnalyzer

    return PathAnalyzer(hidden_dim=hidden_dim, num_layers=num_layers)


def benchmark_inference(
    *,
    batch_sizes: tuple[int, ...] = (1, 4, 16, 64, 256),
    seed: int = 0,
    warmup: int = 2,
    repeats: int = 5,
    hidden_dim: int = 64,
    num_layers: int = 3,
) -> list[BenchmarkRow]:
    """Time `PathAnalyzer` forward pass on PyG batches of varying size."""
    import torch
    from torch_geometric.data import Batch

    from pfg.synthetic.dataset import samples_to_pyg
    from pfg.synthetic.generator import generate_dataset

    max_n = max(batch_sizes)
    samples = generate_dataset(max_n, seed=seed)
    pyg_all = samples_to_pyg(samples)
    model = _make_path_analyzer(hidden_dim=hidden_dim, num_layers=num_layers)
    model.eval()

    rows: list[BenchmarkRow] = []
    with torch.no_grad():
        for k in batch_sizes:
            chunk = pyg_all[:k]
            batch = Batch.from_data_list(chunk)

            for _ in range(warmup):
                _ = model(batch)

            t0 = time.perf_counter()
            for _ in range(repeats):
                _ = model(batch)
            elapsed = (time.perf_counter() - t0) / repeats

            n_nodes = int(batch.x.shape[0])
            n_edges = int(batch.edge_index.shape[1])
            rows.append(
                BenchmarkRow(
                    kind="inference",
                    label=f"synth_batch_{k}",
                    loc=0,
                    n_nodes=n_nodes,
                    n_edges=n_edges,
                    n_endpoints=k,
                    n_graphs=k,
                    seconds=elapsed,
                    seconds_per_graph=elapsed / max(k, 1),
                )
            )
    return rows


# --- top-level ------------------------------------------------------------


def run_scalability(
    *,
    corpus_root: Path | None = None,
    extra_app_roots: list[Path] | None = None,
    batch_sizes: tuple[int, ...] = (1, 4, 16, 64, 256),
    skip_inference: bool = False,
    seed: int = 0,
) -> ScalabilityReport:
    """Run the extractor + inference scalability sweeps and return the report."""
    extractor_rows: list[BenchmarkRow] = []

    apps = list(extra_app_roots or [])
    apps.extend(_discover_apps(corpus_root))
    for app_root in apps:
        try:
            extractor_rows.append(benchmark_extractor(app_root))
        except Exception as exc:
            extractor_rows.append(
                BenchmarkRow(
                    kind="extractor",
                    label=f"{app_root.name} [error: {type(exc).__name__}]",
                    loc=0,
                    n_nodes=0,
                    n_edges=0,
                    n_endpoints=0,
                    n_graphs=0,
                    seconds=0.0,
                    seconds_per_graph=0.0,
                )
            )

    inference_rows: list[BenchmarkRow] = []
    torch_available = True
    device = "cpu"
    if not skip_inference:
        try:
            import torch  # noqa: F401

            inference_rows = benchmark_inference(batch_sizes=batch_sizes, seed=seed)
        except ImportError:
            torch_available = False

    return ScalabilityReport(
        extractor_rows=extractor_rows,
        inference_rows=inference_rows,
        device=device,
        torch_available=torch_available,
    )


def report_to_dict(report: ScalabilityReport) -> dict[str, Any]:
    """Convert a `ScalabilityReport` to a JSON-serialisable dict."""
    return {
        "device": report.device,
        "torch_available": report.torch_available,
        "extractor_rows": [asdict(r) for r in report.extractor_rows],
        "inference_rows": [asdict(r) for r in report.inference_rows],
    }


def write_report(report: ScalabilityReport, out_path: Path) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report_to_dict(report), indent=2), encoding="utf-8")
    return out_path
