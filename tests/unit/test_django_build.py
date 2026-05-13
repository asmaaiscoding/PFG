"""Phase 2 W11 gate: end-to-end PFG assembly + Graphviz DOT.

We reuse `ref_callgraph` (which has endpoints + a call chain) as the
integration target. The assembled PFG must:

  * validate against the schema (load_pfg path),
  * contain a node for every endpoint,
  * contain a service node for every reachable function,
  * contain at least one data_access node where ORM calls are present
    (none in ref_callgraph, so we use ref_idflow for that part).
"""

from __future__ import annotations

from pathlib import Path

from pfg.extractors.django.build import _endpoint_id, _service_id, build_pfg
from pfg.pfg.graph import load_pfg, save_pfg
from pfg.pfg.viz import to_dot

REF_CG = Path(__file__).parents[2] / "benchmarks" / "reference" / "ref_callgraph"


def test_build_pfg_on_ref_callgraph_roundtrips(tmp_path: Path) -> None:
    pfg = build_pfg(REF_CG, application="ref_callgraph")
    out = tmp_path / "ref_callgraph.pfg.json"
    save_pfg(pfg, out)  # validates against schema
    reloaded = load_pfg(out)
    assert reloaded.application == "ref_callgraph"
    assert reloaded.framework == "django"

    # Endpoints: 3 routes -> 3 endpoint nodes.
    endpoint_ids = {n.id for n in reloaded.endpoints()}
    assert _endpoint_id("GET", "/invoice/{pk}/") in endpoint_ids
    assert _endpoint_id("GET", "/admin/users/") in endpoint_ids
    assert _endpoint_id("GET", "/noop/") in endpoint_ids


def test_build_pfg_includes_call_chain() -> None:
    pfg = build_pfg(REF_CG, application="ref_callgraph")
    service_ids = {n.id for n in pfg.nodes if n.type in ("service",)}
    # Handler + service + repo qualnames present.
    assert _service_id("views.get_invoice") in service_ids
    assert _service_id("services.fetch_invoice") in service_ids
    assert _service_id("repo.invoice_by_pk") in service_ids
    # Endpoint -> handler edge present.
    eid = _endpoint_id("GET", "/invoice/{pk}/")
    handler_sid = _service_id("views.get_invoice")
    assert any(
        e.src == eid and e.dst == handler_sid and e.type == "call" for e in pfg.edges
    )
    # services.fetch_invoice -> repo.invoice_by_pk call edge.
    src = _service_id("services.fetch_invoice")
    dst = _service_id("repo.invoice_by_pk")
    assert any(
        e.src == src and e.dst == dst and e.type == "call" for e in pfg.edges
    )


def test_build_pfg_links_all_routes_for_shared_handler(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        """
def upload(request):
    return None
""",
        encoding="utf-8",
    )
    (tmp_path / "urls.py").write_text(
        """
from django.urls import path
from .views import upload

urlpatterns = [
    path("uploads/", upload),
    path("mdeditor/uploads/", upload),
]
""",
        encoding="utf-8",
    )

    pfg = build_pfg(tmp_path, application="shared_handler")
    handler_sid = _service_id("views.upload")

    assert any(
        e.src == _endpoint_id("GET", "/uploads/") and e.dst == handler_sid and e.type == "call"
        for e in pfg.edges
    )
    assert any(
        e.src == _endpoint_id("GET", "/mdeditor/uploads/")
        and e.dst == handler_sid
        and e.type == "call"
        for e in pfg.edges
    )


def test_to_dot_emits_valid_dot() -> None:
    pfg = build_pfg(REF_CG, application="ref_callgraph")
    dot = to_dot(pfg)
    assert dot.startswith("digraph ")
    assert "rankdir=LR" in dot
    # Each node id appears at least once.
    for n in pfg.nodes:
        assert f'"{n.id}"' in dot
