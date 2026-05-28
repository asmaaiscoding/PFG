"""PFG Demo Backend — FastAPI server for real-time vulnerability analysis.

Provides:
- GET /api/codebases — list available benchmark apps
- POST /api/analyze/{app_id} — trigger analysis
- WS /ws/analyze/{session_id} — real-time progress updates
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

app = FastAPI(title="PFG Demo", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pre-loaded benchmark apps
CORPUS_ROOT = Path(__file__).parent.parent.parent / "benchmarks" / "realworld"
MODEL_PATH = Path(__file__).parent.parent.parent / "artifacts" / "synthetic-v7" / "path_analyzer_synthetic.pt"

# Cache for analysis sessions
_sessions: dict[str, dict[str, Any]] = {}


def _discover_demo_apps() -> list[dict[str, Any]]:
    """Discover available Django benchmark apps for the demo."""
    from pfg.eval.manifest import discover_manifests

    manifests = [m for m in discover_manifests(CORPUS_ROOT) if m.framework == "django"]

    # Group by base app name
    apps: dict[str, dict[str, Any]] = {}
    for m in manifests:
        base = m.application.rsplit("-cve-", 1)[0] if "-cve-" in m.application else m.application
        if base not in apps:
            apps[base] = {
                "id": base,
                "name": base.replace("-", " ").title(),
                "cves": [],
                "project_root": str(m.project_root),
                "framework": m.framework,
            }
        if "-cve-" in m.application:
            cve_id = "CVE-" + m.application.rsplit("-cve-", 1)[1].replace("-", "-")
            apps[base]["cves"].append(cve_id)

    # Only return apps we want in the demo
    demo_apps = ["django-mdeditor", "nautobot", "wger", "sentry", "weblate", "pretix"]
    return [apps[a] for a in demo_apps if a in apps]


@app.get("/api/codebases")
async def list_codebases():
    """List available codebases for analysis."""
    return _discover_demo_apps()


@app.post("/api/analyze/{app_id}")
async def start_analysis(app_id: str):
    """Start an analysis session. Returns a session_id for WebSocket connection."""
    session_id = str(uuid.uuid4())
    _sessions[session_id] = {"app_id": app_id, "status": "pending", "result": None}
    return {"session_id": session_id, "app_id": app_id}


@app.websocket("/ws/analyze/{session_id}")
async def ws_analyze(websocket: WebSocket, session_id: str):
    """WebSocket endpoint for real-time analysis progress."""
    await websocket.accept()

    session = _sessions.get(session_id)
    if not session:
        await websocket.send_json({"type": "error", "message": "Invalid session"})
        await websocket.close()
        return

    app_id = session["app_id"]
    try:
        await _run_analysis_with_progress(websocket, app_id)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        await websocket.send_json({"type": "error", "message": str(e)})
    finally:
        await websocket.close()


async def _run_analysis_with_progress(ws: WebSocket, app_id: str):
    """Run the full PFG analysis pipeline with real-time progress updates."""
    import warnings
    warnings.filterwarnings("ignore")

    from pfg.eval.manifest import discover_manifests
    from pfg.extractors.django.build import build_pfg
    from pfg.pfg.nodes import NodeType, EdgeType

    # Find the app manifest
    manifests = [m for m in discover_manifests(CORPUS_ROOT)
                 if m.framework == "django" and app_id in m.application]
    if not manifests:
        await ws.send_json({"type": "error", "message": f"App '{app_id}' not found"})
        return

    manifest = manifests[0]  # Use first CVE version
    project_root = manifest.project_root

    # Step 1: Building PFG
    await ws.send_json({
        "type": "progress",
        "step": "building_pfg",
        "message": f"Building Program Flow Graph for {app_id}...",
        "progress": 0.1,
    })
    await asyncio.sleep(0.1)  # Let the message send

    # Run PFG construction (CPU-bound, run in thread)
    loop = asyncio.get_event_loop()
    pfg = await loop.run_in_executor(None, build_pfg, Path(project_root))

    # Step 2: Report graph structure
    nodes_by_type: dict[str, int] = {}
    for n in pfg.nodes:
        nodes_by_type[n.type] = nodes_by_type.get(n.type, 0) + 1

    await ws.send_json({
        "type": "progress",
        "step": "pfg_built",
        "message": f"PFG constructed: {len(pfg.nodes)} nodes, {len(pfg.edges)} edges",
        "progress": 0.4,
        "data": {
            "total_nodes": len(pfg.nodes),
            "total_edges": len(pfg.edges),
            "nodes_by_type": nodes_by_type,
        },
    })

    # Step 3: Send graph data for visualization
    graph_nodes = []
    for n in pfg.nodes:
        node_data = {"id": n.id, "type": n.type}
        if hasattr(n, "attrs") and n.attrs:
            if hasattr(n.attrs, "route"):
                node_data["route"] = n.attrs.route
            if hasattr(n.attrs, "http_method"):
                method = n.attrs.http_method
                node_data["method"] = method.value if hasattr(method, "value") else method
            if hasattr(n.attrs, "requires_auth"):
                node_data["requires_auth"] = n.attrs.requires_auth
        graph_nodes.append(node_data)

    graph_edges = [{"source": e.src, "target": e.dst, "type": e.type} for e in pfg.edges]

    await ws.send_json({
        "type": "graph",
        "nodes": graph_nodes,
        "edges": graph_edges,
    })

    # Step 4: Run GNN inference
    await ws.send_json({
        "type": "progress",
        "step": "gnn_inference",
        "message": "Running GNN vulnerability detection...",
        "progress": 0.6,
    })

    from pfg.eval.harness import validated_gnn_detector
    from pfg.models.checkpoint import load_model

    model, _ = load_model(str(MODEL_PATH))
    model.eval()
    detector = validated_gnn_detector(model, threshold=0.35)

    predictions = await loop.run_in_executor(None, detector, pfg)

    await ws.send_json({
        "type": "progress",
        "step": "gnn_complete",
        "message": f"GNN analysis complete: {len(predictions)} findings after validation",
        "progress": 0.9,
    })

    # Step 5: Format findings
    findings = []
    for ep_id, subtype in predictions:
        # Get endpoint details
        ep_node = next((n for n in pfg.nodes if n.id == ep_id), None)
        finding: dict[str, Any] = {
            "endpoint_id": ep_id,
            "subtype": subtype,
            "severity": _severity(subtype),
        }
        if ep_node and hasattr(ep_node, "attrs") and ep_node.attrs:
            if hasattr(ep_node.attrs, "route"):
                finding["route"] = ep_node.attrs.route
            if hasattr(ep_node.attrs, "http_method"):
                m = ep_node.attrs.http_method
                finding["method"] = m.value if hasattr(m, "value") else m
        findings.append(finding)

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 99))

    await ws.send_json({
        "type": "results",
        "findings": findings,
        "summary": {
            "total_endpoints": nodes_by_type.get(NodeType.ENDPOINT.value, 0),
            "total_findings": len(findings),
            "by_subtype": _count_by_subtype(findings),
        },
        "progress": 1.0,
    })


def _severity(subtype: str) -> str:
    """Map vulnerability subtype to severity level."""
    mapping = {
        "MISSING_AUTH": "CRITICAL",
        "IDOR": "HIGH",
        "TENANT_ISOLATION_FAILURE": "HIGH",
        "OBJECT_LEVEL_PERMISSION_BYPASS": "HIGH",
        "MISSING_ROLE": "MEDIUM",
        "COMBINED": "HIGH",
    }
    return mapping.get(subtype, "MEDIUM")


def _count_by_subtype(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["subtype"]] = counts.get(f["subtype"], 0) + 1
    return counts


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
