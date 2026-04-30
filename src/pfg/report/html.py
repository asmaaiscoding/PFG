"""Phase 5 W26: standalone HTML report generation.

Produces a single self-contained HTML file summarizing a PFG analysis:
metadata, flagged endpoints with explanations, and an embedded SVG of
the graph (or the raw DOT source if Graphviz is not available).

No external runtime dependencies beyond what's already in the project.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pfg.detectors.rule_baseline import Finding, detect_all
from pfg.pfg.graph import PFG
from pfg.pfg.viz import to_dot


@dataclass(frozen=True)
class ReportContext:
    pfg: PFG
    findings: list[Finding]
    title: str
    extra_meta: dict[str, str]


_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>{title}</title>
<style>
  :root {{
    --bg:#0f1115; --fg:#e6e6e6; --muted:#8b95a7;
    --card:#171a21; --border:#262b36; --accent:#7aa2f7;
    --bad:#f7768e; --warn:#e0af68; --ok:#9ece6a;
    --mono: ui-monospace, Menlo, Consolas, monospace;
  }}
  html,body {{ margin:0; padding:0; background:var(--bg); color:var(--fg);
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }}
  main {{ max-width: 1200px; margin: 0 auto; padding: 32px 24px 80px; }}
  h1 {{ font-size: 28px; margin: 0 0 6px; letter-spacing: -0.01em; }}
  .sub {{ color: var(--muted); margin-bottom: 28px; }}
  .grid {{ display:grid; gap:16px; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); margin-bottom:24px; }}
  .card {{ background:var(--card); border:1px solid var(--border); border-radius:10px; padding:14px 16px; }}
  .card .k {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.06em; }}
  .card .v {{ font-size:20px; font-weight:600; margin-top:4px; }}
  table {{ width:100%; border-collapse:collapse; background:var(--card);
    border:1px solid var(--border); border-radius:10px; overflow:hidden; }}
  th, td {{ padding:10px 12px; text-align:left; vertical-align:top;
    border-bottom:1px solid var(--border); font-size:13px; }}
  th {{ background:#1d212b; color:var(--muted); font-weight:600; }}
  tr:last-child td {{ border-bottom:none; }}
  td.mono, code {{ font-family: var(--mono); font-size:12.5px; }}
  .pill {{ display:inline-block; padding:2px 8px; border-radius:999px;
    font-size:11px; font-weight:700; letter-spacing:.04em; }}
  .pill-MISSING_AUTH {{ background:#3a1d22; color:var(--bad); }}
  .pill-MISSING_ROLE {{ background:#3a2a16; color:var(--warn); }}
  .pill-IDOR        {{ background:#3a1d22; color:var(--bad); }}
  .pill-COMBINED    {{ background:#3a1d22; color:var(--bad); }}
  .pill-SAFE        {{ background:#1f2a1c; color:var(--ok); }}
  details {{ background:var(--card); border:1px solid var(--border);
    border-radius:10px; padding:10px 14px; margin-top:24px; }}
  summary {{ cursor:pointer; color:var(--muted); }}
  pre {{ font-family:var(--mono); font-size:12.5px; background:#10131a;
    padding:12px; border-radius:8px; overflow:auto; }}
  .graph {{ background:var(--card); border:1px solid var(--border);
    border-radius:10px; padding:16px; margin-top:16px; overflow:auto; }}
  .graph svg {{ max-width:100%; height:auto; background:#fff; border-radius:6px; }}
  .empty {{ color: var(--muted); padding:14px 0; }}
</style>
</head>
<body>
<main>
  <h1>{title}</h1>
  <div class="sub">{subtitle}</div>

  <div class="grid">
    <div class="card"><div class="k">Application</div><div class="v">{app}</div></div>
    <div class="card"><div class="k">Framework</div><div class="v">{framework}</div></div>
    <div class="card"><div class="k">Endpoints</div><div class="v">{n_endpoints}</div></div>
    <div class="card"><div class="k">Services</div><div class="v">{n_services}</div></div>
    <div class="card"><div class="k">Data accesses</div><div class="v">{n_data}</div></div>
    <div class="card"><div class="k">Findings</div><div class="v">{n_findings}</div></div>
  </div>

  <h2 style="margin-top:24px;">Flagged endpoints</h2>
  {findings_table}

  <h2 style="margin-top:32px;">Privilege Flow Graph</h2>
  <div class="graph">{graph_block}</div>

  <details>
    <summary>Raw PFG (JSON)</summary>
    <pre>{pfg_json}</pre>
  </details>
</main>
</body>
</html>
"""


def _node_counts(pfg: PFG) -> dict[str, int]:
    counts = {"endpoint": 0, "service": 0, "data_access": 0}
    for n in pfg.nodes:
        t = getattr(n.type, "value", n.type)
        if t in counts:
            counts[t] += 1
    return counts


def _endpoint_attr(pfg: PFG, endpoint_id: str) -> dict[str, Any]:
    for n in pfg.nodes:
        if n.id == endpoint_id:
            a = n.attrs.model_dump() if hasattr(n.attrs, "model_dump") else dict(n.attrs)
            return dict(a)
    return {}


def _findings_table_html(pfg: PFG, findings: list[Finding]) -> str:
    if not findings:
        return '<div class="empty">No vulnerable endpoints flagged by the rule baseline.</div>'
    rows: list[str] = []
    for f in findings:
        ep = _endpoint_attr(pfg, f.endpoint_id)
        method = html.escape(str(ep.get("http_method", "")))
        route = html.escape(str(ep.get("route", "")))
        loc = html.escape(str(ep.get("source_location", "") or ""))
        sub = f.subtype.value
        pill = f'<span class="pill pill-{sub}">{sub}</span>'
        rows.append(
            "<tr>"
            f"<td>{pill}</td>"
            f"<td class=mono>{method} <code>{route}</code></td>"
            f"<td class=mono>{html.escape(f.endpoint_id)}</td>"
            f"<td class=mono>{loc}</td>"
            f"<td>{html.escape(f.explanation)}</td>"
            "</tr>"
        )
    return (
        "<table>"
        "<thead><tr><th>Subtype</th><th>Endpoint</th><th>ID</th>"
        "<th>Source</th><th>Why</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )


def _graph_block(pfg: PFG) -> str:
    """Try to render PFG as inline SVG; fall back to <pre> with the DOT source."""
    dot = to_dot(pfg)
    try:
        import graphviz

        src = graphviz.Source(dot)
        svg = str(src.pipe(format="svg").decode("utf-8", errors="ignore"))
        # Strip XML/DOCTYPE preamble so it embeds cleanly.
        idx = svg.find("<svg")
        if idx >= 0:
            svg = svg[idx:]
        return svg
    except Exception:
        return f"<pre>{html.escape(dot)}</pre>"


def render_report(
    pfg: PFG,
    *,
    findings: list[Finding] | None = None,
    title: str | None = None,
    extra_meta: dict[str, str] | None = None,
) -> str:
    """Render a standalone HTML string for `pfg`."""
    f = list(findings) if findings is not None else detect_all(pfg)
    counts = _node_counts(pfg)
    title_str = title or f"PFG report — {pfg.application}"
    subtitle = f"{counts['endpoint']} endpoints · {len(f)} findings"
    if extra_meta:
        subtitle += " · " + " · ".join(f"{k}={v}" for k, v in extra_meta.items())
    pfg_json = html.escape(
        json.dumps(pfg.model_dump(mode="json"), indent=2)
    )
    return _HTML_TEMPLATE.format(
        title=html.escape(title_str),
        subtitle=html.escape(subtitle),
        app=html.escape(pfg.application),
        framework=html.escape(pfg.framework),
        n_endpoints=counts["endpoint"],
        n_services=counts["service"],
        n_data=counts["data_access"],
        n_findings=len(f),
        findings_table=_findings_table_html(pfg, f),
        graph_block=_graph_block(pfg),
        pfg_json=pfg_json,
    )


def write_report(
    pfg: PFG,
    out_path: Path,
    *,
    findings: list[Finding] | None = None,
    title: str | None = None,
    extra_meta: dict[str, str] | None = None,
) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    html_text = render_report(pfg, findings=findings, title=title, extra_meta=extra_meta)
    out_path.write_text(html_text, encoding="utf-8")
    return out_path
