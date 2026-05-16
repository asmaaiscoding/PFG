"""Interactive web UI for PFG — stdlib only, zero new deps.

A single-page app served by a custom HTTP handler. The frontend is
inline HTML/CSS/JS; the backend exposes one JSON endpoint:

    POST /api/analyze
    Body: {"project_root": "...", "framework": "django"|"spring", "app_name": "..."|null}
    Response: AnalysisResult JSON

Usage:
    pfg web --port 8080
"""

from __future__ import annotations

import json
import re
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# ---------------------------------------------------------------------------
# SPA
# ---------------------------------------------------------------------------

_SPA = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>PFG — Privilege Flow Graph Analyzer</title>
<script src="https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js"></script>
<style>
*,::before,::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#080b10;--surface:#0e1117;--card:#13171f;--border:#1e2330;
  --fg:#e2e8f0;--muted:#64748b;--accent:#818cf8;--accent2:#38bdf8;
  --bad:#f87171;--warn:#fb923c;--ok:#4ade80;
  --mono:ui-monospace,Menlo,Consolas,monospace;
  --radius:12px;--transition:.18s cubic-bezier(.4,0,.2,1);
}
html,body{height:100%;background:var(--bg);color:var(--fg);
  font-family:ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  font-size:14px;line-height:1.6;}
#shell{display:grid;grid-template-rows:56px 1fr;height:100vh;overflow:hidden;}
header{display:flex;align-items:center;gap:12px;padding:0 24px;
  border-bottom:1px solid var(--border);background:var(--surface);}
header .logo{font-weight:800;font-size:17px;letter-spacing:-.02em;
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;}
header .tag{font-size:11px;color:var(--muted);margin-top:1px;}
#body{display:grid;grid-template-columns:300px 1fr;overflow:hidden;}
#sidebar{border-right:1px solid var(--border);background:var(--surface);
  display:flex;flex-direction:column;padding:20px;gap:16px;overflow-y:auto;}
.field{display:flex;flex-direction:column;gap:5px;}
label{font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;}
input,select{background:var(--card);border:1px solid var(--border);color:var(--fg);
  padding:8px 11px;border-radius:8px;font-size:13px;outline:none;
  transition:border-color var(--transition);}
input:focus,select:focus{border-color:var(--accent);}
select option{background:var(--card);}
button#run{background:linear-gradient(135deg,var(--accent),var(--accent2));
  color:#fff;border:none;padding:10px 0;border-radius:8px;font-size:14px;
  font-weight:700;cursor:pointer;width:100%;transition:opacity var(--transition);}
button#run:hover{opacity:.85;}button#run:disabled{opacity:.4;cursor:default;}
.divider{border:none;border-top:1px solid var(--border);}
.stat-row{display:grid;grid-template-columns:1fr 1fr;gap:8px;}
.stat{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:10px 12px;}
.stat .k{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;}
.stat .v{font-size:18px;font-weight:700;margin-top:2px;}
.v-bad{color:var(--bad);}.v-ok{color:var(--ok);}
/* ---- main ---- */
#main{display:flex;flex-direction:column;overflow:hidden;}
#placeholder{display:flex;flex-direction:column;align-items:center;justify-content:center;
  flex:1;gap:12px;color:var(--muted);}
#placeholder svg{opacity:.15;}
#spinner{display:none;flex-direction:column;align-items:center;justify-content:center;
  flex:1;gap:14px;color:var(--muted);}
.spin{width:38px;height:38px;border:3px solid var(--border);
  border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite;}
@keyframes spin{to{transform:rotate(360deg)}}
#error-box{display:none;margin:24px;background:#1a0e0e;border:1px solid #5c2020;
  border-radius:var(--radius);padding:16px;color:var(--bad);
  font-family:var(--mono);font-size:12px;white-space:pre-wrap;}
/* ---- results ---- */
#results{display:none;flex-direction:column;flex:1;overflow-y:auto;padding:24px;gap:20px;}
h2{font-size:15px;font-weight:700;letter-spacing:-.01em;margin-bottom:10px;}
/* findings table */
.findings-wrap{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;}
table{width:100%;border-collapse:collapse;table-layout:fixed;}
th,td{padding:9px 13px;text-align:left;font-size:13px;border-bottom:1px solid var(--border);vertical-align:top;
  word-break:break-word;overflow-wrap:anywhere;white-space:normal;}
td code{display:inline-block;max-width:100%;white-space:normal;word-break:break-all;overflow-wrap:anywhere;}
th{background:#0d1018;color:var(--muted);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;}
tr:last-child td{border-bottom:none;}
tr.finding-row:hover td{background:#161b26;cursor:pointer;}
.pill{display:inline-flex;align-items:center;gap:4px;padding:3px 9px;
  border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.04em;}
.pill::before{content:'';width:6px;height:6px;border-radius:50%;}
.MISSING_AUTH{background:#3a1620;color:var(--bad);}.MISSING_AUTH::before{background:var(--bad);}
.MISSING_ROLE{background:#2d1a0e;color:var(--warn);}.MISSING_ROLE::before{background:var(--warn);}
.IDOR{background:#3a1620;color:var(--bad);}.IDOR::before{background:var(--bad);}
.TENANT_ISOLATION_FAILURE{background:#2a233a;color:var(--bad);}.TENANT_ISOLATION_FAILURE::before{background:var(--bad);}
.OBJECT_LEVEL_PERMISSION_BYPASS{background:#1e2f32;color:var(--bad);}.OBJECT_LEVEL_PERMISSION_BYPASS::before{background:var(--bad);}
.COMBINED{background:#3a1620;color:var(--bad);}.COMBINED::before{background:var(--bad);}
.SAFE{background:#0e2218;color:var(--ok);}.SAFE::before{background:var(--ok);}
.INTENTIONALLY_PUBLIC{background:#0a1a2a;color:var(--accent2);}.INTENTIONALLY_PUBLIC::before{background:var(--accent2);}
.no-findings{padding:20px;color:var(--muted);text-align:center;}
.expl{font-size:12px;color:var(--muted);}
code{font-family:var(--mono);font-size:11.5px;background:#1a1f2e;padding:1px 5px;border-radius:4px;color:var(--accent2);}
/* ---- graph area ---- */
#graph-area{display:grid;grid-template-columns:1fr 280px;gap:16px;align-items:start;}
.graph-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;}
.graph-toolbar{display:flex;align-items:center;gap:8px;padding:9px 13px;border-bottom:1px solid var(--border);background:#0d1018;}
.graph-toolbar button{background:var(--card);border:1px solid var(--border);color:var(--fg);
  padding:3px 9px;border-radius:6px;font-size:11px;cursor:pointer;}
.graph-toolbar button:hover{border-color:var(--accent);color:var(--accent);}
.graph-legend{display:flex;gap:10px;font-size:11px;color:var(--muted);flex:1;flex-wrap:wrap;}
.leg{display:flex;align-items:center;gap:4px;}
.leg-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0;}
#graph-svg-wrap{width:100%;height:500px;}
#graph-svg-wrap svg{width:100%;height:100%;background:#060912;}
/* ---- detail panel ---- */
#node-detail{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);
  padding:16px;font-size:13px;min-height:200px;}
#node-detail .nd-header{font-weight:700;font-size:14px;margin-bottom:4px;word-break:break-all;}
#node-detail .nd-type{font-size:11px;text-transform:uppercase;letter-spacing:.06em;margin-bottom:12px;}
#node-detail .nd-section{font-size:11px;font-weight:700;text-transform:uppercase;
  letter-spacing:.07em;color:var(--muted);margin:12px 0 6px;}
#node-detail .nd-row{display:flex;justify-content:space-between;gap:8px;
  border-bottom:1px solid var(--border);padding:5px 0;font-size:12px;
  flex-wrap:wrap;}
#node-detail .nd-row:last-child{border-bottom:none;}
#node-detail .nd-k{color:var(--muted);flex-shrink:0;}
#node-detail .nd-v{color:var(--fg);text-align:right;word-break:break-all;overflow-wrap:anywhere;
  min-width:0;flex:1;}
#node-detail .nd-row-full{display:block;}
#node-detail .nd-row-full .nd-k{display:block;margin-bottom:3px;}
#node-detail .nd-src{display:block;font-family:ui-monospace,monospace;font-size:11px;
  color:#94a3b8;word-break:break-all;overflow-wrap:anywhere;white-space:normal;}
#node-detail .vuln-box{margin-top:12px;background:#1f0a0a;border:1px solid #5c2020;
  border-radius:8px;padding:10px 12px;}
#node-detail .vuln-title{color:var(--bad);font-weight:700;font-size:12px;margin-bottom:6px;}
#node-detail .vuln-why{color:#fca5a5;font-size:12px;line-height:1.5;}
#node-detail .nd-hint{color:var(--muted);font-size:12px;margin-top:8px;}
.nd-clean{color:var(--ok);}
.src-line{font-size:11px;color:var(--muted);margin-top:4px;}
.src-line code{font-size:10.5px;}
code.src{font-size:10.5px;color:#94a3b8;background:transparent;padding:0;}
</style>
</head>
<body>
<div id="shell">
  <header>
    <div>
      <div class="logo">PFG Analyzer</div>
      <div class="tag">Privilege Flow Graph &amp; Vulnerability Detection</div>
    </div>
  </header>
  <div id="body">
    <div id="sidebar">
      <div class="field">
        <label>Project root</label>
        <input id="proj" type="text" placeholder="C:\path\to\your\app" spellcheck="false"/>
      </div>
      <div class="field">
        <label>Framework</label>
        <select id="fw">
          <option value="django">Django</option>
          <option value="spring">Spring Boot</option>
        </select>
      </div>
      <div class="field">
        <label>App name <span style="font-weight:400;text-transform:none">(optional)</span></label>
        <input id="appname" type="text" placeholder="auto-detect"/>
      </div>
      <button id="run" onclick="analyze()">Analyze</button>
      <hr class="divider"/>
      <div id="stats" style="display:none">
        <div class="stat-row" id="stat-grid"></div>
      </div>
    </div>
    <div id="main">
      <div id="placeholder">
        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <circle cx="12" cy="12" r="10"/><path d="M12 8v4l3 3"/>
        </svg>
        <p>Enter a project path and click <strong>Analyze</strong></p>
      </div>
      <div id="spinner">
        <div class="spin"></div>
        <span>Analyzing&hellip;</span>
      </div>
      <div id="error-box"></div>
      <div id="results">
        <div>
          <h2>Findings</h2>
          <div class="findings-wrap"><table id="findings-table"></table></div>
        </div>
        <div>
          <h2>Privilege Flow Graph</h2>
          <div id="graph-area">
            <div class="graph-card">
              <div class="graph-toolbar">
                <div class="graph-legend">
                  <span class="leg"><span class="leg-dot" style="background:#818cf8"></span>Endpoint</span>
                  <span class="leg"><span class="leg-dot" style="background:#f87171"></span>Vulnerable</span>
                  <span class="leg"><span class="leg-dot" style="background:#475569"></span>Service</span>
                  <span class="leg"><span class="leg-dot" style="background:#fb923c"></span>Data access</span>
                  <span class="leg"><span class="leg-dot" style="background:#facc15"></span>Middleware</span>
                </div>
                <button onclick="fitGraph()">Fit all</button>
                <button onclick="resetZoom()">1:1</button>
              </div>
              <div id="graph-svg-wrap"></div>
            </div>
            <div>
              <h2>Node detail</h2>
              <div id="node-detail"><p class="nd-hint">Click any node in the graph to inspect it.</p></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
<script>
const $=id=>document.getElementById(id);
function show(id){['placeholder','spinner','error-box','results'].forEach(x=>{$(x).style.display='none';});
  $(id).style.display=(id==='results'||id==='spinner'||id==='placeholder')?'flex':'block';}

// ---- analyze ----
async function analyze(){
  const proj=$('proj').value.trim();
  if(!proj){$('proj').focus();return;}
  $('run').disabled=true;$('stats').style.display='none';
  show('spinner');
  try{
    const res=await fetch('/api/analyze',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({project_root:proj,framework:$('fw').value,app_name:$('appname').value.trim()||null})});
    const data=await res.json();
    if(!res.ok||data.error){$('error-box').textContent=data.error||'Unknown error';show('error-box');}
    else{renderStats(data);renderFindings(data.findings,data.graph_nodes);renderGraph(data.graph_nodes,data.graph_edges,data.findings);show('results');}
  }catch(e){$('error-box').textContent='Network error: '+e.message;show('error-box');}
  finally{$('run').disabled=false;}
}

// ---- stats ----
function renderStats(d){
  const flagged=d.findings.length;
  $('stat-grid').innerHTML=[['Endpoints',d.n_endpoints,''],['Nodes',d.n_nodes,''],
    ['Findings',flagged,flagged>0?'v-bad':'v-ok'],['Framework',d.framework,''],
  ].map(([k,v,c])=>`<div class="stat"><div class="k">${k}</div><div class="v ${c}">${v}</div></div>`).join('');
  $('stats').style.display='block';
}

// ---- findings table ----
let _findingsData=[], _nodesData=[];
function renderFindings(findings,nodes){
  _findingsData=findings;_nodesData=nodes||[];
  const t=$('findings-table');
  if(!findings.length){t.innerHTML='<tr><td class="no-findings" colspan="6">\u2713 No vulnerable endpoints detected</td></tr>';return;}
  t.innerHTML='<thead><tr><th>Type</th><th>Endpoint</th><th>Route</th><th>Source</th><th>Reaches</th><th>Cause</th></tr></thead>'
    +'<tbody>'+findings.map(f=>{
      const n=nodes&&nodes.find(x=>x.id===f.endpoint_id);
      const route=n&&n.detail?esc(n.detail.route||''):'';
      const method=n&&n.detail?esc(n.detail.http_method||''):'';
      const src=f.endpoint_source?esc(f.endpoint_source):'\u2014';
      const reaches=f.data_access_id?esc(f.data_access_id):'\u2014';
      return `<tr class="finding-row" onclick="selectNodeById('${esc(f.endpoint_id)}')">
        <td><span class="pill ${f.subtype}">${f.subtype}</span></td>
        <td><code>${esc(f.endpoint_id)}</code></td>
        <td><code>${method} ${route}</code></td>
        <td><code class="src">${src}</code></td>
        <td><code>${reaches}</code></td>
        <td class="expl">${esc(f.cause||f.explanation)}</td>
      </tr>`;
    }).join('')+'</tbody>';
}

// ---- detail panel ----
function showNodeDetail(d, findings){
  const panel=$('node-detail');
  const typeColor={endpoint:'#818cf8',service:'#475569',data_access:'#fb923c',middleware:'#facc15'};
  const col=d.flagged?'#f87171':(typeColor[d.type]||'#64748b');
  let rows='', vulnHtml='';

  // standard key/value row
  const row=(k,v,vc)=>`<div class="nd-row"><span class="nd-k">${k}</span><span class="nd-v" ${vc?'style="color:'+vc+'"':''}>${esc(String(v))}</span></div>`;
  // full-width source path row (code block, wraps)
  const srcRow=(k,v)=>`<div class="nd-row nd-row-full"><span class="nd-k">${k}</span><code class="nd-src">${esc(String(v))}</code></div>`;

  if(d.type==='endpoint'){
    rows+=row('HTTP method', d.detail.http_method||'\u2014');
    rows+=row('Route', d.detail.route||'\u2014');
    rows+=row('Authentication', d.detail.requires_auth?'Required':'None', d.detail.requires_auth?'#4ade80':'#f87171');
    rows+=row('Required role', d.detail.required_role&&d.detail.required_role!='NONE'?d.detail.required_role:'\u2014');
    rows+=row('Intentionally public', d.detail.is_intentionally_public?'Yes':'No');
    if(d.detail.source_location)rows+=srcRow('Source', d.detail.source_location);
  } else if(d.type==='data_access'){
    rows+=row('Operation', d.detail.operation||'\u2014');
    rows+=row('Target entity', d.detail.target_entity||'\u2014');
    rows+=row('Ownership check', d.detail.has_ownership_predicate?'Present':'Missing', d.detail.has_ownership_predicate?'#4ade80':'#fb923c');
    if(d.detail.source_location)rows+=srcRow('Source', d.detail.source_location);
  } else if(d.type==='service'){
    rows+=row('Name', d.detail.name||d.id);
    rows+=row('Mutates data', d.detail.performs_mutation?'Yes':'No', d.detail.performs_mutation?'#fb923c':'');
    if(d.detail.source_location)rows+=srcRow('Source', d.detail.source_location);
  }

  // parse explanation: if it contains a Python-list-like pattern, split into bullets
  function fmtExplanation(text){
    // extract anything between [ and ] and split by commas+quotes
    const m=text.match(/^(.*?)\[(.+)\]\s*$/s);
    if(m){
      const prefix=m[1].trim();
      const items=m[2].split(/,\s*/).map(s=>s.replace(/^['"]/,'').replace(/['"]$/,'').trim()).filter(Boolean);
      const bullets=items.map(it=>`<li style="margin:2px 0;font-family:ui-monospace,monospace;font-size:10.5px;color:#94a3b8;word-break:break-all">${esc(it)}</li>`).join('');
      return `<span>${esc(prefix)}</span><ul style="margin:6px 0 0 14px;padding:0;list-style:disc">${bullets}</ul>`;
    }
    return esc(text);
  }

  const myFindings=findings.filter(f=>f.endpoint_id===d.id);
  if(myFindings.length){
    vulnHtml=myFindings.map(f=>{
      const traceHtml=(f.trace||[]).map(t=>{
        const tcolor=t.type==='endpoint'?'#818cf8':t.type==='data_access'?'#fb923c':t.type==='service'?'#94a3b8':'#facc15';
        const srcStr=t.source
          ?`<div style="font-family:ui-monospace,monospace;font-size:10px;color:#475569;word-break:break-all;margin-top:2px">${esc(t.source)}</div>`
          :'';
        return `<div style="padding:5px 0;border-bottom:1px dashed #1e2330">
          <span style="color:${tcolor};font-size:9px;text-transform:uppercase;letter-spacing:.06em;font-weight:700">${esc(t.type.replace('_',' '))}</span>
          <div style="font-family:ui-monospace,monospace;font-size:11px;color:#e2e8f0;word-break:break-all">${esc(t.label||t.id)}</div>
          ${srcStr}
        </div>`;
      }).join('');
      const epSrc=f.endpoint_source
        ?`<div style="margin-top:4px;font-size:11px;color:#64748b">Endpoint: <span style="font-family:ui-monospace,monospace;color:#94a3b8;word-break:break-all">${esc(f.endpoint_source)}</span></div>`:'';
      const daSrc=f.data_access_source
        ?`<div style="margin-top:4px;font-size:11px;color:#64748b">Sink: <span style="font-family:ui-monospace,monospace;color:#94a3b8;word-break:break-all">${esc(f.data_access_source)}</span></div>`:'';
      const causeHtml=f.cause
        ?`<div style="margin-top:8px;font-size:11.5px"><span style="color:#fca5a5;font-weight:600">Root cause: </span><span style="color:#fecaca">${esc(f.cause)}</span></div>`:'';
      return `<div class="vuln-box">
        <div class="vuln-title">\u26a0 ${esc(f.subtype)}</div>
        <div class="vuln-why">${fmtExplanation(f.explanation)}</div>
        ${causeHtml}
        ${epSrc||daSrc?'<div class="nd-section" style="margin-top:10px">Where it comes from</div>'+epSrc+daSrc:''}
        ${traceHtml?'<div class="nd-section" style="margin-top:10px">Call trace</div>'+traceHtml:''}
      </div>`;
    }).join('');
  } else if(d.type==='endpoint'){
    vulnHtml='<div style="margin-top:12px;color:#4ade80;font-size:12px;font-weight:600">\u2713 No vulnerabilities detected</div>';
  }

  panel.innerHTML=`
    <div class="nd-header" style="color:${col}">${esc(d.id)}</div>
    <div class="nd-type" style="color:${col}">${esc(d.type.replace('_',' '))}</div>
    <div class="nd-section">Attributes</div>
    ${rows||'<div class="nd-hint">No attributes.</div>'}
    ${vulnHtml}`;
}

// ---- graph (force-directed circles) ----
let _zoom=null, _svg=null, _gNodes=[], _findings=[], _sim=null;
const _typeColor={endpoint:'#818cf8',service:'#64748b',data_access:'#fb923c',middleware:'#facc15'};
const _flaggedColor='#f87171';

function resetZoom(){if(_zoom&&_svg)_svg.transition().duration(350).call(_zoom.transform,d3.zoomIdentity);}
function fitGraph(){
  if(!_zoom||!_svg)return;
  const wrap=$('graph-svg-wrap');
  const W=wrap.clientWidth||900, H=wrap.clientHeight||500;
  try{
    const b=_svg.select('g.zoom-root').node().getBBox(), pad=40;
    const s=Math.min(W/(b.width+pad*2),H/(b.height+pad*2),.95);
    const tx=W/2-(b.x+b.width/2)*s, ty=H/2-(b.y+b.height/2)*s;
    _svg.transition().duration(500).call(_zoom.transform,d3.zoomIdentity.translate(tx,ty).scale(s));
  }catch(e){}
}

function selectNodeById(id){
  const d=_gNodes.find(n=>n.id===id);
  if(d)showNodeDetail(d,_findings);
  if(!_svg)return;
  _svg.selectAll('circle.node-circle')
    .attr('stroke',n=>n.id===id?'#fff':(n.flagged?'#fca5a5':'#1e293b'))
    .attr('stroke-width',n=>n.id===id?3:(n.flagged?2.5:1.5))
    .attr('r',n=>n.id===id?22:18);
}

function renderGraph(gNodes,gEdges,findings){
  _gNodes=gNodes; _findings=findings;
  const wrap=$('graph-svg-wrap');
  wrap.innerHTML='';
  if(!gNodes||!gNodes.length){wrap.innerHTML='<div style="padding:24px;color:#64748b">No nodes.</div>';return;}
  if(_sim){_sim.stop();_sim=null;}

  const W=wrap.clientWidth||900, H=wrap.clientHeight||500;

  const svg=d3.select(wrap).append('svg')
    .attr('width','100%').attr('height','100%')
    .style('background','#060912');
  _svg=svg;

  const defs=svg.append('defs');
  [['call','#4a5568'],['flow','#f87171']].forEach(([id,color])=>{
    defs.append('marker').attr('id','arrow-'+id)
      .attr('viewBox','0 -5 10 10').attr('refX',24).attr('refY',0)
      .attr('markerWidth',6).attr('markerHeight',6).attr('orient','auto')
      .append('path').attr('d','M0,-5L10,0L0,5').attr('fill',color);
  });

  const g=svg.append('g').classed('zoom-root',true);
  const zoom=d3.zoom().scaleExtent([.1,4]).on('zoom',ev=>g.attr('transform',ev.transform));
  svg.call(zoom); _zoom=zoom;

  // map edges to source/target objects for d3.forceLink
  const links=gEdges.map(e=>({...e,source:e.src,target:e.dst}));

  const sim=d3.forceSimulation(gNodes)
    .force('link',d3.forceLink(links).id(d=>d.id).distance(120).strength(.5))
    .force('charge',d3.forceManyBody().strength(-380))
    .force('center',d3.forceCenter(W/2,H/2))
    .force('collide',d3.forceCollide(38));
  _sim=sim;

  // edges
  const link=g.append('g').selectAll('line').data(links).join('line')
    .attr('stroke',d=>d.type==='identifier_flow'?'#f87171':'#2d3748')
    .attr('stroke-width',d=>d.type==='identifier_flow'?1.5:1.2)
    .attr('stroke-dasharray',d=>d.type==='identifier_flow'?'5,3':null)
    .attr('marker-end',d=>'url(#arrow-'+(d.type==='identifier_flow'?'flow':'call')+')');

  // nodes
  const node=g.append('g').selectAll('g').data(gNodes).join('g')
    .attr('cursor','pointer')
    .call(d3.drag()
      .on('start',(ev,d)=>{if(!ev.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y;})
      .on('drag',(ev,d)=>{d.fx=ev.x;d.fy=ev.y;})
      .on('end',(ev,d)=>{if(!ev.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}))
    .on('click',(ev,d)=>{
      showNodeDetail(d,findings);
      svg.selectAll('circle.node-circle')
        .attr('stroke',n=>n.id===d.id?'#fff':(n.flagged?'#fca5a5':'#1e293b'))
        .attr('stroke-width',n=>n.id===d.id?3:(n.flagged?2.5:1.5))
        .attr('r',n=>n.id===d.id?22:18);
    });

  node.append('circle').classed('node-circle',true)
    .attr('r',18)
    .attr('fill',d=>d.flagged?_flaggedColor:(_typeColor[d.type]||'#64748b'))
    .attr('stroke',d=>d.flagged?'#fca5a5':'#1e293b')
    .attr('stroke-width',d=>d.flagged?2.5:1.5)
    .attr('opacity',.93);

  // small short label inside circle
  node.append('text').attr('text-anchor','middle').attr('dy','0.35em')
    .attr('font-size',9).attr('fill','#fff')
    .attr('font-family','ui-monospace,Menlo,Consolas,monospace')
    .attr('font-weight','700').attr('pointer-events','none')
    .text(d=>{
      if(d.type==='endpoint')return (d.detail.http_method||'EP').slice(0,4);
      if(d.type==='data_access')return (d.detail.operation||'DA').slice(0,4);
      if(d.type==='service')return 'SVC';
      if(d.type==='middleware')return 'MW';
      return d.type.slice(0,3).toUpperCase();
    });

  // bottom label (route / target / name)
  node.append('text').attr('text-anchor','middle').attr('dy',32)
    .attr('font-size',10).attr('fill','#94a3b8')
    .attr('font-family','ui-sans-serif,system-ui,sans-serif')
    .attr('pointer-events','none')
    .text(d=>{
      let s='';
      if(d.type==='endpoint')s=d.detail.route||d.id;
      else if(d.type==='data_access')s=d.detail.target_entity||d.id;
      else s=d.detail.name||d.id;
      return s.length>22?s.slice(0,20)+'\u2026':s;
    });

  // tooltip on hover
  node.append('title').text(d=>{
    const lines=[d.id,'type: '+d.type];
    if(d.type==='endpoint'){
      lines.push('route: '+(d.detail.http_method||'')+' '+(d.detail.route||''));
      lines.push('auth: '+(d.detail.requires_auth?'required':'NONE'));
      if(d.detail.required_role&&d.detail.required_role!=='NONE')lines.push('role: '+d.detail.required_role);
    } else if(d.type==='data_access'){
      lines.push('op: '+(d.detail.operation||''));
      lines.push('entity: '+(d.detail.target_entity||''));
      lines.push('ownership: '+(d.detail.has_ownership_predicate?'yes':'NONE'));
    } else if(d.type==='service'){
      lines.push('mutates: '+(d.detail.performs_mutation?'yes':'no'));
    }
    if(d.flagged)lines.push('\u26a0 FLAGGED');
    return lines.join('\n');
  });

  sim.on('tick',()=>{
    link
      .attr('x1',d=>d.source.x).attr('y1',d=>d.source.y)
      .attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
    node.attr('transform',d=>`translate(${d.x},${d.y})`);
  });

  sim.on('end',()=>{ setTimeout(fitGraph,50); });
  // also fit after a short warm-up so very large graphs are visible quickly
  setTimeout(()=>{ if(sim.alpha()>.05) fitGraph(); }, 1500);
}

function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
document.getElementById('proj').addEventListener('keydown',e=>{if(e.key==='Enter')analyze();});
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:  # silence access log
        pass

    def _send(self, status: int, ctype: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", _SPA.encode())
        else:
            self._send(404, "text/plain", b"Not found")

    def do_POST(self) -> None:
        if self.path != "/api/analyze":
            self._send(404, "text/plain", b"Not found")
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            req = json.loads(body)
        except Exception:
            self._send(400, "application/json", json.dumps({"error": "Invalid JSON"}).encode())
            return
        result = _run_analysis(req)
        self._send(
            200 if result.get("error") is None else 500,
            "application/json",
            json.dumps(result).encode(),
        )


# ---------------------------------------------------------------------------
# Analysis runner
# ---------------------------------------------------------------------------

def _run_analysis(req: dict[str, object]) -> dict[str, object]:
    project_root = req.get("project_root")
    framework = req.get("framework", "django")
    app_name = req.get("app_name") or None

    app_name_str: str | None = str(app_name) if app_name else None

    if not isinstance(project_root, str) or not project_root.strip():
        return {"error": "project_root is required"}
    if not re.match(r"^[a-zA-Z0-9_.:/\\-]", project_root):
        return {"error": "Invalid project_root path"}
    if framework not in ("django", "spring"):
        return {"error": "framework must be 'django' or 'spring'"}

    p = Path(project_root.strip())
    if not p.is_dir():
        return {"error": f"Directory not found: {p}"}

    try:
        if framework == "django":
            from pfg.extractors.django.build import build_pfg as _build
        else:
            from pfg.extractors.spring.build import build_pfg as _build

        from pfg.detectors.rule_baseline import detect_all
        from pfg.pfg.viz import to_dot

        pfg = _build(p, application=app_name_str or p.name)
        findings = detect_all(pfg)
        dot = to_dot(pfg)
        svg = _try_svg(dot)
        flagged_ids = {f.endpoint_id for f in findings}
        n_endpoints = sum(
            1 for n in pfg.nodes if getattr(n.type, "value", n.type) == "endpoint"
        )

        from collections import deque

        from pfg.pfg.nodes import Node as _Node

        graph_nodes = []
        node_by_id: dict[str, _Node] = {}
        for n in pfg.nodes:
            ntype = getattr(n.type, "value", n.type)
            a = n.attrs
            src_loc = getattr(a, "source_location", None)
            detail: dict[str, object] = {"source_location": src_loc}
            if ntype == "endpoint":
                detail.update({
                    "http_method": getattr(a, "http_method", ""),
                    "route": getattr(a, "route", ""),
                    "requires_auth": getattr(a, "requires_auth", False),
                    "required_role": str(getattr(a, "required_role", "")),
                    "is_intentionally_public": getattr(a, "is_intentionally_public", False),
                })
            elif ntype == "data_access":
                op = getattr(a, "operation", "")
                detail.update({
                    "operation": getattr(op, "value", op),
                    "target_entity": getattr(a, "target_entity", ""),
                    "has_ownership_predicate": getattr(a, "has_ownership_predicate", False),
                })
            elif ntype == "service":
                detail.update({
                    "name": getattr(a, "name", n.id),
                    "performs_mutation": getattr(a, "performs_mutation", False),
                })
            elif ntype == "middleware":
                detail.update({
                    "name": getattr(a, "name", n.id),
                    "guard_type": str(getattr(a, "guard_type", "")),
                })
            graph_nodes.append({
                "id": n.id,
                "type": ntype,
                "flagged": n.id in flagged_ids,
                "detail": detail,
            })
            node_by_id[n.id] = n

        graph_edges = []
        adj: dict[str, list[tuple[str, str]]] = {}
        for e in pfg.edges:
            etype = getattr(e.type, "value", e.type)
            graph_edges.append({
                "src": e.src,
                "dst": e.dst,
                "type": etype,
                "param": getattr(e, "param", None),
            })
            adj.setdefault(e.src, []).append((e.dst, etype))

        # ---- enrich findings with source location + call trace ------------
        def _shortest_path(src: str, dst: str) -> list[str]:
            """BFS path src->dst over call/identifier_flow edges, [] if none."""
            if src == dst:
                return [src]
            q: deque[tuple[str, list[str]]] = deque([(src, [src])])
            seen = {src}
            while q:
                cur, path = q.popleft()
                for nxt, _et in adj.get(cur, []):
                    if nxt in seen:
                        continue
                    new_path = [*path, nxt]
                    if nxt == dst:
                        return new_path
                    seen.add(nxt)
                    q.append((nxt, new_path))
            return []

        def _node_label(node_id: str) -> str:
            n = node_by_id.get(node_id)
            if n is None:
                return node_id
            a = n.attrs
            ntype = getattr(n.type, "value", n.type)
            if ntype == "endpoint":
                return f"{getattr(a, 'http_method', '')} {getattr(a, 'route', node_id)}".strip()
            if ntype == "data_access":
                op = getattr(a, "operation", "")
                op_s = getattr(op, "value", op)
                return f"{op_s} {getattr(a, 'target_entity', '')}".strip()
            return str(getattr(a, "name", node_id) or node_id)

        def _src_of(node_id: str) -> str | None:
            n = node_by_id.get(node_id)
            if n is None:
                return None
            loc = getattr(n.attrs, "source_location", None)
            return str(loc) if loc else None

        cause_for = {
            "MISSING_AUTH": "Endpoint has no authentication guard but reaches a data-access node.",
            "MISSING_ROLE": "Endpoint reaches a privileged data-access op without a role check.",
            "IDOR": "Route parameter flows into a data-access query without an ownership predicate.",
            "TENANT_ISOLATION_FAILURE": "Tenant/org/workspace-scoped data is reachable without a tenant predicate.",
            "OBJECT_LEVEL_PERMISSION_BYPASS": "Model-level permission exists but object-level authorization is missing.",
            "COMBINED": "Multiple privilege-flow violations along the same path.",
        }

        enriched_findings: list[dict[str, object]] = []
        for f in findings:
            ep_id = f.endpoint_id
            da_id = f.data_access_id
            trace_ids = _shortest_path(ep_id, da_id) if da_id else [ep_id]
            trace_payload: list[dict[str, object]] = []
            for nid in trace_ids:
                tn = node_by_id.get(nid)
                ntype = getattr(tn.type, "value", tn.type) if tn is not None else ""
                trace_payload.append({
                    "id": nid,
                    "label": _node_label(nid),
                    "type": ntype,
                    "source": _src_of(nid),
                })
            subtype_str = f.subtype.value if hasattr(f.subtype, "value") else str(f.subtype)
            d: dict[str, object] = {
                "endpoint_id": f.endpoint_id,
                "subtype": subtype_str,
                "data_access_id": f.data_access_id,
                "explanation": f.explanation,
                "endpoint_source": _src_of(ep_id),
                "data_access_source": _src_of(da_id) if da_id else None,
                "trace": trace_payload,
                "cause": cause_for.get(subtype_str, ""),
            }
            enriched_findings.append(d)

        return {
            "error": None,
            "application": pfg.application,
            "framework": pfg.framework,
            "n_nodes": len(pfg.nodes),
            "n_edges": len(pfg.edges),
            "n_endpoints": n_endpoints,
            "findings": enriched_findings,
            "dot": dot,
            "svg": svg,
            "graph_nodes": graph_nodes,
            "graph_edges": graph_edges,
        }
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}\n\n{traceback.format_exc(limit=6)}"}


def _try_svg(dot: str) -> str | None:
    try:
        import graphviz

        raw: bytes = graphviz.Source(dot).pipe(format="svg")
        svg = str(raw.decode("utf-8", errors="ignore"))
        idx = svg.find("<svg")
        return svg[idx:] if idx >= 0 else svg
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(host: str = "127.0.0.1", port: int = 8080) -> None:
    server = ThreadingHTTPServer((host, port), _Handler)
    print(f"PFG web UI  →  http://{host}:{port}/  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
