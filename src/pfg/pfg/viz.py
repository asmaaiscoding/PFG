"""Graphviz rendering for `PFG` instances.

Produces a DOT string (and optionally writes a PNG/SVG via the `graphviz`
package). The `to_dot` function is usable without the optional Graphviz
binary; rendering an image requires Graphviz to be installed on the system.
"""

from __future__ import annotations

from pathlib import Path

from pfg.pfg.graph import PFG
from pfg.pfg.nodes import Node

_NODE_STYLES = {
    "endpoint": ("box", "lightblue"),
    "middleware": ("hexagon", "khaki"),
    "service": ("ellipse", "lightgrey"),
    "data_access": ("cylinder", "salmon"),
}


def _node_label(node: Node) -> str:
    a = node.attrs
    t = node.type if isinstance(node.type, str) else node.type.value
    if t == "endpoint":
        auth = "auth" if a.requires_auth else "no-auth"  # type: ignore[union-attr]
        role_v = a.required_role  # type: ignore[union-attr]
        role = role_v if isinstance(role_v, str) else role_v.value
        pub = " [public]" if a.is_intentionally_public else ""  # type: ignore[union-attr]
        return f"{a.http_method} {a.route}\\n{auth} role={role}{pub}"  # type: ignore[union-attr]
    if t == "service":
        marks = []
        if a.performs_data_access:  # type: ignore[union-attr]
            marks.append("DA")
        if a.performs_mutation:  # type: ignore[union-attr]
            marks.append("MUT")
        suffix = (" [" + ",".join(marks) + "]") if marks else ""
        return f"{a.name or node.id}{suffix}"  # type: ignore[union-attr]
    if t == "data_access":
        op_v = a.operation  # type: ignore[union-attr]
        op = op_v if isinstance(op_v, str) else op_v.value
        own = "OWNED" if a.has_ownership_predicate else "UNOWNED"  # type: ignore[union-attr]
        return f"{op} {a.target_entity}\\n{own}"  # type: ignore[union-attr]
    if t == "middleware":
        gt_v = a.guard_type  # type: ignore[union-attr]
        gt = gt_v if isinstance(gt_v, str) else gt_v.value
        return f"{gt}"
    return node.id


def _escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def to_dot(pfg: PFG) -> str:
    """Serialize `pfg` to a Graphviz DOT string."""
    lines: list[str] = []
    lines.append(f'digraph PFG_{_safe_id(pfg.application)} {{')
    lines.append('  rankdir=LR;')
    lines.append('  node [fontname="Helvetica",fontsize=10];')
    lines.append('  edge [fontname="Helvetica",fontsize=9];')

    for n in pfg.nodes:
        t = n.type if isinstance(n.type, str) else n.type.value
        shape, color = _NODE_STYLES.get(t, ("box", "white"))
        label = _node_label(n)
        lines.append(
            f'  "{_escape(n.id)}" '
            f'[shape={shape},style=filled,fillcolor={color},label="{_escape(label)}"];'
        )

    for e in pfg.edges:
        et = e.type if isinstance(e.type, str) else e.type.value
        attrs: list[str] = []
        if et == "identifier_flow":
            attrs.append("style=dashed")
            attrs.append("color=red")
            if e.param:
                attrs.append(f'label="{_escape(e.param)}"')
        attr_str = (" [" + ",".join(attrs) + "]") if attrs else ""
        lines.append(f'  "{_escape(e.src)}" -> "{_escape(e.dst)}"{attr_str};')

    lines.append("}")
    return "\n".join(lines) + "\n"


def render(pfg: PFG, out_path: str | Path, *, format: str = "png") -> Path:
    """Render `pfg` to an image. Requires the `graphviz` Python package and
    the system `dot` binary."""
    try:
        import graphviz
    except ImportError as exc:  # pragma: no cover - optional dep
        raise RuntimeError(
            "Graphviz Python package not installed. `pip install graphviz`."
        ) from exc
    out = Path(out_path)
    src = graphviz.Source(to_dot(pfg))
    src.format = format
    rendered = src.render(filename=out.stem, directory=str(out.parent), cleanup=True)
    return Path(rendered)


def _safe_id(s: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in s) or "G"
