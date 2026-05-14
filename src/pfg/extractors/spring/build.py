"""Phase 5 W24-W25: Spring Boot extractor demo.

A pragmatic, regex-based extractor for Spring MVC / Spring Boot projects.
Goal is *demonstration*: show that the same PFG schema generalizes to a
second framework, not full coverage.

What is recognized
------------------
* **Endpoints**: ``@RequestMapping``, ``@GetMapping``, ``@PostMapping``,
  ``@PutMapping``, ``@PatchMapping``, ``@DeleteMapping`` on methods of
  ``@RestController`` / ``@Controller`` classes. Class-level
  ``@RequestMapping`` is concatenated as a base path.
* **Auth**: method- or class-level ``@PreAuthorize("...")`` /
  ``@Secured(...)`` / ``@RolesAllowed(...)``. Absence of any of these
  *and* no ``@PermitAll`` /  no Spring-Security ``http.requestMatchers``
  override means ``requires_auth=False``.
* **Path variables**: ``@PathVariable`` parameter names. A flow edge is
  added from the endpoint to a data-access node iff the path variable is
  passed (by name) to a JPA-repository call site.
* **Data access**: invocations on fields/locals whose declared type ends
  in ``Repository`` (or ``JpaRepository``). Operation kind is inferred
  from the method name (``find*/get*`` -> READ, ``save*`` -> UPDATE,
  ``delete*`` -> DELETE).
* **Ownership predicate**: a heuristic — a repository call whose method
  name contains ``ByOwner`` / ``ByUser`` / ``ByCurrentUser`` is treated
  as owner-checked.

Out of scope
------------
* Spring Security configuration files (``http.requestMatchers(...)``):
  not parsed; user can mark endpoints intentional_public via the
  manifest if needed.
* Method-overload resolution / generics. Single-file, line-based, fast.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pfg.pfg.graph import PFG

# --- regexes --------------------------------------------------------------

_CLASS_RE = re.compile(
    r"(?ms)"
    r"((?:@\w+(?:\([^)]*\))?\s*)*)"  # annotations
    r"public\s+(?:abstract\s+|final\s+)?class\s+(\w+)\b"
)
_METHOD_RE = re.compile(
    r"(?ms)"
    r"((?:@\w+(?:\([^)]*\))?\s*)+)"  # annotations (>=1)
    r"public\s+(?:static\s+|final\s+)?[\w<>,?\[\] ]+?\s+"  # return type
    r"(\w+)\s*\(([^)]*)\)\s*\{"  # name + args
)
_REPO_FIELD_RE = re.compile(
    r"(?m)^\s*(?:private|protected|public)?\s*(?:final\s+)?"
    r"(\w+Repository)(?:<[^>]+>)?\s+(\w+)\s*[;=]"
)
_REPO_LOCAL_RE = re.compile(
    r"(?m)^\s*(?:final\s+)?(\w+Repository)(?:<[^>]+>)?\s+(\w+)\s*="
)
_AUTOWIRED_FIELD_RE = re.compile(
    r"(?ms)@Autowired[^\n]*\n\s*(?:private|protected|public)?\s*(?:final\s+)?"
    r"(\w+Repository)(?:<[^>]+>)?\s+(\w+)"
)

_HTTP_ANN_TO_METHODS: dict[str, tuple[str, ...]] = {
    "GetMapping": ("GET",),
    "PostMapping": ("POST",),
    "PutMapping": ("PUT",),
    "PatchMapping": ("PATCH",),
    "DeleteMapping": ("DELETE",),
}

_AUTH_ANN = ("PreAuthorize", "Secured", "RolesAllowed")
_PUBLIC_ANN = ("PermitAll",)


# --- data classes ---------------------------------------------------------


@dataclass(frozen=True)
class SpringEndpoint:
    http_method: str
    route: str
    route_params: tuple[str, ...]
    handler_qualname: str  # ClassName.methodName
    source_location: str
    requires_auth: bool
    required_role: str
    is_intentionally_public: bool
    parameters: tuple[str, ...]  # @PathVariable / @RequestParam names


@dataclass(frozen=True)
class SpringDataAccess:
    repo_var: str
    repo_type: str
    method: str
    operation: str  # READ|WRITE|UPDATE|DELETE
    has_ownership_predicate: bool
    arg_names: tuple[str, ...]
    target_entity: str
    line: int


@dataclass
class _ParsedClass:
    name: str
    file_path: Path
    class_annotations: list[str]
    class_route: str
    methods: list[dict[str, Any]] = field(default_factory=list)
    repo_fields: dict[str, str] = field(default_factory=dict)  # var -> repo_type


# --- helpers --------------------------------------------------------------


def _strip_str(s: str) -> str:
    s = s.strip()
    if s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    return s


def _extract_route_from_ann(ann: str) -> str:
    m = re.search(r'value\s*=\s*"([^"]*)"', ann) or re.search(r'\(\s*"([^"]*)"', ann)
    return m.group(1) if m else ""


def _http_methods_from_request_mapping(ann: str) -> tuple[str, ...]:
    m = re.search(r"method\s*=\s*([^,)\s]+(?:\s*,\s*[^,)\s]+)*)", ann)
    if not m:
        return ("GET",)  # default for @RequestMapping w/ no method
    raw = m.group(1)
    methods: list[str] = []
    for tok in re.findall(r"RequestMethod\.(\w+)", raw):
        methods.append(tok.upper())
    return tuple(methods) if methods else ("GET",)


def _route_params(route: str) -> tuple[str, ...]:
    return tuple(re.findall(r"\{(\w+)\}", route))


def _join_routes(base: str, sub: str) -> str:
    base = base or ""
    sub = sub or ""
    if not base and not sub:
        return "/"
    if not base:
        return sub if sub.startswith("/") else f"/{sub}"
    if not sub:
        return base if base.startswith("/") else f"/{base}"
    if not base.startswith("/"):
        base = f"/{base}"
    if base.endswith("/") and sub.startswith("/"):
        return base + sub[1:]
    if not base.endswith("/") and not sub.startswith("/"):
        return f"{base}/{sub}"
    return base + sub


def _split_annotations(annotations_text: str) -> list[str]:
    """Split a blob of `@Foo(...) @Bar(...)` into individual annotation strings."""
    out: list[str] = []
    i = 0
    while i < len(annotations_text):
        if annotations_text[i] != "@":
            i += 1
            continue
        j = i + 1
        # name
        while j < len(annotations_text) and (annotations_text[j].isalnum() or annotations_text[j] == "_"):
            j += 1
        # optional (...) — balanced
        if j < len(annotations_text) and annotations_text[j] == "(":
            depth = 1
            k = j + 1
            while k < len(annotations_text) and depth > 0:
                if annotations_text[k] == "(":
                    depth += 1
                elif annotations_text[k] == ")":
                    depth -= 1
                k += 1
            out.append(annotations_text[i:k])
            i = k
        else:
            out.append(annotations_text[i:j])
            i = j
    return out


def _ann_name(ann: str) -> str:
    m = re.match(r"@(\w+)", ann)
    return m.group(1) if m else ""


def _safe_id(s: str) -> str:
    out = "".join(c if c.isalnum() else "_" for c in s)
    if not out or not (out[0].isalpha() or out[0] == "_"):
        out = "_" + out
    return out


# --- parsing --------------------------------------------------------------


def _parse_file(path: Path) -> list[_ParsedClass]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    classes: list[_ParsedClass] = []

    for cm in _CLASS_RE.finditer(text):
        ann_blob, name = cm.group(1) or "", cm.group(2)
        anns = _split_annotations(ann_blob)
        ann_names = [_ann_name(a) for a in anns]
        if not any(n in {"RestController", "Controller"} for n in ann_names):
            continue
        # class-level @RequestMapping for base path
        class_route = ""
        for a in anns:
            if _ann_name(a) == "RequestMapping":
                class_route = _extract_route_from_ann(a)
                break

        # Locate the class body bounds (balanced braces).
        body_start = text.find("{", cm.end())
        if body_start < 0:
            continue
        depth = 1
        i = body_start + 1
        while i < len(text) and depth > 0:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        body = text[body_start + 1 : i - 1]

        pc = _ParsedClass(
            name=name,
            file_path=path,
            class_annotations=anns,
            class_route=class_route,
        )

        # Repository fields.
        for rm in _REPO_FIELD_RE.finditer(body):
            pc.repo_fields[rm.group(2)] = rm.group(1)
        for rm in _AUTOWIRED_FIELD_RE.finditer(body):
            pc.repo_fields[rm.group(2)] = rm.group(1)

        # Methods: hand-scan to handle nested parens in annotations like
        # @PreAuthorize("isAuthenticated()") which break greedy regexes.
        for mname, mann_strs, margs, mbody, abs_off in _scan_methods(text, body_start + 1, i - 1):
            line_no = text.count("\n", 0, abs_off) + 1
            pc.methods.append(
                {
                    "name": mname,
                    "annotations": mann_strs,
                    "args": margs,
                    "body": mbody,
                    "line": line_no,
                }
            )
        classes.append(pc)
    return classes


def _scan_methods(
    text: str, body_start: int, body_end: int
) -> list[tuple[str, list[str], str, str, int]]:
    """Find every method declaration inside text[body_start:body_end].

    Returns tuples (method_name, [annotation_strings], args_blob, body, abs_offset).
    Handles nested parens in annotations and skips field declarations and comments.
    """
    out: list[tuple[str, list[str], str, str, int]] = []
    pos = body_start
    while pos < body_end:
        pos = _skip_ws_and_comments(text, pos, body_end)
        if pos >= body_end:
            break
        # Collect annotations.
        anns: list[str] = []
        while pos < body_end and text[pos] == "@":
            start = pos
            pos += 1
            while pos < body_end and (text[pos].isalnum() or text[pos] == "_"):
                pos += 1
            if pos < body_end and text[pos] == "(":
                depth = 1
                pos += 1
                while pos < body_end and depth > 0:
                    ch = text[pos]
                    if ch == '"':
                        pos += 1
                        while pos < body_end and text[pos] != '"':
                            if text[pos] == "\\":
                                pos += 1
                            pos += 1
                        pos += 1
                        continue
                    if ch == "(":
                        depth += 1
                    elif ch == ")":
                        depth -= 1
                    pos += 1
            anns.append(text[start:pos])
            pos = _skip_ws_and_comments(text, pos, body_end)

        # We're now at the start of either a method, a field, or a nested block.
        # Look for `name(args) {` -- find the next '(' before any ';' or '{'.
        decl_start = pos
        scan = pos
        while scan < body_end and text[scan] not in "({};":
            scan += 1
        if scan >= body_end or text[scan] in ";{":
            # Not a method: skip to next ; or }.
            while scan < body_end and text[scan] not in ";}":
                scan += 1
            pos = scan + 1
            continue

        # text[scan] == '('. Identify method name = last identifier before '('.
        head = text[decl_start:scan]
        m = re.search(r"(\w+)\s*$", head)
        if m is None:
            pos = scan + 1
            continue
        mname = m.group(1)

        # Java reserved words that look like methods but aren't (e.g. constructors fine; if/while are not at this scope).
        if mname in {"if", "while", "for", "switch", "catch", "return", "synchronized", "new"}:
            pos = scan + 1
            continue

        # Read balanced args.
        depth = 1
        arg_start = scan + 1
        i = arg_start
        while i < body_end and depth > 0:
            if text[i] == '"':
                i += 1
                while i < body_end and text[i] != '"':
                    if text[i] == "\\":
                        i += 1
                    i += 1
                i += 1
                continue
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
            i += 1
        args_blob = text[arg_start : i - 1]
        # After ')' optional throws... and then '{' or ';'.
        j = i
        while j < body_end and text[j] != "{" and text[j] != ";":
            j += 1
        if j >= body_end or text[j] == ";":
            # Abstract / interface method: still record with empty body.
            out.append((mname, anns, args_blob, "", decl_start))
            pos = j + 1
            continue
        # Read balanced method body.
        depth = 1
        k = j + 1
        while k < body_end and depth > 0:
            if text[k] == "{":
                depth += 1
            elif text[k] == "}":
                depth -= 1
            k += 1
        mbody = text[j + 1 : k - 1]
        out.append((mname, anns, args_blob, mbody, decl_start))
        pos = k
    return out


def _parse_classes_done(_x: object) -> None:
    """No-op; kept to preserve module shape during incremental edits."""
    return None


def _skip_ws_and_comments(text: str, pos: int, end: int) -> int:
    """Advance past whitespace and Java line/block comments."""
    while pos < end:
        ch = text[pos]
        if ch.isspace():
            pos += 1
            continue
        if ch == "/" and pos + 1 < end:
            nxt = text[pos + 1]
            if nxt == "/":
                pos += 2
                while pos < end and text[pos] != "\n":
                    pos += 1
                continue
            if nxt == "*":
                pos += 2
                while pos + 1 < end and not (text[pos] == "*" and text[pos + 1] == "/"):
                    pos += 1
                pos += 2
                continue
        break
    return pos


# --- per-method analysis --------------------------------------------------


def _path_variables(args_blob: str) -> tuple[list[str], list[tuple[str, str]]]:
    """Return (path_var_names, [(java_param_name, source_kind), ...])."""
    pvs: list[str] = []
    params: list[tuple[str, str]] = []
    # Split top-level commas.
    parts: list[str] = []
    depth = 0
    cur = ""
    for ch in args_blob:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    for p in parts:
        p = p.strip()
        if not p:
            continue
        ann_match = re.match(r"((?:@\w+(?:\([^)]*\))?\s*)*)\s*[\w<>,?\[\] ]+?\s+(\w+)\s*$", p)
        if not ann_match:
            continue
        ann_text = ann_match.group(1) or ""
        pname = ann_match.group(2)
        anns = _split_annotations(ann_text)
        kinds = [_ann_name(a) for a in anns]
        if "PathVariable" in kinds:
            pvs.append(pname)
            params.append((pname, "path"))
        elif "RequestParam" in kinds:
            params.append((pname, "query"))
        elif "RequestBody" in kinds:
            params.append((pname, "body"))
    return pvs, params


def _detect_data_accesses(
    method_body: str, repo_fields: dict[str, str], local_repos: dict[str, str]
) -> list[SpringDataAccess]:
    out: list[SpringDataAccess] = []
    # repo_var.method(arg1, arg2)
    for cm in re.finditer(r"\b(\w+)\.(\w+)\s*\(([^)]*)\)", method_body):
        var, meth, args = cm.group(1), cm.group(2), cm.group(3)
        rtype = repo_fields.get(var) or local_repos.get(var)
        if rtype is None:
            continue
        op = "READ"
        if meth.startswith("save") or meth.startswith("update"):
            op = "UPDATE"
        elif meth.startswith("delete") or meth.startswith("remove"):
            op = "DELETE"
        elif meth.startswith("insert") or meth.startswith("create"):
            op = "WRITE"
        owner = any(k in meth for k in ("ByOwner", "ByUser", "ByCurrentUser"))
        # Naive arg name extraction (idents only).
        arg_names = tuple(re.findall(r"\b([A-Za-z_]\w*)\b", args))
        # Strip Java keywords / common noise.
        kws = {"new", "true", "false", "null", "this"}
        arg_names = tuple(a for a in arg_names if a not in kws)
        # target entity = repo type with "Repository" stripped, lower-cased table.
        entity = rtype[:-len("Repository")] if rtype.endswith("Repository") else rtype
        line = method_body.count("\n", 0, cm.start())
        out.append(
            SpringDataAccess(
                repo_var=var,
                repo_type=rtype,
                method=meth,
                operation=op,
                has_ownership_predicate=owner,
                arg_names=arg_names,
                target_entity=entity,
                line=line,
            )
        )
    return out


def _local_repos_in(method_body: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in _REPO_LOCAL_RE.finditer(method_body):
        out[m.group(2)] = m.group(1)
    return out


# --- top-level discovery + build -----------------------------------------


def discover_endpoints(project_root: Path) -> list[tuple[SpringEndpoint, _ParsedClass, dict[str, Any]]]:
    """Find every Spring controller method and produce (endpoint, class, method_dict)."""
    out: list[tuple[SpringEndpoint, _ParsedClass, dict[str, Any]]] = []
    java_files = list(project_root.rglob("*.java"))
    for f in java_files:
        try:
            classes = _parse_file(f)
        except OSError:
            continue
        for pc in classes:
            class_ann_names = [_ann_name(a) for a in pc.class_annotations]
            class_auth = any(n in _AUTH_ANN for n in class_ann_names)
            class_role = _required_role(pc.class_annotations)
            class_public = any(n in _PUBLIC_ANN for n in class_ann_names)
            for mdef in pc.methods:
                ann_names = [_ann_name(a) for a in mdef["annotations"]]
                http_methods: tuple[str, ...] = ()
                sub_route = ""
                for ann in mdef["annotations"]:
                    aname = _ann_name(ann)
                    if aname in _HTTP_ANN_TO_METHODS:
                        http_methods = _HTTP_ANN_TO_METHODS[aname]
                        sub_route = _extract_route_from_ann(ann)
                        break
                    if aname == "RequestMapping":
                        http_methods = _http_methods_from_request_mapping(ann)
                        sub_route = _extract_route_from_ann(ann)
                        break
                if not http_methods:
                    continue

                full_route = _join_routes(pc.class_route, sub_route)
                _pvs, params_kinds = _path_variables(mdef["args"])
                method_auth = any(n in _AUTH_ANN for n in ann_names)
                method_public = any(n in _PUBLIC_ANN for n in ann_names)
                requires_auth = bool(class_auth or method_auth) and not (class_public or method_public)
                role = _required_role(mdef["annotations"]) or class_role
                relpath = str(f.relative_to(project_root)).replace("\\", "/")

                for hm in http_methods:
                    ep = SpringEndpoint(
                        http_method=hm,
                        route=full_route,
                        route_params=tuple(_route_params(full_route)),
                        handler_qualname=f"{pc.name}.{mdef['name']}",
                        source_location=f"{relpath}:{mdef['line']}",
                        requires_auth=requires_auth,
                        required_role=role,
                        is_intentionally_public=bool(class_public or method_public),
                        parameters=tuple(p for p, _ in params_kinds),
                    )
                    out.append((ep, pc, mdef))
    return out


def _required_role(annotations: list[str]) -> str:
    for a in annotations:
        if _ann_name(a) == "PreAuthorize":
            m = re.search(r"hasRole\(\s*'([^']+)'\s*\)", a) or re.search(
                r'hasRole\(\s*"([^"]+)"\s*\)', a
            )
            if m:
                return m.group(1).upper()
            mr = re.search(r"hasAuthority\(\s*['\"]([^'\"]+)['\"]\s*\)", a)
            if mr:
                return mr.group(1).upper()
        elif _ann_name(a) == "Secured" or _ann_name(a) == "RolesAllowed":
            m = re.search(r"['\"]([A-Z_]+)['\"]", a)
            if m:
                return m.group(1)
    return "NONE"


def build_pfg(project_root: str | Path, *, application: str | None = None) -> PFG:
    """Build a PFG from a Spring Boot project root."""
    root = Path(project_root).resolve()
    app_name = application or root.name

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen_nodes: set[str] = set()
    seen_edges: set[tuple[str, str, str, str | None]] = set()

    def add_node(n: dict[str, Any]) -> None:
        if n["id"] in seen_nodes:
            return
        seen_nodes.add(n["id"])
        nodes.append(n)

    def add_edge(src: str, dst: str, etype: str, param: str | None = None) -> None:
        key = (src, dst, etype, param)
        if key in seen_edges:
            return
        seen_edges.add(key)
        e: dict[str, Any] = {"src": src, "dst": dst, "type": etype}
        if param is not None:
            e["param"] = param
        edges.append(e)

    for ep, pc, mdef in discover_endpoints(root):
        eid = _safe_id(f"endpoint__{ep.http_method}__{ep.route}")
        sid = _safe_id(f"service__{ep.handler_qualname}")
        add_node(
            {
                "id": eid,
                "type": "endpoint",
                "attrs": {
                    "http_method": ep.http_method,
                    "route": ep.route,
                    "route_params": list(ep.route_params),
                    "requires_auth": ep.requires_auth,
                    "required_role": ep.required_role,
                    "ownership_check_present": False,
                    "is_intentionally_public": ep.is_intentionally_public,
                    "source_location": ep.source_location,
                },
            }
        )
        add_node(
            {
                "id": sid,
                "type": "service",
                "attrs": {
                    "name": ep.handler_qualname,
                    "performs_data_access": False,
                    "performs_mutation": False,
                },
            }
        )
        add_edge(eid, sid, "call")

        local_repos = _local_repos_in(mdef["body"])
        accesses = _detect_data_accesses(mdef["body"], pc.repo_fields, local_repos)
        for idx, da in enumerate(accesses):
            did = _safe_id(f"data__{ep.handler_qualname}__{da.method}__{idx}")
            add_node(
                {
                    "id": did,
                    "type": "data_access",
                    "attrs": {
                        "operation": da.operation,
                        "target_entity": da.target_entity,
                        "has_ownership_predicate": da.has_ownership_predicate,
                    "ownership_predicate_type": "DIRECT" if da.has_ownership_predicate else "NONE",
                        "user_controlled_params_in_query": [
                            a for a in da.arg_names if a in ep.parameters
                        ],
                    },
                }
            )
            add_edge(sid, did, "call")
            # Mark service as data-access / mutating.
            for n in nodes:
                if n["id"] == sid:
                    n["attrs"]["performs_data_access"] = True
                    if da.operation in {"WRITE", "UPDATE", "DELETE"}:
                        n["attrs"]["performs_mutation"] = True

            # Identifier flow: if any path variable is passed by name into the call
            # args, add an idflow edge from the endpoint to this data-access node.
            for pv in ep.route_params:
                if pv in da.arg_names:
                    add_edge(eid, did, "identifier_flow", param=pv)

    pfg = PFG.model_validate(
        {
            "schema_version": "1.0",
            "application": app_name,
            "framework": "spring",
            "nodes": nodes,
            "edges": edges,
        }
    )
    from pfg.pfg.features import enrich_endpoint_features
    enrich_endpoint_features(pfg)
    return pfg
