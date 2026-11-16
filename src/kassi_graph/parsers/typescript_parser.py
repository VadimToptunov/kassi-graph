"""TypeScript/JavaScript parser via py-tree-sitter.

Supports: .ts, .tsx, .js, .jsx, .mjs, .cjs.

What we extract:
    - function_declaration, arrow_function (when assigned to a const/let),
      method_definition → Node(FUNCTION)
    - call_expression inside a function body → Edge(CALLS)
    - Handler-reference args to router.get("/", handler) → Edge(routes_to)

Known limits (Phase 3):
    - Default export, import aliases → unresolved names → MEDIUM confidence
    - TypeScript type-level sanitizers (`Guard<T>`) not modeled
    - Arrow functions assigned via destructuring are missed
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tree_sitter_typescript  # type: ignore
    from tree_sitter import Language, Node as _TSNode, Parser  # type: ignore
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "TS parser needs: pip install tree-sitter tree-sitter-typescript"
    ) from e

from kassi_graph.types import (
    Confidence,
    Edge,
    Graph,
    Location,
    Node,
    NodeKind,
)


_TS_LANG: Language | None = None
_TSX_LANG: Language | None = None


def _ts_lang() -> Language:
    global _TS_LANG
    if _TS_LANG is None:
        _TS_LANG = Language(tree_sitter_typescript.language_typescript())
    return _TS_LANG


def _tsx_lang() -> Language:
    global _TSX_LANG
    if _TSX_LANG is None:
        _TSX_LANG = Language(tree_sitter_typescript.language_tsx())
    return _TSX_LANG


def _text(node: _TSNode, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _loc(ts: _TSNode, file: str) -> Location:
    sp = ts.start_point
    row = sp[0] if isinstance(sp, tuple) else sp.row
    col = sp[1] if isinstance(sp, tuple) else sp.column
    return Location(file=file, line=row + 1, col=col)


def _node_id(kind: NodeKind, qualified_name: str) -> str:
    return f"{kind.value}:{qualified_name}"


def _call_qualified(call_node: _TSNode, src: bytes) -> tuple[str, str]:
    """Return (short_name, qualified_chain) for a call_expression.

    `router.get("/", h)`   -> ("get", "router.get")
    `app.get("/u/:id", h)` -> ("get", "app.get")
    `a.b.c(x)`             -> ("c", "a.b.c")
    `foo(x)`               -> ("foo", "foo")
    """
    fn = call_node.child_by_field_name("function")
    if fn is None:
        return ("", "")
    if fn.type == "identifier":
        name = _text(fn, src)
        return (name, name)
    if fn.type == "member_expression":
        parts: list[str] = []
        cur: _TSNode | None = fn
        while cur is not None and cur.type == "member_expression":
            prop = cur.child_by_field_name("property")
            if prop is not None:
                parts.append(_text(prop, src))
            obj = cur.child_by_field_name("object")
            if obj is None:
                break
            if obj.type == "identifier":
                parts.append(_text(obj, src))
                break
            cur = obj
        parts.reverse()
        qual = ".".join(parts) if parts else ""
        short = parts[-1] if parts else ""
        return (short, qual)
    txt = _text(fn, src)
    short = txt.split(".")[-1] if "." in txt else txt
    return (short, txt)


@dataclass
class _FileState:
    module: str
    file: str
    func_stack: list[tuple[str, str]] = field(default_factory=list)


def _process_function(
    name: str,
    body: _TSNode | None,
    loc_node: _TSNode,
    state: _FileState,
    graph: Graph,
    decorators: list[str] | None = None,
) -> None:
    qname = f"{state.module}.{name}" if state.module else name
    func_node = Node(
        id=_node_id(NodeKind.FUNCTION, qname),
        kind=NodeKind.FUNCTION,
        qualified_name=qname,
        short_name=name,
        location=_loc(loc_node, state.file),
    )
    graph.add_node(func_node)

    # Decorators (TypeScript @decorator syntax on methods/classes)
    for dec_name in decorators or []:
        dec_qname = f"@{dec_name}"
        dec_node = Node(
            id=_node_id(NodeKind.DECORATOR, dec_qname),
            kind=NodeKind.DECORATOR,
            qualified_name=dec_qname,
            short_name=dec_name,
            location=_loc(loc_node, state.file),
        )
        graph.add_node(dec_node)
        graph.add_edge(Edge(
            src=dec_node.id,
            dst=func_node.id,
            kind="decorates",
            callsite=_loc(loc_node, state.file),
        ))

    state.func_stack.append((qname, func_node.id))
    if body is not None:
        _walk_body(body, state, graph)
    state.func_stack.pop()


def _collect_decorators(node: _TSNode, src: bytes) -> list[str]:
    """TS decorators appear as siblings before the decorated member."""
    decorators: list[str] = []
    for child in node.children:
        if child.type == "decorator":
            # @expr OR @expr(args)
            exp = child.named_child(0) if child.named_child_count else None
            if exp is None:
                continue
            if exp.type == "identifier":
                decorators.append(_text(exp, src))
            elif exp.type == "call_expression":
                fn = exp.child_by_field_name("function")
                if fn is not None and fn.type == "identifier":
                    decorators.append(_text(fn, src))
                elif fn is not None and fn.type == "member_expression":
                    prop = fn.child_by_field_name("property")
                    if prop is not None:
                        decorators.append(_text(prop, src))
            elif exp.type == "member_expression":
                prop = exp.child_by_field_name("property")
                if prop is not None:
                    decorators.append(_text(prop, src))
    return decorators


def _walk_body(node: _TSNode, state: _FileState, graph: Graph) -> None:
    # We walk the body looking for call_expressions, but we also need to
    # descend into nested function_declaration / arrow_function to register
    # those as separate functions. tree-sitter's TS grammar names several
    # callable node types; just recurse without short-circuiting at calls.
    stack: list[_TSNode] = [node]
    while stack:
        cur = stack.pop()
        if cur.type == "call_expression":
            _process_call(cur, state, graph)
        for child in cur.children:
            stack.append(child)


def _process_call(call: _TSNode, state: _FileState, graph: Graph) -> None:
    src = state._src  # type: ignore[attr-defined]
    short, qual = _call_qualified(call, src)
    if not short:
        return

    if "." in qual:
        callee_qname = qual
        callee_node = Node(
            id=_node_id(NodeKind.CALL, qual),
            kind=NodeKind.CALL,
            qualified_name=callee_qname,
            short_name=short,
        )
    else:
        callee_qname = short
        callee_node = Node(
            id=_node_id(NodeKind.FUNCTION, callee_qname),
            kind=NodeKind.FUNCTION,
            qualified_name=callee_qname,
            short_name=short,
        )
    graph.add_node(callee_node)

    if state.func_stack:
        src_id = state.func_stack[-1][1]
    else:
        mod_node = Node(
            id=_node_id(NodeKind.MODULE, state.module),
            kind=NodeKind.MODULE,
            qualified_name=state.module,
            short_name=state.module.split(".")[-1] if state.module else state.module,
        )
        graph.add_node(mod_node)
        src_id = mod_node.id

    graph.add_edge(Edge(
        src=src_id,
        dst=callee_node.id,
        kind="calls",
        callsite=_loc(call, state.file),
    ))

    # Handler-ref detection — covers two idioms:
    #   (1) `app.get("/", myHandler)` — IDENTIFIER arg
    #   (2) `server.tool("name", schema, async (args) => { ... })` — inline
    #       arrow function or function expression as the LAST arg. Common in
    #       MCP, Hono, Fastify handler definitions.
    arguments = call.child_by_field_name("arguments")
    if arguments is not None:
        for child in arguments.children:
            if child.type == "identifier":
                handler_name = _text(child, src)
                if handler_name == short:
                    continue
                handler_node = Node(
                    id=_node_id(NodeKind.FUNCTION, handler_name),
                    kind=NodeKind.FUNCTION,
                    qualified_name=handler_name,
                    short_name=handler_name,
                )
                graph.add_node(handler_node)
                graph.add_edge(Edge(
                    src=callee_node.id,
                    dst=handler_node.id,
                    kind="routes_to",
                    callsite=_loc(call, state.file),
                ))
            elif child.type in ("arrow_function", "function_expression", "function"):
                # Hoist inline handler into a synthetic named function so its
                # body is traced. Name encodes call-site location for stability.
                sp = child.start_point
                row = sp[0] if isinstance(sp, tuple) else sp.row
                synth_name = f"__inline_handler_{row + 1}"
                qname = f"{state.module}.{synth_name}" if state.module else synth_name
                handler_node = Node(
                    id=_node_id(NodeKind.FUNCTION, qname),
                    kind=NodeKind.FUNCTION,
                    qualified_name=qname,
                    short_name=synth_name,
                    location=_loc(child, state.file),
                )
                graph.add_node(handler_node)
                graph.add_edge(Edge(
                    src=callee_node.id,
                    dst=handler_node.id,
                    kind="routes_to",
                    callsite=_loc(call, state.file),
                ))
                # Walk the inline handler body as if it were a function.
                body = child.child_by_field_name("body")
                if body is not None:
                    state.func_stack.append((qname, handler_node.id))
                    _walk_body(body, state, graph)
                    state.func_stack.pop()


def _visit_root(root: _TSNode, state: _FileState, graph: Graph) -> None:
    src = state._src  # type: ignore[attr-defined]
    stack: list[_TSNode] = [root]
    pending_decorators: list[str] = []
    while stack:
        cur = stack.pop()
        t = cur.type

        if t == "function_declaration":
            name_node = cur.child_by_field_name("name")
            body = cur.child_by_field_name("body")
            if name_node is not None:
                _process_function(_text(name_node, src), body, cur, state, graph,
                                   decorators=pending_decorators)
                pending_decorators = []
            continue

        if t == "method_definition":
            name_node = cur.child_by_field_name("name")
            body = cur.child_by_field_name("body")
            # Collect decorators from siblings? tree-sitter attaches decorators
            # as inner children of method_definition in many grammars.
            decs = _collect_decorators(cur, src)
            if name_node is not None:
                _process_function(_text(name_node, src), body, cur, state, graph,
                                   decorators=decs)
            continue

        if t == "arrow_function":
            # Arrow functions: `const foo = (x) => { ... }`. The containing
            # variable declaration gives us the name. We walk up at the time
            # of lexical_declaration below, so here we only process if we
            # can't name it.
            body = cur.child_by_field_name("body")
            if body is not None:
                _walk_body(body, state, graph)
            continue

        if t == "lexical_declaration" or t == "variable_declaration":
            # Look for `const/let/var NAME = (ARROW_FUNCTION)` and treat NAME
            # as a function definition.
            for v in cur.children:
                if v.type == "variable_declarator":
                    name_node = v.child_by_field_name("name")
                    value_node = v.child_by_field_name("value")
                    if (
                        name_node is not None
                        and name_node.type == "identifier"
                        and value_node is not None
                        and value_node.type in ("arrow_function", "function_expression", "function")
                    ):
                        body = value_node.child_by_field_name("body")
                        _process_function(_text(name_node, src), body, v, state, graph)
                    else:
                        for c in v.children:
                            stack.append(c)
            continue

        # Module-level call_expression — e.g. `app.get('/', h)` outside any function.
        if t == "call_expression" and not state.func_stack:
            _process_call(cur, state, graph)
            continue

        for child in cur.children:
            stack.append(child)


def parse_codebase(root: str | Path, *, excludes: list[str] | None = None) -> Graph:
    """Walk root, parse every .ts/.tsx/.js/.jsx/.mjs/.cjs file."""
    root_path = Path(root).resolve()
    excludes = excludes or [
        "/node_modules/", "/dist/", "/build/", "/.next/", "/coverage/",
        ".d.ts", ".min.js", ".min.ts", ".test.", ".spec.",
    ]
    graph = Graph(language="typescript")
    parser_ts = Parser(_ts_lang())
    parser_tsx = Parser(_tsx_lang())

    exts = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
    files: list[str] = []
    for dirpath, _, filenames in os.walk(root_path):
        for fn in filenames:
            ext = os.path.splitext(fn)[1]
            if ext not in exts:
                continue
            full = os.path.join(dirpath, fn)
            if any(ex in full for ex in excludes):
                continue
            files.append(full)

    for file in files:
        rel = os.path.relpath(file, root_path)
        module = rel.replace(os.sep, ".").rsplit(".", 1)[0]
        try:
            with open(file, "rb") as f:
                src = f.read()
            is_tsx = file.endswith(".tsx") or file.endswith(".jsx")
            tree = (parser_tsx if is_tsx else parser_ts).parse(src)
        except (OSError, ValueError):
            continue
        state = _FileState(module=module, file=file)
        state._src = src  # type: ignore[attr-defined]
        _visit_root(tree.root_node, state, graph)

    return graph


def resolve_short_name_edges(graph: Graph) -> None:
    by_short: dict[str, list[Node]] = {}
    for n in graph.nodes.values():
        if n.kind == NodeKind.FUNCTION and n.location is not None:
            by_short.setdefault(n.short_name, []).append(n)
    for edge in graph.edges:
        if edge.kind not in ("calls", "routes_to"):
            continue
        dst = graph.nodes.get(edge.dst)
        if dst is None or dst.kind == NodeKind.CALL or dst.location is not None:
            continue
        candidates = by_short.get(dst.short_name, [])
        if len(candidates) == 1:
            edge.dst = candidates[0].id
        elif len(candidates) > 1:
            edge.confidence = Confidence.MEDIUM
