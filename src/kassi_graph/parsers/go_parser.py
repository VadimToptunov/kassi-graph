"""Go parser via py-tree-sitter.

What we extract:
    - func declarations and method declarations → Node(FUNCTION)
    - Call expressions inside a function → Edge(CALLS) from containing-function
      to the called name (with full selector chain if present).

Handler registrations such as `http.HandleFunc("/path", MyHandler)` are
NOT treated as decorators. Instead, the ADAPTER specifies them as `call`-kind
SOURCE patterns matching e.g. `http.HandleFunc` or `router.GET`. The handler
name (second arg) is identified at label time by a lightweight per-pattern
convention: when a call matches a source pattern of kind=call with attribute
`handler_arg_index`, the parser creates a FUNCTION_REFERENCE edge from the
call to the referenced function. For Phase 2, simplest: just emit the call
itself as a module-level CALL node that becomes a SOURCE, and emit the
handler-ref as an edge of kind `routes_to`.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tree_sitter_go  # type: ignore
    from tree_sitter import Language, Node as _TSNode, Parser  # type: ignore
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "Go parser needs: pip install tree-sitter tree-sitter-go"
    ) from e

from kassi_graph.types import (
    Confidence,
    Edge,
    Graph,
    Location,
    Node,
    NodeKind,
)

_GO_LANG: Language | None = None


def _lang() -> Language:
    global _GO_LANG
    if _GO_LANG is None:
        _GO_LANG = Language(tree_sitter_go.language())
    return _GO_LANG


def _text(node: _TSNode, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _loc(ts: _TSNode, file: str) -> Location:
    start_point = ts.start_point
    row = start_point[0] if isinstance(start_point, tuple) else start_point.row
    col = start_point[1] if isinstance(start_point, tuple) else start_point.column
    return Location(file=file, line=row + 1, col=col)


def _node_id(kind: NodeKind, qualified_name: str) -> str:
    return f"{kind.value}:{qualified_name}"


def _call_qualified(call_node: _TSNode, src: bytes) -> tuple[str, str]:
    """Return (short_name, qualified_chain) for a call_expression.

    `http.HandleFunc(x, y)`      -> ("HandleFunc", "http.HandleFunc")
    `router.GET("/", h)`         -> ("GET", "router.GET")
    `foo(x)`                     -> ("foo", "foo")
    `pkg.Struct.Method(x)`       -> ("Method", "pkg.Struct.Method")
    `r.Handle("/", h)`           -> ("Handle", "r.Handle")
    """
    function_child = call_node.child_by_field_name("function")
    if function_child is None:
        return ("", "")
    if function_child.type == "identifier":
        name = _text(function_child, src)
        return (name, name)
    if function_child.type == "selector_expression":
        # a.b.c.method — walk left siblings
        parts: list[str] = []
        cur: _TSNode | None = function_child
        while cur is not None and cur.type == "selector_expression":
            field = cur.child_by_field_name("field")
            if field is not None:
                parts.append(_text(field, src))
            operand = cur.child_by_field_name("operand")
            if operand is None:
                break
            if operand.type == "identifier":
                parts.append(_text(operand, src))
                break
            cur = operand
        parts.reverse()
        qual = ".".join(parts) if parts else ""
        short = parts[-1] if parts else ""
        return (short, qual)
    # Fallback — raw text
    txt = _text(function_child, src)
    short = txt.split(".")[-1] if "." in txt else txt
    return (short, txt)


@dataclass
class _FileState:
    module: str
    file: str
    func_stack: list[tuple[str, str]] = field(default_factory=list)
    # For method_declaration: receiver type name becomes class scope.
    receiver_stack: list[str] = field(default_factory=list)


def _process_function(
    node: _TSNode,
    src: bytes,
    state: _FileState,
    graph: Graph,
    *,
    is_method: bool,
) -> None:
    name_node = node.child_by_field_name("name")
    if name_node is None:
        return
    name = _text(name_node, src)

    # Compose qualified name: module + receiver + name
    parts = [state.module]
    if is_method:
        receiver = node.child_by_field_name("receiver")
        if receiver is not None:
            # Receiver has subtree with a type — e.g. (r *Foo) -> "Foo"
            rtype_text = _text(receiver, src)
            # crude extract between asterisk/space and closing paren
            inner = rtype_text.strip("() ").lstrip("*")
            inner_parts = inner.split()
            # e.g. "r *Foo" -> ["r", "*Foo"] after strip; take last stripped of *
            if inner_parts:
                receiver_type = inner_parts[-1].lstrip("*")
                parts.append(receiver_type)
    parts.append(name)
    qname = ".".join(p for p in parts if p)

    func_node = Node(
        id=_node_id(NodeKind.FUNCTION, qname),
        kind=NodeKind.FUNCTION,
        qualified_name=qname,
        short_name=name,
        location=_loc(node, state.file),
    )
    graph.add_node(func_node)

    state.func_stack.append((qname, func_node.id))
    body = node.child_by_field_name("body")
    if body is not None:
        _walk_for_calls(body, src, state, graph)
    state.func_stack.pop()


def _walk_for_calls(
    node: _TSNode,
    src: bytes,
    state: _FileState,
    graph: Graph,
) -> None:
    """Recursive walk collecting call_expression nodes under `node`."""
    stack: list[_TSNode] = [node]
    while stack:
        cur = stack.pop()
        if cur.type == "call_expression":
            _process_call(cur, src, state, graph)
        # Don't recurse into nested function literals? We DO want to capture
        # calls inside anonymous functions passed as arguments — Go closures
        # often ARE the request handler. Keep walking.
        for child in cur.children:
            stack.append(child)


def _process_call(
    call: _TSNode,
    src: bytes,
    state: _FileState,
    graph: Graph,
) -> None:
    short, qual = _call_qualified(call, src)
    if not short:
        return

    # Determine callee node
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

    # Determine src: containing function (if any) or module-level
    if state.func_stack:
        src_id = state.func_stack[-1][1]
    else:
        # Module-level call — emit synthetic module node as src.
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

    # Additionally: if the call has arguments that are IDENTIFIERS matching
    # local function definitions, emit a "routes_to" edge — this captures the
    # `http.HandleFunc("/", MyHandler)` pattern.
    arguments = call.child_by_field_name("arguments")
    if arguments is not None:
        for child in arguments.children:
            if child.type == "identifier":
                handler_name = _text(child, src)
                if handler_name == short:
                    continue  # self
                # Emit reference edge from the call to the handler name.
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


def _visit_root(node: _TSNode, src: bytes, state: _FileState, graph: Graph) -> None:
    if node.type == "function_declaration":
        _process_function(node, src, state, graph, is_method=False)
        return
    if node.type == "method_declaration":
        _process_function(node, src, state, graph, is_method=True)
        return
    if node.type == "call_expression" and not state.func_stack:
        # Module-level or init() scope. The walker below still enters function
        # bodies via _process_function, so we only hit this at package scope.
        _process_call(node, src, state, graph)
        return
    for child in node.children:
        _visit_root(child, src, state, graph)


def parse_codebase(root: str | Path, *, excludes: list[str] | None = None) -> Graph:
    """Walk root, parse every .go file, return assembled graph.

    `excludes` are substring patterns against paths; defaults skip vendor/,
    tests, and generated code.
    """
    root_path = Path(root).resolve()
    excludes = excludes or [
        "/vendor/", "/testdata/", "_test.go", ".pb.go", ".gen.go", "/node_modules/",
    ]
    graph = Graph(language="go")
    parser = Parser(_lang())

    go_files: list[str] = []
    for dirpath, _, filenames in os.walk(root_path):
        for fn in filenames:
            if not fn.endswith(".go"):
                continue
            full = os.path.join(dirpath, fn)
            if any(ex in full for ex in excludes):
                continue
            go_files.append(full)

    for file in go_files:
        rel = os.path.relpath(file, root_path)
        module = rel.replace(os.sep, ".").removesuffix(".go")
        try:
            with open(file, "rb") as f:
                src = f.read()
            tree = parser.parse(src)
        except (OSError, ValueError):
            continue
        state = _FileState(module=module, file=file)
        _visit_root(tree.root_node, src, state, graph)

    return graph


def resolve_short_name_edges(graph: Graph) -> None:
    """Rewrite edges whose dst is an unresolved short-name FUNCTION node to
    point at a defined function with that short name, if exactly one exists.

    Does NOT rewrite CALL-kind destinations (those are sink/sanitizer anchors).
    """
    by_short: dict[str, list[Node]] = {}
    for n in graph.nodes.values():
        if n.kind == NodeKind.FUNCTION and n.location is not None:
            by_short.setdefault(n.short_name, []).append(n)

    for edge in graph.edges:
        if edge.kind not in ("calls", "routes_to"):
            continue
        dst = graph.nodes.get(edge.dst)
        if dst is None:
            continue
        if dst.kind == NodeKind.CALL:
            continue
        if dst.location is not None:
            continue
        candidates = by_short.get(dst.short_name, [])
        if len(candidates) == 1:
            edge.dst = candidates[0].id
        elif len(candidates) > 1:
            edge.confidence = Confidence.MEDIUM


# unused import silence
_ = Any
