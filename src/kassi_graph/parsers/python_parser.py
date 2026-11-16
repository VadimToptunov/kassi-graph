"""Python parser — builds a kassi-graph.Graph from a codebase using stdlib `ast`.

What we extract:
    - Function/method definitions → Node(FUNCTION)
    - Decorator applications on functions → Node(DECORATOR) + edge DECORATES
    - Call sites inside a function → Edge(CALLS) from containing-function to called-name

Limits (Phase 0):
    - Name resolution is unqualified: we store short-name + file path, and do a
      global match-by-short-name during edge resolution. Cross-module exact
      resolution requires an import graph; Phase 1.
    - Class method resolution is partial: `self.foo()` is captured as a call to
      the class's method if the containing class is known.
    - Decorator semantics: we only record presence, not transformations.
"""
from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from pathlib import Path

from kassi_graph.types import (
    Confidence,
    Edge,
    Graph,
    Location,
    Node,
    NodeKind,
    Role,
)


# -------------------- helpers --------------------

def _qualify(module: str, name: str) -> str:
    return f"{module}.{name}" if module else name


def _node_id(kind: NodeKind, qualified_name: str) -> str:
    return f"{kind.value}:{qualified_name}"


def _get_decorator_name(dec: ast.expr) -> str:
    """Return the short name of a decorator expression.

    @foo               -> "foo"
    @foo.bar           -> "bar"
    @foo(a, b)         -> "foo"
    @foo.bar(a)        -> "bar"
    """
    if isinstance(dec, ast.Name):
        return dec.id
    if isinstance(dec, ast.Attribute):
        return dec.attr
    if isinstance(dec, ast.Call):
        return _get_decorator_name(dec.func)
    return ""


def _get_call_name(call: ast.Call) -> str:
    """Return the short name of a call expression.

    foo(x)       -> "foo"
    foo.bar(x)   -> "bar"
    foo.bar.baz(x) -> "baz"
    """
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _get_call_qualified(call: ast.Call) -> str:
    """Return a dotted name approximating the full attribute chain.

    `Model.objects.filter(x)` -> "Model.objects.filter"
    `foo.bar(x)` -> "foo.bar"
    `foo(x)` -> "foo"
    """
    func = call.func
    parts: list[str] = []
    cur: ast.expr | None = func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    parts.reverse()
    return ".".join(parts) if parts else ""


# -------------------- per-file parser --------------------

@dataclass
class _FileState:
    module: str
    file: str
    # stack of (function_qualified_name, function_node_id)
    func_stack: list[tuple[str, str]] = field(default_factory=list)
    class_stack: list[str] = field(default_factory=list)


class _Visitor(ast.NodeVisitor):
    def __init__(self, state: _FileState, graph: Graph) -> None:
        self.s = state
        self.g = graph

    def _loc(self, node: ast.AST) -> Location:
        line = getattr(node, "lineno", 0)
        col = getattr(node, "col_offset", 0)
        return Location(file=self.s.file, line=line, col=col)

    def _qualified(self, name: str) -> str:
        parts = [self.s.module]
        parts.extend(self.s.class_stack)
        parts.append(name)
        return ".".join(p for p in parts if p)

    def _visit_funcdef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qname = self._qualified(node.name)
        func_node = Node(
            id=_node_id(NodeKind.FUNCTION, qname),
            kind=NodeKind.FUNCTION,
            qualified_name=qname,
            short_name=node.name,
            location=self._loc(node),
        )
        self.g.add_node(func_node)

        # Record decorators as nodes + edges
        for dec in node.decorator_list:
            dname = _get_decorator_name(dec)
            if not dname:
                continue
            dec_qname = f"@{dname}"
            dec_node = Node(
                id=_node_id(NodeKind.DECORATOR, dec_qname),
                kind=NodeKind.DECORATOR,
                qualified_name=dec_qname,
                short_name=dname,
                location=self._loc(dec),
            )
            self.g.add_node(dec_node)
            self.g.add_edge(Edge(
                src=dec_node.id,
                dst=func_node.id,
                kind="decorates",
                callsite=self._loc(dec),
            ))

        # Recurse into body with this function as the current container.
        self.s.func_stack.append((qname, func_node.id))
        self.generic_visit(node)
        self.s.func_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_funcdef(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_funcdef(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.s.class_stack.append(node.name)
        self.generic_visit(node)
        self.s.class_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        if not self.s.func_stack:
            # Module-level call (urlpatterns = [rest_path(...), ...]). We STILL
            # want to register this so URL-pattern sources are found.
            qual = _get_call_qualified(node)
            short = _get_call_name(node) or qual
            callee_qname = f"call:{qual}"
            callee_node = Node(
                id=_node_id(NodeKind.CALL, callee_qname),
                kind=NodeKind.CALL,
                qualified_name=qual,
                short_name=short,
                location=self._loc(node),
            )
            self.g.add_node(callee_node)
            # No containing function; call-site exists on its own.
        else:
            # Edge from containing function to the called NAME.
            qual = _get_call_qualified(node)
            short = _get_call_name(node) or qual
            if not short:
                self.generic_visit(node)
                return
            # For chained attribute calls (X.Y.Z()), use the full chain as the
            # node's qualified_name so sink patterns like "*.objects.filter"
            # can match. Node ID uses chain too so different chains don't
            # collapse. For simple name calls (foo()), collapse by short name
            # so reachability can resolve across files.
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
            self.g.add_node(callee_node)
            self.g.add_edge(Edge(
                src=self.s.func_stack[-1][1],
                dst=callee_node.id,
                kind="calls",
                callsite=self._loc(node),
            ))
        self.generic_visit(node)


# -------------------- top-level API --------------------

def parse_codebase(root: str | Path, *, excludes: list[str] | None = None) -> Graph:
    """Walk `root`, parse every .py file, return assembled graph.

    `excludes` are substring patterns against paths; default skips tests/.
    """
    root_path = Path(root).resolve()
    excludes = excludes or ["/tests/", "/test_", "/migrations/", "/__pycache__/", "/node_modules/"]
    graph = Graph(language="python")

    py_files = []
    for dirpath, _, filenames in os.walk(root_path):
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            full = os.path.join(dirpath, fn)
            if any(ex in full for ex in excludes):
                continue
            py_files.append(full)

    for file in py_files:
        rel = os.path.relpath(file, root_path)
        module = rel.replace(os.sep, ".").removesuffix(".py")
        try:
            with open(file, "rb") as f:
                src = f.read()
            tree = ast.parse(src, filename=file)
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue
        state = _FileState(module=module, file=file)
        _Visitor(state, graph).visit(tree)

    return graph


def resolve_short_name_edges(graph: Graph) -> None:
    """Rewrite edges whose dst is an unqualified short-name to point at a
    defined function with that short name, when exactly one exists.

    Ambiguity (multiple defs with same short name) leaves the edge unresolved
    (it still points at the synthetic short-name node). Caller sees ambiguity
    as MEDIUM-confidence at reachability time.
    """
    by_short: dict[str, list[Node]] = {}
    for n in graph.nodes.values():
        if n.kind == NodeKind.FUNCTION and n.location is not None:
            by_short.setdefault(n.short_name, []).append(n)

    rewrites = 0
    for edge in graph.edges:
        if edge.kind != "calls":
            continue
        dst_node = graph.nodes.get(edge.dst)
        if dst_node is None:
            continue
        # NEVER rewrite CALL-kind destinations — those are chained-call
        # sink candidates (e.g. "User.objects.filter") created with the full
        # attribute chain as their id. Collapsing them to a FUNCTION
        # short-name node would lose the pattern-matching surface.
        if dst_node.kind == NodeKind.CALL:
            continue
        # Also skip already-resolved FUNCTION nodes (ones that have a real
        # location from a def).
        if dst_node.location is not None:
            continue
        # dst is a synthetic short-name placeholder. Try to resolve.
        candidates = by_short.get(dst_node.short_name, [])
        if len(candidates) == 1:
            edge.dst = candidates[0].id
            rewrites += 1
        elif len(candidates) > 1:
            # Keep the placeholder but downgrade confidence.
            edge.confidence = Confidence.MEDIUM

    _ = rewrites  # for debugging; silent in Phase 0
