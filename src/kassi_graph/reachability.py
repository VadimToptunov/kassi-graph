"""Reachability analysis: enumerate unguarded source→sink paths.

Given a Graph and an Adapter:
    1. Mark nodes with Role (SOURCE/SINK/SANITIZER) based on adapter patterns.
    2. For each source, BFS the call graph to any sink.
    3. A path is UNGUARDED if no node along the way (inclusive) is a SANITIZER.
    4. Each unguarded source→sink pair becomes a Finding.

Decorators:
    - A SOURCE decorator attached to function F -> treat F as the source.
    - A SANITIZER decorator attached to function F -> treat F as a sanitizer
      entry point (the function body is considered "whitewashed" from the top).
    - This means a view decorated with @require_realm_admin is implicitly
      sanitized at its own start, regardless of what it calls inside.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from kassi_graph.adapters.schema import Adapter, PatternSpec
from kassi_graph.types import (
    Confidence,
    Finding,
    Graph,
    Node,
    NodeKind,
    Path,
    Role,
)


# -------------------- labelling --------------------

def _match_any(name: str, qualified: str, patterns: list[PatternSpec]) -> PatternSpec | None:
    for p in patterns:
        # Match against short name OR qualified attribute chain (e.g. Model.objects.get)
        if p.matches(name) or p.matches(qualified):
            return p
    return None


def label_graph(graph: Graph, adapter: Adapter) -> dict[str, list[str]]:
    """Mutates graph.nodes to assign roles. Also tags functions decorated with
    source/sanitizer decorators. Returns a stats dict.

    Returns {role.value: [node_id, ...]} for post-run inspection.
    """
    # First pass: label individual nodes by their own name.
    for node in graph.nodes.values():
        name = node.short_name
        qualified = node.qualified_name

        if node.kind == NodeKind.DECORATOR:
            m = _match_any(name, qualified, [p for p in adapter.sources if p.kind == "decorator"])
            if m is not None:
                node.role = Role.SOURCE
                node.description = m.description or name
                continue
            m = _match_any(name, qualified, [p for p in adapter.sanitizers if p.kind == "decorator"])
            if m is not None:
                node.role = Role.SANITIZER
                node.description = m.description or name
                continue

        if node.kind in (NodeKind.CALL, NodeKind.FUNCTION):
            # Order of precedence: sanitizer > sink > source. (A node labelled
            # a sanitizer by its own definition shouldn't be re-labelled a sink
            # just because something inside it looks sink-shaped.)
            m = _match_any(name, qualified, [p for p in adapter.sanitizers if p.kind == "call"])
            if m is not None:
                node.role = Role.SANITIZER
                node.description = m.description or name
                continue
            m = _match_any(name, qualified, [p for p in adapter.sinks if p.kind == "call"])
            if m is not None:
                node.role = Role.SINK
                node.description = m.description or name
                continue
            m = _match_any(name, qualified, [p for p in adapter.sources if p.kind == "call"])
            if m is not None:
                node.role = Role.SOURCE
                node.description = m.description or name
                continue

    # Second pass: propagate decorator-based roles to the decorated function.
    # If a function has a SOURCE decorator attached, the function itself becomes
    # a SOURCE (entry to be probed). If it has a SANITIZER decorator, the
    # function is treated as sanitized at its entrypoint.
    decorator_targets: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge.kind != "decorates":
            continue
        decorator_targets.setdefault(edge.dst, []).append(edge.src)

    for target_id, decorator_ids in decorator_targets.items():
        target = graph.nodes.get(target_id)
        if target is None:
            continue
        for d_id in decorator_ids:
            d = graph.nodes.get(d_id)
            if d is None:
                continue
            if d.role == Role.SOURCE and target.role == Role.NEUTRAL:
                target.role = Role.SOURCE
                target.description = f"decorated with {d.short_name}"
            elif d.role == Role.SANITIZER:
                # Decorator-sanitized function: the function body starts in a
                # sanitized state. We mark the function as sanitizer so paths
                # passing through it are considered guarded.
                #
                # This is semantically the right call for @require_realm_admin
                # but SLIGHTLY aggressive — a sanitizer-decorated view can still
                # call a sink in a way that bypasses the decorator's check
                # (e.g. the decorator only verifies auth level, but the body
                # still needs object-level authz). Phase 5 refines this.
                if target.role in (Role.NEUTRAL, Role.SOURCE):
                    target.role = Role.SANITIZER
                    target.description = (target.description + " + " if target.description else "") + f"decorated with {d.short_name}"

    stats: dict[str, list[str]] = {r.value: [] for r in Role}
    for n in graph.nodes.values():
        stats[n.role.value].append(n.id)
    return stats


# -------------------- reachability --------------------

@dataclass
class _BFSItem:
    node_id: str
    path: list[str]
    sanitized: bool


def _function_calls_sanitizer(graph: Graph, func_id: str) -> bool:
    """Flow-insensitive heuristic: does this function call at least one
    sanitizer anywhere in its body? If yes, we treat all of its outgoing
    paths as sanitized.

    Known trade-off: this is coarse. A function that sanitizes user A and
    then reaches a sink keyed on user B is falsely marked guarded. Phase 5
    adds flow-sensitivity via CFG. For now: this matches how Zulip code
    review grants "authz handled" trust — same assumption, aggregated.
    """
    for edge in graph.outgoing(func_id):
        if edge.kind != "calls":
            continue
        dst = graph.nodes.get(edge.dst)
        if dst is not None and dst.role == Role.SANITIZER:
            return True
    return False


def _reachable(
    graph: Graph, source_id: str, sink_role: Role, *, max_depth: int = 8, max_paths_per_source: int = 20
) -> list[tuple[str, list[str]]]:
    """BFS from source. Return list of (sink_id, path) for sinks reachable
    WITHOUT passing through a sanitizer.

    A path is a list of node_ids starting with source and ending with the sink.
    `max_depth` caps the search to avoid explosion.
    `max_paths_per_source` caps results per source.
    """
    results: list[tuple[str, list[str]]] = []
    visited_states: set[tuple[str, bool]] = set()
    queue: deque[_BFSItem] = deque()
    # Flow-insensitive pre-check: if source function itself calls any
    # sanitizer, treat it as already sanitized for all onward hops.
    source_pre_sanitized = _function_calls_sanitizer(graph, source_id)
    queue.append(_BFSItem(node_id=source_id, path=[source_id], sanitized=source_pre_sanitized))

    while queue and len(results) < max_paths_per_source:
        item = queue.popleft()
        node = graph.nodes.get(item.node_id)
        if node is None:
            continue
        # Only dedup intermediate nodes. For sinks, each distinct path is a
        # separate finding — different callers to the same sink are different
        # bugs.
        if node.role != sink_role:
            state = (item.node_id, item.sanitized)
            if state in visited_states:
                continue
            visited_states.add(state)

        if len(item.path) > max_depth:
            continue

        # If this node is a sanitizer, mark path as sanitized and keep walking.
        sanitized_now = item.sanitized or (node.role == Role.SANITIZER and item.node_id != source_id)

        # Also: if the current node is a function that calls a sanitizer in
        # its own body, sanitize onward hops. Phase-0 flow-insensitive rule.
        if not sanitized_now and _function_calls_sanitizer(graph, item.node_id):
            sanitized_now = True

        # Hit a sink.
        if node.role == sink_role and item.node_id != source_id:
            if not sanitized_now:
                results.append((item.node_id, item.path))
            continue

        # Expand outgoing edges.
        for edge in graph.outgoing(item.node_id):
            if edge.dst == item.node_id:
                continue
            if edge.dst in item.path:
                continue  # avoid cycles
            queue.append(_BFSItem(
                node_id=edge.dst,
                path=item.path + [edge.dst],
                sanitized=sanitized_now,
            ))

    return results


def unguarded_findings(
    graph: Graph, adapter: Adapter, *,
    max_depth: int = 8,
    max_paths_per_source: int = 20,
    exclude_path_substrings: list[str] | None = None,
    dedup: bool = True,
) -> list[Finding]:
    """Label graph then enumerate unguarded source→sink paths.

    `exclude_path_substrings`: filter out findings whose source OR sink
    location contains any of these substrings. Use to drop pre-auth flows,
    test fixtures, vendored code, etc.

    `dedup`: when True (default), collapse findings that share the same
    (anchor_function, sink_location) key — picks the shortest path as the
    canonical representation. This removes the typical "decorator vs
    function" double-reporting.
    """
    label_graph(graph, adapter)
    excludes = exclude_path_substrings or []
    findings: list[Finding] = []
    for source in graph.nodes_by_role(Role.SOURCE):
        for sink_id, path in _reachable(
            graph, source.id, Role.SINK,
            max_depth=max_depth,
            max_paths_per_source=max_paths_per_source,
        ):
            sink = graph.nodes.get(sink_id)
            if sink is None:
                continue
            # Severity: pick from adapter.sink_weights (match by short_name)
            sev = adapter.sink_weights.get(sink.short_name, "medium")
            # Confidence: assume HIGH unless path contains a synthetic (unresolved) node
            conf = Confidence.HIGH
            for nid in path:
                n = graph.nodes.get(nid)
                if n is not None and n.kind == NodeKind.FUNCTION and n.location is None:
                    conf = Confidence.MEDIUM
                    break
            # Build Path with edges along the way (or empty if unresolved)
            edges = []
            for a, b in zip(path, path[1:]):
                outs = [e for e in graph.outgoing(a) if e.dst == b]
                if outs:
                    edges.append(outs[0])
            fnd = Finding(
                source_node=source,
                sink_node=sink,
                path=Path(nodes=list(path), edges=edges, confidence=conf),
                severity_hint=sev,
                why=f"{source.short_name} → … → {sink.short_name}; no sanitizer on this path",
            )
            # Exclude filter: drop if source OR sink location contains any
            # of the user-supplied substrings. Useful for pre-auth flows,
            # test fixtures, vendored code, generated code.
            if excludes:
                src_loc = str(source.location) if source.location else ""
                sink_loc = str(sink.location) if sink.location else ""
                if any(ex in src_loc or ex in sink_loc for ex in excludes):
                    continue
            findings.append(fnd)

    if dedup and findings:
        # Collapse: (anchor_function, sink_file:sink_line) → shortest path.
        # The "anchor function" is the innermost non-decorator FUNCTION node
        # on the source side — resolves the "decorator view vs function view"
        # double-reporting.
        def _anchor(f: Finding) -> str:
            # Walk the path from source; first FUNCTION node WITH a location is the anchor.
            for nid in f.path.nodes:
                n = graph.nodes.get(nid)
                if n is not None and n.kind == NodeKind.FUNCTION and n.location is not None:
                    return n.qualified_name
            return f.source_node.qualified_name

        def _key(f: Finding) -> tuple[str, str]:
            sink_loc = str(f.sink_node.location) if f.sink_node.location else f.sink_node.qualified_name
            return (_anchor(f), sink_loc)

        best: dict[tuple[str, str], Finding] = {}
        for f in findings:
            k = _key(f)
            cur = best.get(k)
            if cur is None or f.path.length < cur.path.length:
                best[k] = f
        findings = list(best.values())

    return findings
