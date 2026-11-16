"""Universal node/edge/graph types for kassi-graph.

Language-agnostic: parsers populate these; reachability consumes them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeKind(Enum):
    FUNCTION = "function"        # a def/func/method definition
    CALL = "call"                # a call site inside a function
    DECORATOR = "decorator"      # a decorator application
    IMPORT = "import"            # an import statement
    CLASS = "class"              # a class definition
    MODULE = "module"            # a source file


class Role(Enum):
    """What the adapter has labelled this node as, for reachability."""
    SOURCE = "source"            # untrusted-input entrypoint
    SINK = "sink"                # sensitive operation
    SANITIZER = "sanitizer"      # authz gate
    NEUTRAL = "neutral"          # neither — just a function in the graph


class Confidence(Enum):
    HIGH = "high"                # direct name-resolved call chain
    MEDIUM = "medium"            # decorator-wrapped or well-known indirection
    LOW = "low"                  # dynamic dispatch / unresolved indirection


@dataclass(frozen=True)
class Location:
    file: str                    # absolute path
    line: int                    # 1-indexed
    col: int = 0

    def __str__(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass
class Node:
    """A unit in the graph — typically a function, sometimes a call-site anchor.

    Node identity = (kind, qualified_name). Multiple occurrences of the same
    name across modules collapse into one node unless qualified.
    """
    id: str                      # deterministic hash: f"{kind.value}:{qualified_name}"
    kind: NodeKind
    qualified_name: str          # e.g. "zerver.views.users.get_members_backend"
    short_name: str              # last segment: "get_members_backend"
    location: Location | None = None
    role: Role = Role.NEUTRAL
    description: str = ""        # from adapter if labelled
    attributes: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Node) and self.id == other.id


@dataclass
class Edge:
    """Call-edge from caller to callee. The callsite line is in attributes."""
    src: str                     # Node.id
    dst: str                     # Node.id
    kind: str = "calls"          # calls | decorates | imports | contains
    callsite: Location | None = None
    confidence: Confidence = Confidence.HIGH

    def __hash__(self) -> int:
        return hash((self.src, self.dst, self.kind, self.callsite))


@dataclass
class Graph:
    """The unified graph produced by a parser.

    Adjacency indexes are built lazily on first lookup — this makes
    graph construction O(1) per edge, and reachability O(1) per edge-lookup.
    Any mutation to `edges` after lookup invalidates the index; call
    `invalidate_index()`.
    """
    nodes: dict[str, Node] = field(default_factory=dict)  # id → Node
    edges: list[Edge] = field(default_factory=list)
    language: str = ""
    # lazy adjacency
    _by_src: dict[str, list[Edge]] | None = field(default=None, repr=False)
    _by_dst: dict[str, list[Edge]] | None = field(default=None, repr=False)

    def add_node(self, node: Node) -> None:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
        elif existing.location is None and node.location is not None:
            self.nodes[node.id] = node

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)
        self._by_src = None
        self._by_dst = None

    def invalidate_index(self) -> None:
        self._by_src = None
        self._by_dst = None

    def _build_index(self) -> None:
        by_src: dict[str, list[Edge]] = {}
        by_dst: dict[str, list[Edge]] = {}
        for e in self.edges:
            by_src.setdefault(e.src, []).append(e)
            by_dst.setdefault(e.dst, []).append(e)
        self._by_src = by_src
        self._by_dst = by_dst

    def outgoing(self, node_id: str) -> list[Edge]:
        if self._by_src is None:
            self._build_index()
        assert self._by_src is not None
        return self._by_src.get(node_id, [])

    def incoming(self, node_id: str) -> list[Edge]:
        if self._by_dst is None:
            self._build_index()
        assert self._by_dst is not None
        return self._by_dst.get(node_id, [])

    def nodes_by_role(self, role: Role) -> list[Node]:
        return [n for n in self.nodes.values() if n.role == role]

    def stats(self) -> dict[str, int]:
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "sources": len(self.nodes_by_role(Role.SOURCE)),
            "sinks": len(self.nodes_by_role(Role.SINK)),
            "sanitizers": len(self.nodes_by_role(Role.SANITIZER)),
        }


@dataclass
class Path:
    """One sequence of node_ids from a source to a sink."""
    nodes: list[str]             # Node.ids in order; nodes[0] source, nodes[-1] sink
    edges: list[Edge]
    confidence: Confidence
    sanitizers_bypassed: list[str] = field(default_factory=list)

    @property
    def length(self) -> int:
        return len(self.nodes)


@dataclass
class Finding:
    """An unguarded source→sink path — an investigation target."""
    source_node: Node
    sink_node: Node
    path: Path
    severity_hint: str = "medium"  # low|medium|high — heuristic from adapter weights
    why: str = ""                  # one-line why this is suspicious

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": {
                "name": self.source_node.qualified_name,
                "location": str(self.source_node.location) if self.source_node.location else None,
                "description": self.source_node.description,
            },
            "sink": {
                "name": self.sink_node.qualified_name,
                "location": str(self.sink_node.location) if self.sink_node.location else None,
                "description": self.sink_node.description,
            },
            "path": [
                {"name": n, "callsite": str(e.callsite) if e.callsite else None}
                for n, e in zip(self.path.nodes, self.path.edges + [self.path.edges[-1] if self.path.edges else None])
                if e is not None
            ] if self.path.edges else [{"name": n} for n in self.path.nodes],
            "confidence": self.path.confidence.value,
            "severity_hint": self.severity_hint,
            "why": self.why,
        }
