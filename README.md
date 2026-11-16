# kassi-graph

Reachability analysis for source→sink paths with sanitizer gates. Framework-agnostic core + pluggable YAML adapters. Designed to plug into every kassi-* tool that needs static authz audit.

## What it does (one sentence)

> Given a codebase and a framework adapter, enumerate every path from an untrusted-input source (HTTP endpoint, RPC handler, message consumer) to a sensitive sink (DB write, file serve, event broadcast) and flag paths that do NOT pass through a required sanitizer (authz check).

## Why

My manual grep-based Zulip audit took 3 hours and closed 8/8 hypotheses. That doesn't scale and doesn't guarantee completeness — I grepped what I thought to grep, not every reachable source→sink path. `kassi-graph` reduces the search space from "all endpoints" to "endpoints the engine thinks are unguarded", sorted by sink sensitivity.

## Install (dev)

```bash
cd kassi-graph
python3 -m venv .venv
.venv/bin/pip install -e .
```

## Quickstart — audit a Django/Zulip codebase

```bash
# Scan: just graph stats
.venv/bin/kassi-graph scan --target /path/to/zulip/zerver

# Query: enumerate unguarded source→sink paths
.venv/bin/kassi-graph query --adapter zulip --target /path/to/zulip/zerver

# Go codebase (uses tree-sitter-go)
.venv/bin/kassi-graph scan --target /path/to/mimir/pkg --language go
.venv/bin/kassi-graph query --adapter go_http --target /path/to/mimir/pkg

# Machine-readable
.venv/bin/kassi-graph query --adapter zulip --target /path --json > findings.json

# List available adapters
.venv/bin/kassi-graph list-adapters
# → django  fastapi  flask  go_http  net_http  zulip
```

## Perf

| Codebase | Size | Nodes | Edges | Parse | Query |
|---|---|---|---|---|---|
| hunt-zulip (`zerver/`) | 204 MB | 13,896 | 33,617 | ~1 s | ~2 s |
| hunt-mimir (`pkg/`, Go) | 248 MB | 30,641 | 93,160 | ~1.4 s | ~4.5 s |

(Query time includes BFS over the full graph with adjacency-indexed outgoing edges.)

## Example output

```
[  1] medium/  high | add_navigation_view (zerver/views/navigation_views.py:46)
       → ... → NavigationView.objects.create (zerver/actions/navigation_views.py:12)
       chain: @typed_endpoint → add_navigation_view → do_add_navigation_view → create
       why: add_navigation_view → … → create; no sanitizer on this path
```

Severity hint (`high|medium|low`) comes from the adapter's `sink_weights`. Confidence (`high|medium|low`) is `high` only if the full call chain is name-resolved; `medium` if the path includes an unresolved short-name placeholder.

## Writing a new adapter

Adapters are YAML. Minimal example:

```yaml
name: my-framework
language: python
sources:
  - kind: decorator
    pattern: "api_view"
sinks:
  - kind: call
    pattern: "*.objects.save"
  - kind: call
    pattern: "*.objects.delete"
sanitizers:
  - kind: call
    pattern: "check_permissions"
  - kind: decorator
    pattern: "require_admin"
sink_weights:
  "*.objects.delete": "high"
```

Save as `src/kassi_graph/adapters/my-framework.yaml` and invoke with `--adapter my-framework`.

Pattern syntax: `fnmatch` globs with `{a,b,c}` brace expansion. Add `is_regex: true` to use regex instead.

## Integration with other kassi-* tools

**Mode 1 — library (Python):**
```python
from kassi_graph import Adapter
from kassi_graph.parsers.python_parser import parse_codebase, resolve_short_name_edges
from kassi_graph.reachability import unguarded_findings

g = parse_codebase("/path/to/codebase")
resolve_short_name_edges(g)
findings = unguarded_findings(g, Adapter.load("zulip"))
for f in findings:
    print(f.source_node.qualified_name, "→", f.sink_node.qualified_name)
```

**Mode 2 — subprocess from any language (JSON stdout):**
```bash
kassi-graph query --adapter zulip --target . --json > findings.json
# Go/Rust/TS/Node consume findings.json
```

**Planned consumers:**
- **kassi-mcp-scanner** — call kassi-graph for MCP-framework adapter analysis
- **kassi-web-scanner** — TypeScript/Node adapters once parser is added
- **kassi-go-scanner** — Go adapters (net/http, gin, chi) once parser is added
- **kassi-web-probe** — use kassi-graph output as initial attack hypothesis list
- **kassi-triage** — rank findings using graph-depth and sink-weight signal

## Phase plan

| Phase | Deliverable | Status |
|---|---|---|
| 0 | Python stdlib `ast` parser + Django/Zulip adapters + reachability + CLI | ✅ shipped |
| 1 | Flask + FastAPI adapters | ✅ shipped |
| 2 | Go parser via tree-sitter-go + net/http, broad go_http adapter + 30x perf (adj-index) | ✅ shipped |
| 2.5 | Test corpus (DVWA-equivalents known-vuln) for regression | pending |
| 3 | TypeScript parser + Express + Fastify adapters | pending |
| 4 | Plugin API — integrate into kassi-mcp-scanner first | pending |
| 5 | Dynamic-dispatch resolver + inter-procedural dataflow | pending |

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full design and honest limits.

## Limits (Phase 0, honest)

- Python-only. Go/TS/Java use tree-sitter in Phase 2+.
- Flow-insensitive: if function F calls a sanitizer *anywhere*, all F→sink paths are considered guarded. This matches real-world "function handles authz" trust but misclassifies F that sanitizes user A and then reaches a sink keyed on user B.
- Static call graph only. Dynamic dispatch (getattr, descriptors, Protocol satisfaction) unresolved.
- Short-name resolution — if two files define a function `check()`, edges to that short name become MEDIUM confidence.

What this means in practice: findings are **hypotheses**, not proofs. Human review required for each HIGH. But `kassi-graph` dramatically shrinks the review surface and ranks it.
