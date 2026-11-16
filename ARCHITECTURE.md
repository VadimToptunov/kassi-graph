# kassi-graph — architecture

## Problem

Static authz audit via grep gives function-level coverage but misses workflow-level gaps. When auditing Zulip I spent 3 hours tracing hypothesis-by-hypothesis and closed 8/8 on static. That approach doesn't scale and doesn't guarantee completeness — I grepped what I thought to grep, not every reachable source→sink path.

**Target capability:** given a codebase and a framework adapter, enumerate every path from an untrusted-input source (HTTP endpoint, RPC handler, message-queue consumer) to a sensitive sink (DB write, file serve, external call, event broadcast) and flag paths that do NOT pass through a required sanitizer (authz check). Those unguarded paths are the investigation targets.

## Design principles

1. **Standalone tool with JSON I/O.** Other kassi-* tools call `kassi-graph query --adapter <name> --target <dir>` and consume stdout. No embedded lib per language.
2. **Framework-agnostic core + pluggable adapters.** Adapters are YAML files declaring sources/sinks/sanitizers patterns. Adding a new framework = new YAML, no engine change.
3. **Language adapters are additive.** Phase 0 Python-only (Django/Flask/FastAPI). Phase 2+ Go/TS/Java via tree-sitter.
4. **Reachability with gatekeepers, not just pattern-match.** The engine builds the call graph among source/sink/sanitizer nodes and computes paths that avoid all sanitizer nodes. This is strictly stronger than Semgrep's pattern-matching (which can't model "not passing through").
5. **Honest about limits.** Dynamic dispatch (Django's `@require_...`, decorator chains, DI containers, reflection) is partially modeled. Tool outputs confidence per path: HIGH (direct call chain), MEDIUM (decorator-wrapped), LOW (dynamic dispatch — needs manual).

## Components

```
kassi-graph/
├── src/kassi_graph/
│   ├── types.py             # Node, Edge, Graph dataclasses (universal)
│   ├── parsers/             # per-language frontend → unified graph nodes
│   │   ├── python_parser.py # stdlib `ast` module, no external deps
│   │   ├── go_parser.py     # Phase 2 — tree-sitter-go or go/ast via subprocess
│   │   └── typescript_parser.py  # Phase 2 — tree-sitter-typescript
│   ├── adapters/            # framework YAML specifications
│   │   ├── schema.py        # YAML loader + validator
│   │   ├── django.yaml      # generic Django
│   │   ├── zulip.yaml       # Zulip-specialized Django (overrides)
│   │   ├── flask.yaml       # Phase 1
│   │   ├── fastapi.yaml     # Phase 1
│   │   ├── net_http.yaml    # Phase 2 — Go stdlib
│   │   ├── gin.yaml         # Phase 2 — Go gin
│   │   └── express.yaml     # Phase 2 — Node Express
│   ├── graph.py             # Graph assembly + storage
│   ├── reachability.py      # BFS with sanitizer gates → unguarded paths
│   ├── cli.py               # argparse CLI + JSON stdout
│   └── report.py            # JSON + text + optional mermaid viz
├── tests/
│   ├── test_python_parser.py
│   ├── test_adapter_django.py
│   ├── test_reachability.py
│   └── fixtures/             # minimal guarded + unguarded Django views
└── examples/
    └── zulip_audit.sh        # one-shot "audit Zulip repo, dump report"
```

## Adapter YAML schema

```yaml
# Framework: Django
name: django
language: python
version: "1.0"

sources:
  # HTTP entrypoints — what untrusted input enters the system through
  - kind: decorator
    pattern: "typed_endpoint"            # @typed_endpoint
    description: "Zulip-style typed API endpoint"
  - kind: decorator
    pattern: "typed_endpoint_without_parameters"
  - kind: call
    pattern: "rest_path"                 # registered in urlpatterns
  - kind: view_function                  # fallback: any function matching urlpattern
    name_regex: ".*_backend$|.*_view$"

sinks:
  # Sensitive operations — what you must NOT reach without a sanitizer
  - kind: call
    pattern: "*.objects.{get,filter,all,save,update,delete,create,bulk_create}"
    description: "Django ORM write/read"
  - kind: call
    pattern: "send_event_on_commit"
    description: "Zulip Tornado event broadcast"
  - kind: call
    pattern: "FileResponse|HttpResponse"
    description: "Response construction"

sanitizers:
  # Authz checkpoints — passing through one of these "whitewashes" the path
  - kind: call
    pattern: "access_message|access_stream_by_id|access_user_by_id|access_bot_by_id|access_attachment_by_id|access_scheduled_message|access_reminder|access_user_group_*"
    description: "Zulip access_*_by_id helpers"
  - kind: call
    pattern: "check_sender_can_access_recipients|check_can_send_direct_message|check_can_access_user"
    description: "Zulip access-check helpers"
  - kind: decorator
    pattern: "require_realm_admin|require_member_or_admin|require_billing_access"
    description: "Zulip role decorators"
  - kind: assertion
    pattern: "user_profile is not None"
    description: "Explicit spectator gate"

# Confidence tiers for path reporting
confidence_rules:
  - name: "direct_call_chain"
    description: "Static call graph edge between all nodes in path"
    tier: HIGH
  - name: "decorator_wrapped"
    description: "Path includes decorator-wrapped node"
    tier: MEDIUM
  - name: "dynamic_dispatch"
    description: "Path includes getattr / registry / reflection"
    tier: LOW
```

## Execution flow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Parse codebase → AST per file                            │
│    (Python: stdlib `ast`; Go: tree-sitter; TS: tree-sitter) │
├─────────────────────────────────────────────────────────────┤
│ 2. Walk AST to build Graph:                                 │
│    - Node per function (def / method)                       │
│    - Edge per call (resolved by name, class.method if typed)│
│    - Annotate nodes matching adapter patterns:              │
│         sources / sinks / sanitizers                        │
├─────────────────────────────────────────────────────────────┤
│ 3. Compute reachability:                                    │
│    For each source S, for each sink K:                      │
│      enumerate all paths S → ... → K                        │
│      filter OUT any path containing ANY sanitizer node      │
│      remaining paths = UNGUARDED (findings)                 │
├─────────────────────────────────────────────────────────────┤
│ 4. Rank + output:                                           │
│    - By sink sensitivity × source exposure                  │
│    - JSON: paths[] with node file:line + chain + confidence │
│    - Optional: mermaid diagram of top-N paths               │
└─────────────────────────────────────────────────────────────┘
```

## Integration with other kassi-* tools

**Mode: standalone CLI**
```bash
kassi-graph query --adapter zulip --target /path/to/zulip --json > unguarded.json
```

**Mode: library (Python)**
```python
from kassi_graph import KassiGraph, Adapter

g = KassiGraph.scan("/path/to/zulip", parser="python")
adapter = Adapter.load("zulip")
findings = g.unguarded_paths(adapter)
for f in findings:
    print(f.source.file_line, f.chain, f.sink.file_line)
```

**Mode: subprocess (any language)**
```go
// From kassi-go-scanner
out, _ := exec.Command("kassi-graph", "query", "--adapter", "gin",
                        "--target", ".", "--json").Output()
var findings []Finding
json.Unmarshal(out, &findings)
```

**Consumers planned:**
- [[kassi-mcp-scanner]] — Python, consume graph output for MCP-specific analysis
- [[kassi-web-scanner]] — TS, consume for Node/TS targets
- [[kassi-go-scanner]] — Go, consume for Grafana/Avalanche/k8s hunts
- [[kassi-web-probe]] — dynamic prober uses unguarded paths as initial attack hypothesis list
- [[kassi-triage]] — ranks findings by graph-depth signal

## Phase plan

| Phase | Deliverable | Validation |
|---|---|---|
| **0** (now) | Python stdlib `ast` parser + Django/Zulip adapter + reachability + CLI | Run on `hunt-zulip`, reproduce my 8/8 static-closed audit |
| 1 | Flask + FastAPI adapters + unit test corpus (guarded/unguarded fixtures) | Known-vulnerable Django apps (Django-bench / DVWA-equivalents) |
| 2 | Go parser (tree-sitter-go) + net/http + gin + chi adapters | Run on Grafana Mimir, reproduce known CVE labelset bug |
| 3 | TypeScript parser + Express + Fastify adapters | Run on Supabase, reproduce known SSRF patterns |
| 4 | Plugin API — other kassi-* tools import kassi-graph | Integrate into kassi-mcp-scanner first (same language) |
| 5 | Dynamic-dispatch resolver — decorators, DI containers, interface satisfaction | Reduce LOW-confidence paths to MEDIUM where possible |

## Honest limits (Phase 0)

- Python-only. Go/TS/Java deferred.
- Static call graph only. Dynamic dispatch (getattr, descriptors, generic Protocol satisfaction) → LOW confidence.
- Flat module scope. Doesn't model class hierarchy / MRO fully.
- Decorators partially modeled (recognized by name; semantics only for well-known ones like `@require_realm_admin`).
- No inter-procedural dataflow. "Path exists" ≠ "tainted data flows". Enhancement in Phase 5.

What this means in practice: the tool produces **hypotheses** at HIGH/MEDIUM/LOW confidence, not proofs. Human review still required for each HIGH. But it dramatically reduces the search space from "all endpoints" to "endpoints the engine thinks are unguarded".
