"""kassi-graph CLI.

Commands:
    kassi-graph scan   --target <dir>   # build + show stats
    kassi-graph query  --adapter <name> --target <dir> [--json] [--max-depth N]
    kassi-graph viz    --adapter <name> --target <dir> [--top N]   # mermaid
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from kassi_graph.adapters.schema import Adapter
from kassi_graph.parsers.python_parser import parse_codebase, resolve_short_name_edges
from kassi_graph.reachability import unguarded_findings
from kassi_graph.types import Graph, Role


def _build_graph(target: Path, language: str) -> Graph:
    if language != "python":
        print(f"error: language '{language}' not supported in phase 0 (python-only)", file=sys.stderr)
        sys.exit(2)
    graph = parse_codebase(target)
    resolve_short_name_edges(graph)
    return graph


def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()
    if not target.exists():
        print(f"error: target {target} does not exist", file=sys.stderr)
        return 2
    graph = _build_graph(target, language=args.language)
    stats = graph.stats()
    print(f"Scanned: {target}")
    print(f"Language: {graph.language}")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    return 0


def cmd_query(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()
    adapter = Adapter.load(args.adapter)
    graph = _build_graph(target, language=adapter.language)
    findings = unguarded_findings(
        graph, adapter,
        max_depth=args.max_depth,
        max_paths_per_source=args.max_paths_per_source,
    )

    # Rank: by severity_hint (high > medium > low), then confidence (high > med > low)
    sev_order = {"high": 0, "medium": 1, "low": 2}
    conf_order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (sev_order.get(f.severity_hint, 2), conf_order.get(f.path.confidence.value, 2)))

    if args.limit > 0:
        findings = findings[: args.limit]

    if args.json:
        print(json.dumps({
            "target": str(target),
            "adapter": args.adapter,
            "stats": graph.stats(),
            "findings": [f.to_dict() for f in findings],
        }, indent=2))
    else:
        print(f"Target: {target}")
        print(f"Adapter: {adapter.name} ({adapter.language})")
        s = graph.stats()
        print(f"Graph: {s['nodes']} nodes, {s['edges']} edges "
              f"({s['sources']} sources, {s['sinks']} sinks, {s['sanitizers']} sanitizers)")
        print(f"Unguarded findings: {len(findings)}")
        print()
        for i, fnd in enumerate(findings, 1):
            src = fnd.source_node
            sink = fnd.sink_node
            src_loc = str(src.location) if src.location else "unresolved"
            sink_loc = str(sink.location) if sink.location else "unresolved"
            print(f"[{i:>3}] {fnd.severity_hint:>6}/{fnd.path.confidence.value:>6} | "
                  f"{src.short_name} ({src_loc})")
            print(f"       → ... → {sink.short_name} ({sink_loc})")
            path_short = " → ".join(nid.split(":", 1)[1].split(".")[-1] for nid in fnd.path.nodes)
            print(f"       chain: {path_short}")
            print(f"       why: {fnd.why}")
            print()

    return 0


def cmd_list_adapters(args: argparse.Namespace) -> int:
    here = Path(__file__).parent / "adapters"
    for yf in sorted(here.glob("*.yaml")):
        print(yf.stem)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kassi-graph")
    parser.add_argument("--version", action="store_true")
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="parse codebase and print graph stats")
    p_scan.add_argument("--target", required=True)
    p_scan.add_argument("--language", default="python")
    p_scan.set_defaults(func=cmd_scan)

    p_query = sub.add_parser("query", help="enumerate unguarded source→sink paths")
    p_query.add_argument("--adapter", required=True, help="name (django/zulip/...) or path to YAML")
    p_query.add_argument("--target", required=True)
    p_query.add_argument("--json", action="store_true")
    p_query.add_argument("--max-depth", type=int, default=8)
    p_query.add_argument("--max-paths-per-source", type=int, default=20)
    p_query.add_argument("--limit", type=int, default=0, help="cap output to first N findings")
    p_query.set_defaults(func=cmd_query)

    p_ls = sub.add_parser("list-adapters", help="list bundled adapters")
    p_ls.set_defaults(func=cmd_list_adapters)

    args = parser.parse_args(argv)
    if args.version:
        from kassi_graph import __version__
        print(__version__)
        return 0
    if not getattr(args, "func", None):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
