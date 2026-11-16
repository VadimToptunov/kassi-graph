"""Test-corpus runner.

Runs kassi-graph against each labelled fixture and reports pass/fail vs
the expected findings in EXPECTED.md.

Usage:
    cd kassi-graph
    .venv/bin/python -m tests.corpus.run
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from kassi_graph.adapters.schema import Adapter
from kassi_graph.parsers.python_parser import parse_codebase, resolve_short_name_edges
from kassi_graph.reachability import unguarded_findings


@dataclass
class Case:
    fixture: str                  # path relative to tests/corpus/
    adapter: str
    expected_findings: set[str]   # short_names of functions expected to have a finding
    expected_clean: set[str]      # short_names of functions expected to be clean
    known_fps: set[str]           # short_names where tool may fire but it's intended-public


CASES = [
    Case(
        fixture="flask_vulnerable",
        adapter="flask",
        expected_findings={"user_details", "edit_post"},
        expected_clean={"my_profile", "delete_user"},
        known_fps={"get_post"},
    ),
]


def run_case(case: Case, here: Path) -> tuple[int, int, int, int]:
    target = here / case.fixture
    graph = parse_codebase(target)
    resolve_short_name_edges(graph)
    adapter = Adapter.load(case.adapter)
    findings = unguarded_findings(graph, adapter, dedup=True)

    # The anchor short_name of each finding
    anchors: set[str] = set()
    for f in findings:
        for nid in f.path.nodes:
            n = graph.nodes.get(nid)
            if n is not None and n.location is not None and n.short_name in (
                case.expected_findings | case.expected_clean | case.known_fps
            ):
                anchors.add(n.short_name)
                break

    tp = len(anchors & case.expected_findings)
    fn = len(case.expected_findings - anchors)
    fp = len(anchors & case.expected_clean)
    tn = len(case.expected_clean - anchors)
    known_fps_fired = len(anchors & case.known_fps)

    print(f"\n=== {case.fixture} (adapter: {case.adapter}) ===")
    print(f"  True positives:  {tp}/{len(case.expected_findings)}  {sorted(anchors & case.expected_findings)}")
    print(f"  False negatives: {fn}  {sorted(case.expected_findings - anchors)}")
    print(f"  False positives: {fp}  {sorted(anchors & case.expected_clean)}")
    print(f"  True negatives:  {tn}  {sorted(case.expected_clean - anchors)}")
    print(f"  Known-FP fired:  {known_fps_fired}  (expected; not a failure)")

    # Pass criteria: all TPs caught, no unexpected FPs
    ok = tp == len(case.expected_findings) and fp == 0
    print(f"  Verdict: {'✅ PASS' if ok else '❌ FAIL'}")
    return tp, fn, fp, tn


def main() -> int:
    here = Path(__file__).parent
    total_tp = total_fn = total_fp = total_tn = 0
    for case in CASES:
        tp, fn, fp, tn = run_case(case, here)
        total_tp += tp; total_fn += fn; total_fp += fp; total_tn += tn

    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 0
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 0
    print(f"\n=== OVERALL ===")
    print(f"  Recall:    {recall:.0%}  ({total_tp}/{total_tp + total_fn})")
    print(f"  Precision: {precision:.0%}  ({total_tp}/{total_tp + total_fp})")
    return 0 if (total_fn == 0 and total_fp == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
