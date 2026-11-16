"""Output renderers for kassi-graph findings.

Formats:
    - text (default to stdout — rendered by cli.py)
    - json (rendered by cli.py)
    - html (single-file, no external deps; opens in any browser)
"""
from __future__ import annotations

import html
from pathlib import Path

from kassi_graph.types import Finding, Graph


HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>kassi-graph · {title}</title>
<style>
:root {{
  --bg: #0b0f14;
  --panel: #141a22;
  --fg: #d4dae2;
  --muted: #8891a3;
  --accent: #58a6ff;
  --high: #ff6b6b;
  --medium: #ffa94d;
  --low: #51cf66;
  --row: #1b232e;
}}
* {{ box-sizing: border-box; }}
body {{ background: var(--bg); color: var(--fg); font-family: ui-sans-serif, -apple-system, system-ui, sans-serif; margin: 0; padding: 24px; }}
h1 {{ font-size: 18px; margin: 0 0 4px; }}
.meta {{ color: var(--muted); font-size: 13px; margin-bottom: 20px; }}
.stats {{ display: flex; gap: 20px; margin-bottom: 20px; flex-wrap: wrap; }}
.stat {{ background: var(--panel); border-radius: 6px; padding: 10px 14px; min-width: 100px; }}
.stat .num {{ font-size: 22px; font-weight: 600; }}
.stat .lbl {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; }}
.filters {{ margin-bottom: 14px; display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }}
.filters input, .filters select {{ background: var(--panel); border: 1px solid #22303d; color: var(--fg); padding: 6px 10px; border-radius: 4px; font: inherit; }}
.card {{ background: var(--panel); border-radius: 6px; margin-bottom: 8px; padding: 12px 14px; border-left: 3px solid var(--muted); }}
.card.high {{ border-left-color: var(--high); }}
.card.medium {{ border-left-color: var(--medium); }}
.card.low {{ border-left-color: var(--low); }}
.row1 {{ display: flex; gap: 12px; font-size: 13px; color: var(--muted); align-items: baseline; }}
.row1 .idx {{ color: var(--muted); font-variant-numeric: tabular-nums; min-width: 32px; }}
.row1 .sev {{ font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.04em; }}
.row1 .sev.high {{ color: var(--high); }}
.row1 .sev.medium {{ color: var(--medium); }}
.row1 .sev.low {{ color: var(--low); }}
.row1 .conf {{ color: var(--muted); font-size: 11px; }}
.names {{ margin: 6px 0; font-family: ui-monospace, monospace; font-size: 13px; color: var(--fg); }}
.names b {{ color: var(--accent); font-weight: 600; }}
.chain {{ font-family: ui-monospace, monospace; font-size: 12px; color: var(--muted); margin-top: 4px; }}
.loc {{ color: var(--muted); font-size: 12px; margin-top: 4px; }}
.hidden {{ display: none; }}
</style>
</head><body>
<h1>kassi-graph report</h1>
<div class="meta">Target: {target} · Adapter: {adapter} · {timestamp}</div>
<div class="stats">
  <div class="stat"><div class="num">{total_findings}</div><div class="lbl">findings</div></div>
  <div class="stat"><div class="num">{high_count}</div><div class="lbl">high sev</div></div>
  <div class="stat"><div class="num">{med_count}</div><div class="lbl">medium</div></div>
  <div class="stat"><div class="num">{nodes}</div><div class="lbl">nodes</div></div>
  <div class="stat"><div class="num">{edges}</div><div class="lbl">edges</div></div>
  <div class="stat"><div class="num">{sources}</div><div class="lbl">sources</div></div>
  <div class="stat"><div class="num">{sinks}</div><div class="lbl">sinks</div></div>
  <div class="stat"><div class="num">{sanitizers}</div><div class="lbl">sanitizers</div></div>
</div>
<div class="filters">
  <input id="q" placeholder="filter by source/sink/chain substring…" autocomplete="off">
  <select id="sev">
    <option value="all">all severities</option>
    <option value="high">high only</option>
    <option value="medium">medium only</option>
    <option value="low">low only</option>
  </select>
  <select id="conf">
    <option value="all">any confidence</option>
    <option value="high">high confidence</option>
    <option value="medium">medium confidence</option>
    <option value="low">low confidence</option>
  </select>
  <span id="count" style="color:var(--muted);font-size:12px;"></span>
</div>
<div id="list">
{cards}
</div>
<script>
const q = document.getElementById('q');
const sev = document.getElementById('sev');
const conf = document.getElementById('conf');
const count = document.getElementById('count');
const cards = Array.from(document.querySelectorAll('.card'));
function refilter() {{
  const needle = q.value.toLowerCase().trim();
  const sevFilter = sev.value;
  const confFilter = conf.value;
  let shown = 0;
  for (const c of cards) {{
    const cardSev = c.dataset.sev;
    const cardConf = c.dataset.conf;
    const body = c.textContent.toLowerCase();
    const sevOk = sevFilter === 'all' || cardSev === sevFilter;
    const confOk = confFilter === 'all' || cardConf === confFilter;
    const qOk = !needle || body.includes(needle);
    const show = sevOk && confOk && qOk;
    c.classList.toggle('hidden', !show);
    if (show) shown++;
  }}
  count.textContent = shown + ' of ' + cards.length + ' shown';
}}
q.addEventListener('input', refilter);
sev.addEventListener('change', refilter);
conf.addEventListener('change', refilter);
refilter();
</script>
</body></html>"""


def _card_html(idx: int, f: Finding) -> str:
    sev = f.severity_hint
    conf = f.path.confidence.value
    src = f.source_node
    sink = f.sink_node
    src_loc = str(src.location) if src.location else "unresolved"
    sink_loc = str(sink.location) if sink.location else "unresolved"
    # Short-chain readable form
    chain_parts = []
    for nid in f.path.nodes:
        if ":" in nid:
            tail = nid.split(":", 1)[1]
            chain_parts.append(tail.split(".")[-1])
        else:
            chain_parts.append(nid)
    chain = " → ".join(html.escape(p) for p in chain_parts)

    return (
        f'<div class="card {sev}" data-sev="{sev}" data-conf="{conf}">'
        f'<div class="row1">'
        f'<span class="idx">#{idx}</span>'
        f'<span class="sev {sev}">{sev}</span>'
        f'<span class="conf">confidence: {conf}</span>'
        f'</div>'
        f'<div class="names"><b>{html.escape(src.short_name)}</b> → … → <b>{html.escape(sink.short_name)}</b></div>'
        f'<div class="loc">source: {html.escape(src_loc)}</div>'
        f'<div class="loc">sink:&nbsp;&nbsp; {html.escape(sink_loc)}</div>'
        f'<div class="chain">{chain}</div>'
        f'</div>'
    )


def write_html(
    out_path: str | Path,
    *,
    target: str,
    adapter: str,
    graph: Graph,
    findings: list[Finding],
) -> None:
    import datetime
    sev_order = {"high": 0, "medium": 1, "low": 2}
    conf_order = {"high": 0, "medium": 1, "low": 2}
    sorted_findings = sorted(
        findings,
        key=lambda f: (sev_order.get(f.severity_hint, 2), conf_order.get(f.path.confidence.value, 2)),
    )
    cards_html = "\n".join(_card_html(i, f) for i, f in enumerate(sorted_findings, 1))
    high_count = sum(1 for f in findings if f.severity_hint == "high")
    med_count = sum(1 for f in findings if f.severity_hint == "medium")
    stats = graph.stats()
    doc = HTML_TEMPLATE.format(
        title=html.escape(Path(target).name) or "report",
        target=html.escape(target),
        adapter=html.escape(adapter),
        timestamp=datetime.datetime.now().isoformat(timespec="minutes"),
        total_findings=len(findings),
        high_count=high_count,
        med_count=med_count,
        nodes=stats["nodes"],
        edges=stats["edges"],
        sources=stats["sources"],
        sinks=stats["sinks"],
        sanitizers=stats["sanitizers"],
        cards=cards_html,
    )
    Path(out_path).write_text(doc, encoding="utf-8")
