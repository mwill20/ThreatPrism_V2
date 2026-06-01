"""Dashboard generator (spec 34 challenge deliverable): render the audit JSONL
trail as a dependency-free, self-contained `.claude/audit/dashboard.html`.

The data is embedded into the HTML at generation time (no fetch/CORS issues with
`file://`), mirroring the same no-dependency posture as the ThreatPrism dashboard.
Run manually: `python tools/hooks/gen_dashboard.py`.
"""

from __future__ import annotations

import html
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import audit_dir, load_jsonl, now_iso  # noqa: E402

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ThreatPrism Dev-Workflow Governance Dashboard</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }}
  header {{ padding: 16px 24px; background: #1e293b; border-bottom: 1px solid #334155; }}
  h1 {{ font-size: 18px; margin: 0; }}
  .meta {{ color: #94a3b8; font-size: 12px; margin-top: 4px; }}
  .cards {{ display: flex; gap: 12px; padding: 16px 24px; flex-wrap: wrap; }}
  .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 12px 16px; min-width: 120px; }}
  .card .n {{ font-size: 24px; font-weight: 700; }}
  .card.block .n {{ color: #f87171; }}
  .card .l {{ color: #94a3b8; font-size: 12px; }}
  section {{ padding: 0 24px 24px; }}
  h2 {{ font-size: 14px; color: #cbd5e1; border-bottom: 1px solid #334155; padding-bottom: 6px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th, td {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid #1e293b; vertical-align: top; }}
  th {{ color: #94a3b8; position: sticky; top: 0; background: #0f172a; }}
  code {{ color: #7dd3fc; }}
  tr.blocked td {{ background: #2a1414; }}
  .tag {{ background: #334155; border-radius: 4px; padding: 1px 6px; font-size: 11px; }}
</style>
</head>
<body>
<header>
  <h1>ThreatPrism — Dev-Workflow AI Governance Dashboard</h1>
  <div class="meta">Generated {generated} · spec 34 · data is redacted (hashes + sizes, never raw content)</div>
</header>
<div class="cards">
  <div class="card"><div class="n">{n_prompts}</div><div class="l">Prompts</div></div>
  <div class="card"><div class="n">{n_tools}</div><div class="l">Tool calls</div></div>
  <div class="card"><div class="n">{n_files}</div><div class="l">Files touched</div></div>
  <div class="card block"><div class="n">{n_blocks}</div><div class="l">Secret blocks</div></div>
</div>
<section id="app"></section>
<script id="data" type="application/json">{data_json}</script>
<script>
const DATA = JSON.parse(document.getElementById('data').textContent);
function esc(s) {{ const d = document.createElement('div'); d.textContent = (s==null?'':String(s)); return d.innerHTML; }}
function table(title, rows, cols, opts) {{
  opts = opts || {{}};
  let h = '<h2>' + esc(title) + '</h2>';
  if (!rows.length) {{ return h + '<p style="color:#64748b">(none)</p>'; }}
  h += '<table><thead><tr>' + cols.map(c => '<th>' + esc(c.label) + '</th>').join('') + '</tr></thead><tbody>';
  for (const r of rows) {{
    const cls = opts.blocked && opts.blocked(r) ? ' class="blocked"' : '';
    h += '<tr' + cls + '>' + cols.map(c => '<td>' + c.render(r) + '</td>').join('') + '</tr>';
  }}
  return h + '</tbody></table>';
}}
const app = document.getElementById('app');
app.innerHTML =
  table('Blocked secret writes', DATA.blocks, [
    {{label:'time', render:r=>esc(r.ts)}},
    {{label:'file', render:r=>'<code>'+esc(r.file_path)+'</code>'}},
    {{label:'patterns', render:r=>(r.patterns||[]).map(p=>'<span class="tag">'+esc(p)+'</span>').join(' ')}},
  ], {{blocked:()=>true}}) +
  table('Tool calls', DATA.audit, [
    {{label:'time', render:r=>esc(r.ts)}},
    {{label:'tool', render:r=>'<code>'+esc(r.tool)+'</code>'}},
    {{label:'target', render:r=>esc((r.input&&(r.input.file_path||r.input.command_preview))||'')}},
    {{label:'bytes', render:r=>esc(r.input&&r.input.content_bytes)}},
  ]) +
  table('Prompts', DATA.prompts, [
    {{label:'time', render:r=>esc(r.ts)}},
    {{label:'len', render:r=>esc(r.prompt_len)}},
    {{label:'preview (redacted)', render:r=>esc(r.prompt_preview)}},
  ]);
</script>
</body>
</html>
"""


def render(audit: list[dict], prompts: list[dict], blocks: list[dict]) -> str:
    files = {
        r["input"]["file_path"]
        for r in audit
        if isinstance(r.get("input"), dict) and r["input"].get("file_path")
    }
    data_json = json.dumps({"audit": audit, "prompts": prompts, "blocks": blocks})
    # Escape only the closing-script sequence so the embedded JSON can't break out.
    data_json = data_json.replace("</", "<\\/")
    return _TEMPLATE.format(
        generated=html.escape(now_iso()),
        n_prompts=len(prompts),
        n_tools=len(audit),
        n_files=len(files),
        n_blocks=len(blocks),
        data_json=data_json,
    )


def main() -> int:
    out = audit_dir() / "dashboard.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        render(load_jsonl("audit.jsonl"), load_jsonl("prompts.jsonl"), load_jsonl("blocked.log")),
        encoding="utf-8",
    )
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
