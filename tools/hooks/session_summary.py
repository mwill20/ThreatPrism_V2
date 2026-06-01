"""Stop hook (spec 34): write a per-session summary markdown to
`.claude/audit/session-<id>.md` by aggregating the JSONL trail (the `Stop` payload
carries only `assistant_message`, so the summary is built from `audit.jsonl` /
`prompts.jsonl` / `blocked.log`, filtered to this session). Fail-safe."""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import audit_dir, base_fields, load_jsonl, now_iso, read_stdin_json  # noqa: E402


def _for_session(records: list[dict], session_id: str | None) -> list[dict]:
    if not session_id:
        return records
    return [r for r in records if r.get("session_id") == session_id]


def build_summary(session_id: str | None) -> str:
    audit = _for_session(load_jsonl("audit.jsonl"), session_id)
    prompts = _for_session(load_jsonl("prompts.jsonl"), session_id)
    blocks = _for_session(load_jsonl("blocked.log"), session_id)

    tool_counts = Counter(r.get("tool") for r in audit if r.get("tool"))
    files = sorted({
        r["input"]["file_path"]
        for r in audit
        if isinstance(r.get("input"), dict) and r["input"].get("file_path")
    })

    lines = [
        f"# Session Summary — `{session_id or 'unknown'}`",
        "",
        f"_Generated {now_iso()} by the dev-workflow governance hooks (spec 34)._",
        "",
        f"- Prompts submitted: **{len(prompts)}**",
        f"- Tool calls audited: **{len(audit)}**",
        f"- Files touched: **{len(files)}**",
        f"- Secret-write blocks: **{len(blocks)}**",
        "",
        "## Tool usage",
    ]
    for tool, count in tool_counts.most_common():
        lines.append(f"- `{tool}`: {count}")
    if not tool_counts:
        lines.append("- (none)")
    lines.append("")
    lines.append("## Files touched")
    for f in files:
        lines.append(f"- `{f}`")
    if not files:
        lines.append("- (none)")
    if blocks:
        lines.append("")
        lines.append("## Blocked secret writes")
        for b in blocks:
            lines.append(f"- `{b.get('file_path', '?')}` — patterns: {', '.join(b.get('patterns', []))}")
    return "\n".join(lines) + "\n"


def main() -> int:
    try:
        payload = read_stdin_json()
        session_id = base_fields(payload).get("session_id")
        out = audit_dir() / f"session-{session_id or 'unknown'}.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(build_summary(session_id), encoding="utf-8")
    except Exception:
        pass  # fail safe
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
