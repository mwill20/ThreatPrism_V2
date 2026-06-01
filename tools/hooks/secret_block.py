"""PreToolUse hook for Edit|Write|MultiEdit|NotebookEdit (spec 34): scan the NEW
content the assistant is about to write for secret-shaped data and DENY the tool
call on a match — the dev-workflow analogue of ThreatPrism's secret tokenization +
output policy.

Only the *new* content is scanned (not `old_string`), so removing an existing
secret is never blocked. On a match: emit a PreToolUse `permissionDecision: deny`
(verified hook schema) and append a record to `blocked.log` carrying the matched
PATTERN NAMES only — never the secret value. On any internal error: exit 0
(fail-open) so a hook bug can never wedge the workflow. The deliberate secret
match is the one and only thing that blocks.

`.env` asymmetry (spec 34 §3): an *assistant* Write of a `.env` with secret-shaped
content is blocked; the human still edits gitignored `.env` manually.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import append_jsonl, now_iso, read_stdin_json, scan_secrets  # noqa: E402


def _new_content_strings(tool_input: object) -> list[str]:
    out: list[str] = []
    if isinstance(tool_input, dict):
        for key in ("content", "new_string", "new_source"):
            value = tool_input.get(key)
            if isinstance(value, str):
                out.append(value)
        edits = tool_input.get("edits")
        if isinstance(edits, list):
            for edit in edits:
                if isinstance(edit, dict) and isinstance(edit.get("new_string"), str):
                    out.append(edit["new_string"])
    return out


def main() -> int:
    try:
        payload = read_stdin_json()
        tool_input = payload.get("tool_input") or {}
        file_path = ""
        if isinstance(tool_input, dict):
            file_path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""

        matched: set[str] = set()
        for content in _new_content_strings(tool_input):
            matched.update(scan_secrets(content))

        if matched:
            names = sorted(matched)
            append_jsonl(
                "blocked.log",
                {
                    "ts": now_iso(),
                    "session_id": payload.get("session_id"),
                    "tool": payload.get("tool_name"),
                    "file_path": file_path,
                    "patterns": names,  # NAMES ONLY — never the secret value
                },
            )
            reason = (
                "Blocked by ThreatPrism dev-workflow governance: the proposed content "
                f"matches secret pattern(s): {', '.join(names)}. The assistant must not "
                "write secrets into files. Manage real secrets by hand in gitignored "
                "files (e.g. .env)."
            )
            print(json.dumps({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }))
            return 0  # the JSON deny mechanism uses exit 0
    except Exception:
        # Fail open: a scanner bug must never block legitimate work.
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
