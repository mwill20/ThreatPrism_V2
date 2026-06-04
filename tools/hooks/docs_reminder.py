"""Stop hook: advisory reminder to update docs after a build.

Standing project rule: "After every build, update docs + checklist + CHANGELOG."
This hook nudges (never blocks) when the working tree has uncommitted `src/` changes
but `CHANGELOG.md` and/or `docs/WORKING_CHECKLIST.md` were NOT touched — so the
discipline survives a forgetful moment without standing in the way.

ADVISORY ONLY: it surfaces a message and exits 0. It does NOT emit a Stop "decision":
"block", so Claude is never forced to continue. The decision logic is the pure function
`reminder_for_changes()` (unit-tested without git). Fail-safe: any error exits 0 silently.

Output is best-effort across Claude Code versions:
  - `{"systemMessage": ...}` on stdout (shown to the user as a non-blocking notice),
  - the same text on stderr (visible via `claude --debug` / transcript), and
  - an append to `.claude/audit/docs-reminder.log` (always works; an audit trail).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import REPO_ROOT, append_jsonl, now_iso, read_stdin_json  # noqa: E402

SRC_PREFIX = "src/"
DOCS_TO_CHECK = ("CHANGELOG.md", "docs/WORKING_CHECKLIST.md")


def reminder_for_changes(changed: set[str]) -> str | None:
    """Pure decision logic. Returns the reminder text, or None if no nudge is warranted.

    Nudge only when (a) at least one `src/` file changed AND (b) at least one of the
    tracked docs was NOT changed. If src is untouched, or all docs were updated, stay
    silent.
    """
    changed = set(changed)
    src_changed = sorted(p for p in changed if p.startswith(SRC_PREFIX))
    if not src_changed:
        return None
    missing = [doc for doc in DOCS_TO_CHECK if doc not in changed]
    if not missing:
        return None
    shown = src_changed[:5]
    more = "" if len(src_changed) <= 5 else f" (+{len(src_changed) - 5} more)"
    return (
        "[build closeout reminder] src/ changed this session but these were not "
        f"updated: {', '.join(missing)}. "
        f"Changed src files: {', '.join(shown)}{more}. "
        "Before committing, run the build-closeout checklist: "
        "(1) update CHANGELOG + WORKING_CHECKLIST (+ lessons/specs if relevant), "
        "(2) run demo-safety + validation, "
        "(3) recommend the next slice, "
        "(4) consider whether a lesson is warranted. "
        "Steps 1-2 are mechanical; 3-4 are judgment calls for you/the assistant, not this hook."
    )


def _changed_files() -> set[str]:
    """Working-tree changes (staged + unstaged + untracked) as forward-slash paths."""
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return set()
        files: set[str] = set()
        for line in result.stdout.splitlines():
            if len(line) < 4:
                continue
            path = line[3:].strip()              # strip the 2-char status + space
            if " -> " in path:                   # rename: "old -> new"
                path = path.split(" -> ", 1)[1]
            files.add(path.strip().strip('"'))   # git quotes paths with odd chars
        return files
    except Exception:
        return set()


def main() -> int:
    try:
        payload = read_stdin_json()
        message = reminder_for_changes(_changed_files())
        if message:
            append_jsonl("docs-reminder.log", {"ts": now_iso(), "session_id": payload.get("session_id"), "message": message})
            print(message, file=sys.stderr)
            print(json.dumps({"systemMessage": message}))
    except Exception:
        return 0  # fail-safe: an advisory hook must never wedge the workflow
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
