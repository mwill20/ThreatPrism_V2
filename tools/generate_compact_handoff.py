from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


DEFAULT_PROMPT = """Work in C:\\Projects\\ThreatPrismV2.
Read START_HERE.md, AGENTS.md, and docs/THREATPRISM_V2_CODEX_HANDOFF.md first.
Verify live repo state with git status and current files before answering.
Use docs/WORKING_CHECKLIST.md for completed slices, next slice, validation, and blockers.
Do not use live providers, real credentials, real remediation, or real organization/workplace data.
Keep ALLOW_REAL_ACTIONS=false and run tools/validate-threatprism.ps1 before calling implementation complete.
If context is approaching 75% used or less than roughly 25% remains, output a compact handoff prompt and update durable handoff files before continuing."""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Print a compact ThreatPrism handoff prompt for a fresh AI context."
    )
    parser.add_argument(
        "--root",
        default=".",
        help="ThreatPrism repository root. Defaults to the current directory.",
    )
    parser.add_argument(
        "--include-status",
        action="store_true",
        help="Include a short git status line when git is available.",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    prompt = _build_prompt(root, include_status=args.include_status)
    print(prompt)
    return 0


def _build_prompt(root: Path, *, include_status: bool) -> str:
    parts = [
        "## Compact ThreatPrism Handoff Prompt",
        "",
        "```text",
        DEFAULT_PROMPT,
    ]
    if include_status:
        status = _git_status(root)
        if status:
            parts.extend(["", "Current git status snapshot:", status])
    parts.extend(["```", "", "Paste this into a fresh chat. Do not paste large docs unless asked."])
    return "\n".join(parts)


def _git_status(root: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "status", "-sb"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


if __name__ == "__main__":
    raise SystemExit(main())
