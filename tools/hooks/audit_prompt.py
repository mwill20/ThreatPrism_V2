"""UserPromptSubmit hook (spec 34): append a redacted record of each submitted
prompt to `.claude/audit/prompts.jsonl` (length + hash + secret-masked preview —
never the raw prompt verbatim). Fail-safe — never blocks."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import base_fields, emit_record, read_stdin_json, redact_secrets, sha256  # noqa: E402


def main() -> int:
    try:
        payload = read_stdin_json()
        prompt = payload.get("prompt") or ""
        emit_record(
            "prompts.jsonl",
            base_fields(payload),
            {
                "prompt_len": len(prompt),
                "prompt_sha256": sha256(prompt),
                "prompt_preview": redact_secrets(prompt, 160),
            },
        )
    except Exception:
        pass  # fail safe
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
