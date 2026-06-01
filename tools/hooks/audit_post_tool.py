"""PostToolUse hook (spec 34): append a redacted record of every tool call to
`.claude/audit/audit.jsonl`. Fail-safe — never blocks. Reads the hook JSON from
stdin (fields: tool_name, tool_input, tool_response, session_id, cwd, ...)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import base_fields, emit_record, input_summary, read_stdin_json, sha256  # noqa: E402


def main() -> int:
    try:
        payload = read_stdin_json()
        response = payload.get("tool_response")
        result: dict = {}
        if response is not None:
            blob = json.dumps(response, sort_keys=True, default=str)
            result = {"result_sha256": sha256(blob), "result_bytes": len(blob.encode("utf-8", "replace"))}
        emit_record(
            "audit.jsonl",
            base_fields(payload),
            {
                "tool": payload.get("tool_name"),
                "input": input_summary(payload.get("tool_input")),
                "result": result,
            },
        )
    except Exception:
        pass  # fail safe
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
