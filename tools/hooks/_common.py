"""Shared helpers for the dev-workflow AI governance hooks (spec 34).

These hooks govern the Claude Code assistant working on this repo — the same
Control / Auditability / Safety triangle ThreatPrism enforces on its triage LLM,
applied to the coding assistant. Standalone (no `threatprism` import) so they run
as plain `python tools/hooks/<name>.py` scripts regardless of whether the package
is installed.

Design rules (mirroring the product's audit discipline):
- Output paths resolve from THIS file, not the cwd, so a hook works no matter
  where Claude Code invokes it from.
- Records are append-only JSONL; raw file contents / secrets / full diffs are
  never written verbatim — a content hash + byte count stands in (the dev-workflow
  analogue of `build_llm_call_audit`).
- Hooks FAIL SAFE: any internal error exits 0 (never blocks the workflow). Only
  the deliberate secret-detection match denies a tool call.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def audit_dir() -> Path:
    """`.claude/audit/` under the repo, or an override (used by tests so they
    never pollute the real operational logs)."""
    override = os.getenv("THREATPRISM_HOOK_AUDIT_DIR")
    base = Path(override) if override else REPO_ROOT / ".claude" / "audit"
    return base


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_stdin_json() -> dict:
    try:
        raw = sys.stdin.read()
        data = json.loads(raw) if raw.strip() else {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def append_jsonl(filename: str, record: dict) -> None:
    try:
        d = audit_dir()
        d.mkdir(parents=True, exist_ok=True)
        with (d / filename).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    except Exception:
        pass  # fail safe — a logging failure must never block the workflow


def load_jsonl(filename: str) -> list[dict]:
    path = audit_dir() / filename
    records: list[dict] = []
    if not path.exists():
        return records
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        records.append(obj)
                except json.JSONDecodeError:
                    continue
    except Exception:
        return records
    return records


def sha256(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def iter_strings(value: object):
    """Yield every string in a nested tool_input structure."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from iter_strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from iter_strings(v)


# --- Secret-detection catalog (spec 34 §3) ---------------------------------
# Mirrors ThreatPrism's product secret detectors (guardrails/healthcare.py +
# guardrails/policy.py `sk-` rule). Kept standalone here so the hook has no import
# dependency; a future refactor could share a single catalog (PATTERN_REFRESH.md
# covers both). Pattern NAMES are logged on a block — never the matched value.
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("stripe_secret_key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b")),
    ("anthropic_openai_key", re.compile(r"\bsk-(?:ant|proj)-[A-Za-z0-9_-]{20,}")),
    ("generic_sk_key", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("db_connection_string", re.compile(
        r"(?i)\b(?:postgres|postgresql|mysql|mongodb)(?:\+\w+)?://[^\s:@/]+:[^\s:@/]+@\S+")),
    ("password_assignment", re.compile(r"(?i)\bpassword\s*[:=]\s*['\"]?\S{6,}")),
    ("api_key_assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}")),
]


def scan_secrets(text: str) -> list[str]:
    """Return the sorted unique names of secret patterns that match `text`."""
    if not text:
        return []
    return sorted({name for name, pattern in SECRET_PATTERNS if pattern.search(text)})


def redact_secrets(text: str, max_len: int = 160) -> str:
    """Mask any secret-shaped spans, then truncate — for safe previews."""
    masked = text
    for _name, pattern in SECRET_PATTERNS:
        masked = pattern.sub("[REDACTED_SECRET]", masked)
    masked = masked.replace("\n", " ")
    return masked[:max_len]


def input_summary(tool_input: object) -> dict:
    """A redacted, content-free summary of a tool input: scalar fields that are
    safe (file_path, the command verb), plus a hash + size of any large content."""
    summary: dict = {}
    if isinstance(tool_input, dict):
        for key in ("file_path", "notebook_path", "path", "url", "pattern"):
            if isinstance(tool_input.get(key), str):
                summary[key] = tool_input[key]
        cmd = tool_input.get("command")
        if isinstance(cmd, str):
            summary["command_preview"] = redact_secrets(cmd, 80)
    blob = json.dumps(tool_input, sort_keys=True, default=str)
    summary["content_sha256"] = sha256(blob)
    summary["content_bytes"] = len(blob.encode("utf-8", "replace"))
    return summary


def emit_record(filename: str, base: dict, data: dict) -> dict:
    record = {"ts": now_iso(), **base, **data}
    append_jsonl(filename, record)
    return record


def base_fields(payload: dict) -> dict:
    return {
        "session_id": payload.get("session_id"),
        "cwd": payload.get("cwd"),
        "event": payload.get("hook_event_name"),
    }
