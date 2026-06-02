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
# Single source of truth shared with the product runtime detectors
# (guardrails/secret_catalog.py). Loaded by FILE PATH, not `import threatprism`,
# so the hook stays standalone — it runs as a plain script whether or not the
# package is installed. On any load failure the hook falls back to no patterns and
# fails open (the documented hook philosophy): a broken catalog must never wedge
# the workflow. Pattern NAMES are logged on a block — never the matched value.
def _load_secret_catalog():
    import importlib.util

    path = REPO_ROOT / "src" / "threatprism" / "guardrails" / "secret_catalog.py"
    spec = importlib.util.spec_from_file_location("_tp_secret_catalog", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


try:
    _SECRET_CATALOG = _load_secret_catalog()
    SECRET_PATTERNS = _SECRET_CATALOG.SECRET_PATTERNS
except Exception:  # pragma: no cover - fail open if the catalog cannot be loaded
    _SECRET_CATALOG = None
    SECRET_PATTERNS = []


def scan_secrets(text: str) -> list[str]:
    """Return the sorted unique names of secret patterns that match `text`."""
    if not text or _SECRET_CATALOG is None:
        return []
    return _SECRET_CATALOG.scan(text)


def redact_secrets(text: str, max_len: int = 160) -> str:
    """Mask any secret-shaped spans, then truncate — for safe previews."""
    if _SECRET_CATALOG is None:
        return text.replace("\n", " ")[:max_len]
    return _SECRET_CATALOG.redact(text, max_len)


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
