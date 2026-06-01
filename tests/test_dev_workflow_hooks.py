"""Spec 34 §6 tests for the dev-workflow AI governance hooks.

Each hook is run as a real subprocess with crafted stdin (the way Claude Code
invokes it), with THREATPRISM_HOOK_AUDIT_DIR pointed at a tmp dir so the real
operational logs are never touched. A PreToolUse "block" == a permissionDecision
deny on stdout; "allow" == no deny output. Hooks fail safe (exit 0 either way).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HOOKS = REPO_ROOT / "tools" / "hooks"

# Fake secret-shaped values (not real credentials) used to exercise the scanner.
# Assembled by concatenation ON PURPOSE so no literal secret token appears in the
# source text — otherwise GitHub push protection (and the repo's own scanner) flag
# the test that exists to TEST secret detection. The runtime value is still the
# full secret shape the hook must catch.
FAKE_STRIPE = "sk_" + "live_" + "abc123def456ghi789jkl012"
FAKE_AWS = "AKIA" + "QWERTYUIOPASDFGH"
FAKE_GH = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
FAKE_PROVIDER = "sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz123456"
FAKE_PRIVKEY = "-----BEGIN RSA " + "PRIVATE KEY-----" + "\nMIIabc\n" + "-----END RSA PRIVATE KEY-----"


def _run(script: str, payload: dict, audit_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HOOKS / script)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env={**os.environ, "THREATPRISM_HOOK_AUDIT_DIR": str(audit_dir)},
    )


def _denied(result: subprocess.CompletedProcess) -> bool:
    if not result.stdout.strip():
        return False
    try:
        out = json.loads(result.stdout)
    except json.JSONDecodeError:
        return False
    return out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"


def _write_payload(file_path: str, content: str) -> dict:
    return {"hook_event_name": "PreToolUse", "session_id": "S1", "tool_name": "Write",
            "tool_input": {"file_path": file_path, "content": content}}


def _edit_payload(file_path: str, new_string: str, old_string: str = "x") -> dict:
    return {"hook_event_name": "PreToolUse", "session_id": "S1", "tool_name": "Edit",
            "tool_input": {"file_path": file_path, "old_string": old_string, "new_string": new_string}}


# --- §6.1 / §6.2 secret block vs allow -------------------------------------

def test_edit_with_api_key_is_blocked(tmp_path: Path) -> None:
    r = _run("secret_block.py", _edit_payload("config.py", f'api_key = "{FAKE_STRIPE}"'), tmp_path)
    assert r.returncode == 0
    assert _denied(r)
    blocked = (tmp_path / "blocked.log").read_text(encoding="utf-8")
    assert "config.py" in blocked
    # NAMES only — the secret value must never be logged.
    assert FAKE_STRIPE not in blocked
    assert "stripe_secret_key" in blocked or "api_key_assignment" in blocked


def test_edit_with_benign_name_is_allowed(tmp_path: Path) -> None:
    r = _run("secret_block.py", _edit_payload("people.py", 'name = "John Doe"'), tmp_path)
    assert r.returncode == 0
    assert not _denied(r)
    assert not (tmp_path / "blocked.log").exists()


# --- §6.3 .env write with secrets is blocked -------------------------------

def test_write_env_with_secret_is_blocked(tmp_path: Path) -> None:
    r = _run("secret_block.py", _write_payload(".env", f"OPENAI_API_KEY={FAKE_PROVIDER}\n"), tmp_path)
    assert _denied(r)
    assert FAKE_PROVIDER not in (tmp_path / "blocked.log").read_text(encoding="utf-8")


@pytest.mark.parametrize("secret,expected", [
    (FAKE_AWS, "aws_access_key_id"),
    (FAKE_GH, "github_token"),
    (FAKE_PRIVKEY, "private_key_block"),
    (FAKE_PROVIDER, "anthropic_openai_key"),
])
def test_each_secret_pattern_blocks(tmp_path: Path, secret: str, expected: str) -> None:
    r = _run("secret_block.py", _write_payload("f.txt", f"value = {secret}"), tmp_path)
    assert _denied(r)
    assert expected in (tmp_path / "blocked.log").read_text(encoding="utf-8")


def test_removing_a_secret_is_not_blocked(tmp_path: Path) -> None:
    # The secret is in old_string (being removed); new content is clean -> allowed.
    payload = _edit_payload("config.py", "api_key = load_from_env()", old_string=f'api_key = "{FAKE_STRIPE}"')
    r = _run("secret_block.py", payload, tmp_path)
    assert not _denied(r)


# --- §6.4 PostToolUse audit, no raw content --------------------------------

def test_post_tool_use_appends_redacted_audit(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "PostToolUse", "session_id": "S1", "cwd": "/repo",
        "tool_name": "Edit",
        "tool_input": {"file_path": "secret_config.py", "new_string": f'token = "{FAKE_STRIPE}"'},
        "tool_response": {"type": "text", "text": "ok"},
    }
    r = _run("audit_post_tool.py", payload, tmp_path)
    assert r.returncode == 0
    records = [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(records) == 1
    assert records[0]["tool"] == "Edit"
    assert records[0]["input"]["file_path"] == "secret_config.py"
    assert "content_sha256" in records[0]["input"]
    # The raw secret in new_string must NOT be logged (hash + size only).
    assert FAKE_STRIPE not in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")


def test_user_prompt_submit_redacts_secret_preview(tmp_path: Path) -> None:
    payload = {"hook_event_name": "UserPromptSubmit", "session_id": "S1",
               "prompt": f"please use this key {FAKE_PROVIDER} in the config"}
    _run("audit_prompt.py", payload, tmp_path)
    blob = (tmp_path / "prompts.jsonl").read_text(encoding="utf-8")
    assert FAKE_PROVIDER not in blob
    assert "[REDACTED_SECRET]" in blob


# --- §6.5 Stop session summary ---------------------------------------------

def test_stop_generates_session_summary(tmp_path: Path) -> None:
    for _ in range(2):
        _run("audit_post_tool.py", {"hook_event_name": "PostToolUse", "session_id": "S1",
             "tool_name": "Read", "tool_input": {"file_path": "a.py"}, "tool_response": {}}, tmp_path)
    r = _run("session_summary.py", {"hook_event_name": "Stop", "session_id": "S1",
             "assistant_message": "done"}, tmp_path)
    assert r.returncode == 0
    summary = (tmp_path / "session-S1.md").read_text(encoding="utf-8")
    assert "Session Summary" in summary
    assert "Tool calls audited: **2**" in summary


def test_dashboard_generator_embeds_data(tmp_path: Path) -> None:
    _run("secret_block.py", _write_payload(".env", f"K={FAKE_PROVIDER}"), tmp_path)  # one block
    _run("audit_post_tool.py", {"hook_event_name": "PostToolUse", "session_id": "S1",
         "tool_name": "Read", "tool_input": {"file_path": "a.py"}, "tool_response": {}}, tmp_path)
    r = _run("gen_dashboard.py", {}, tmp_path)
    assert r.returncode == 0
    html = (tmp_path / "dashboard.html").read_text(encoding="utf-8")
    assert "Dev-Workflow AI Governance Dashboard" in html
    assert FAKE_PROVIDER not in html  # only pattern names + hashes embedded
