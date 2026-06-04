"""Tests for the docs-reminder Stop hook (the user's first hand-built hook).

The hook's decision logic is a pure function (`reminder_for_changes`) so it can be
tested without git or a subprocess — the same "factor the logic, test the logic"
pattern as `session_summary.build_summary`. A subprocess smoke test confirms the
script runs end-to-end and always fail-safes (exit 0).
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HOOK = REPO_ROOT / "tools" / "hooks" / "docs_reminder.py"


def _load():
    spec = importlib.util.spec_from_file_location("docs_reminder", HOOK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reminds_when_src_changed_but_docs_untouched() -> None:
    msg = _load().reminder_for_changes({"src/threatprism/cases/service.py"})
    assert msg is not None
    assert "CHANGELOG.md" in msg
    assert "WORKING_CHECKLIST.md" in msg


def test_silent_when_both_docs_updated() -> None:
    changed = {"src/threatprism/cases/service.py", "CHANGELOG.md", "docs/WORKING_CHECKLIST.md"}
    assert _load().reminder_for_changes(changed) is None


def test_silent_when_no_src_change() -> None:
    assert _load().reminder_for_changes({"README.md", "docs/ARCHITECTURE.md"}) is None


def test_names_only_the_missing_doc() -> None:
    # CHANGELOG updated, checklist not -> remind about the checklist specifically.
    msg = _load().reminder_for_changes({"src/threatprism/x.py", "CHANGELOG.md"})
    assert msg is not None
    assert "WORKING_CHECKLIST.md" in msg


def test_hook_runs_end_to_end_and_fail_safes(tmp_path) -> None:
    # Run it exactly as Claude Code would: a Stop payload on stdin. It must exit 0
    # regardless of repo state (advisory hooks never wedge the workflow).
    result = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps({"hook_event_name": "Stop", "session_id": "test", "cwd": str(REPO_ROOT)}),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
