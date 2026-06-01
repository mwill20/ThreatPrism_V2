# Runbook — Dev-Workflow AI Governance Hooks

Operational guide for the Claude Code hooks implemented in spec 34
([`docs/specs/34_DEV_WORKFLOW_AI_GOVERNANCE_HOOKS.md`](../specs/34_DEV_WORKFLOW_AI_GOVERNANCE_HOOKS.md)).
These hooks govern the *coding assistant* working on this repo — they are
dev-workflow tooling, not ThreatPrism product/runtime code.

## What is wired

Wiring lives in the committed project file `.claude/settings.json`. It activates
on the **next Claude Code start** in this repo:

| Event | Script | Effect |
|---|---|---|
| `PostToolUse` (all tools) | `tools/hooks/audit_post_tool.py` | Append a redacted record per tool call to `.claude/audit/audit.jsonl` |
| `UserPromptSubmit` | `tools/hooks/audit_prompt.py` | Append a redacted prompt record to `.claude/audit/prompts.jsonl` |
| `Stop` | `tools/hooks/session_summary.py` | Write `.claude/audit/session-<id>.md` (aggregated from the JSONL trail) |
| `PreToolUse` (`Edit\|Write\|MultiEdit\|NotebookEdit`) | `tools/hooks/secret_block.py` | **Block** a write whose new content matches a secret pattern; append the pattern *names* (never the value) to `.claude/audit/blocked.log` |

**Fail-safe posture:** the audit hooks never block; a hook crash exits 0. Only the
deliberate secret match denies a write, and even the secret-block hook fails *open*
on any internal error — a scanner bug can never wedge the workflow.

## Where the logs live

All output goes to `.claude/audit/`, which is **gitignored** (operational logs, not
source). Records are redacted: file paths and tool names are kept; raw file
contents, secrets, and full diffs are replaced by a content hash + byte count
(mirroring the product's `build_llm_call_audit` hash-not-content rule).

## How to disable

Either:

- Add `"disableAllHooks": true` to `.claude/settings.json`, **or**
- Delete `.claude/settings.json`.

To disable only the blocking hook while keeping the audit trail, remove the
`PreToolUse` block from `.claude/settings.json`.

## Build the dashboard

A dependency-free HTML view of the audit trail:

```bash
python tools/hooks/gen_dashboard.py
```

Writes `.claude/audit/dashboard.html` (data embedded at generation time — open it
directly, no server needed). Regenerate after a session to refresh it.

## Query the trail (requires `jq`)

```bash
# Tool usage counts
jq -r '.tool' .claude/audit/audit.jsonl | sort | uniq -c | sort -rn

# Files the assistant edited
jq -r 'select(.tool=="Edit") | .input.file_path' .claude/audit/audit.jsonl

# Blocked secret-write attempts (pattern names only)
jq -r '"\(.file_path): \(.patterns | join(","))"' .claude/audit/blocked.log
```

## Prerequisites

- **Python on PATH** — the hooks run as `python tools/hooks/<name>.py`. If `python`
  is unavailable, the command hooks exit non-zero, which Claude Code treats as a
  non-blocking error (the workflow proceeds; the secret-block fails open).
- **`jq`** — only for the review queries above; not needed for the hooks to run.
- Hooks run with the project root as the working directory (Claude Code default);
  the scripts also resolve their own output paths via `__file__`, so logging works
  regardless of cwd.

## Security note

`.claude/settings.json` is committed and shared. Hooks execute local commands on
every contributor's machine — review `tools/hooks/*.py` before trusting a change to
them, the same way you would review any code that runs automatically.

## Tests

`tests/test_dev_workflow_hooks.py` exercises every hook as a subprocess (secret
block vs allow, no-content-leak, session summary, dashboard) and includes the
spec §6 mutation check. The repo secret-scanner (`tools/check_demo_safety.py`)
carries a narrow, documented allowlist for that one security-test file because its
fixtures are fake secret-shaped strings by design.
