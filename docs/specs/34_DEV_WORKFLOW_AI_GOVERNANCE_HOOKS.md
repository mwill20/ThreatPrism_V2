# Spec 34 — Dev-Workflow AI Governance Hooks (Claude Code)

Status: **implemented** (2026-06-01). Hook schema verified at build against the
official docs (`code.claude.com/docs/en/hooks`): events `PreToolUse`/`PostToolUse`/
`UserPromptSubmit`/`Stop`, stdin fields, and the `permissionDecision: deny` block
mechanism. Scripts under `tools/hooks/`, wired in `.claude/settings.json`, tested
in `tests/test_dev_workflow_hooks.py` (12 tests, incl. the §6 mutation check).
Validated GREEN: 245 passed. One verified correction to the design: the `Stop`
payload carries `assistant_message` (not a prompt), so the session summary is built
by aggregating the JSONL trail, not from the Stop payload.

This is *dev-workflow tooling*, not
ThreatPrism runtime/product code — it governs the AI coding assistant (Claude
Code) working on this repo, applying the same Control / Auditability / Safety
triangle ThreatPrism enforces on its own triage LLM (see
`docs/AI_GOVERNANCE_ASSESSMENT.md`).

> **Verify-at-build note:** Claude Code hooks are an actively-maintained surface.
> Before implementing, confirm the current hook event names, the stdin JSON
> payload shape, and the blocking mechanism against the official Claude Code hooks
> docs (the `hookify` and `update-config` skills can scaffold `settings.json`).
> This spec records the design and contracts, not verified hook code.

---

## 1. Purpose & use case

- **Forensic reconstruction:** a complete, queryable trail of every action the AI
  took on the repo (what tool, what input, what result, when) — the dev-workflow
  analogue of ThreatPrism's `AuditEvent` trail.
- **Leak prevention:** stop the assistant from writing accidentally-leaked
  credentials into files or commits — the analogue of ThreatPrism's secret
  tokenization + output policy. (This session showed the gap: a live key reached a
  file; a `PreToolUse` scan would have blocked an *assistant* write of it.)
- **Operational visibility:** a per-session summary + a file-based HTML dashboard
  that renders the JSONL trail visually — the analogue of `/metrics` + the run
  summary.

This is optional/educational + operational; it does not touch the Python app, the
test suite, or the runtime. It must **fail safe** (a hook error must not silently
block all work, except the deliberate secret-detection block).

---

## 2. Scope — four hooks + a dashboard

| Hook event | Matcher | Action |
|---|---|---|
| `PostToolUse` | all tools | Append one JSONL record (timestamp, tool, redacted input summary, result summary, cwd) to `.claude/audit/audit.jsonl` |
| `UserPromptSubmit` | n/a | Append the submitted prompt (length + redacted preview) to `.claude/audit/prompts.jsonl` |
| `Stop` | n/a | Generate a session summary (tool counts, files touched, blocks) to `.claude/audit/session-<id>.md` |
| `PreToolUse` | `Edit\|Write` | Scan the proposed content for secrets; **block** on match (non-zero/decision-deny) and append to `.claude/audit/blocked.log` |

**Challenge deliverable:** a static `.claude/audit/dashboard.html` that loads the
JSONL and renders it as a table/timeline (dependency-free, same posture as the
ThreatPrism dashboard) — plus a small generator if needed.

---

## 3. Secret-detection contract (PreToolUse `Edit|Write`)

Block the edit/write if the proposed content matches any of:

- **API keys:** 20+ char high-entropy alphanumerics in an assignment context
- **Passwords in config:** `(?i)password\s*=\s*\S+`
- **Private keys:** `-----BEGIN [A-Z ]*PRIVATE KEY-----`
- **Provider tokens:** GitHub (`ghp_`, `gho_`, …), Stripe (`sk_live_`, `rk_live_`), AWS (`AKIA[0-9A-Z]{16}`)
- **DB connection strings:** `(?i)(postgres|mysql|mongodb)(\+\w+)?://\S+:\S+@\S+`

On match: deny the tool call with a clear reason, and append a record to
`blocked.log` (timestamp, file path, matched **pattern name only** — never the
matched secret value).

**Reuse opportunity:** these patterns overlap ThreatPrism's own
`guardrails/healthcare.py` secret detectors and `guardrails/policy.py` `sk-` rule —
the hook can share the same pattern catalog so product and dev-workflow secret
detection stay in sync (and a single quarterly refresh — `PATTERN_REFRESH.md` —
covers both).

### `.env` handling (deliberate)
A `Write` of a `.env` containing secret-shaped content is **blocked** — the
*assistant* must not write real secrets. The human still edits `.env` manually
(it is gitignored). This is the correct asymmetry: deny AI-authored secrets, allow
human-managed local secrets.

---

## 4. Auditability contract (must not leak)

- Records are **append-only JSONL**; one event per line.
- Inputs/results are **summarized + redacted** before logging — file paths and tool
  names are fine; raw file contents, secrets, and full diffs are **not** written
  verbatim (log a content hash + byte count, mirroring ThreatPrism's
  `build_llm_call_audit` hash-not-content rule).
- `.claude/audit/` is **gitignored** (operational logs, not source).

---

## 5. Configuration

Project-level `.claude/settings.json` `hooks` block wiring each event to a script
under `tools/hooks/` (Python, cross-platform — invoked as
`python tools/hooks/<name>.py`, since this repo runs on Windows/PowerShell where
shell one-liners are not portable). Scripts read the hook JSON from stdin and:
- `PreToolUse` secret scan: exit/deny to block.
- others: write their JSONL/markdown and exit 0.

---

## 6. Test plan

| # | Action | Expected |
|---|--------|----------|
| 1 | Edit a file to contain `api_key = "sk_live_abc123…"` | **BLOCKED** + `blocked.log` entry |
| 2 | Edit a file to contain `name = "John Doe"` | **ALLOWED** |
| 3 | Write a `.env` with secret-shaped content | **BLOCKED** |
| 4 | Make a few normal edits | `audit.jsonl` gains one record per tool call |
| 5 | End the session | a `session-<id>.md` summary is generated |

Review queries (require `jq`):
```bash
jq -r '.tool' .claude/audit/audit.jsonl | sort | uniq -c | sort -rn
jq -r 'select(.tool=="Edit") | .input.file_path' .claude/audit/audit.jsonl
```

**Mutation check (the challenge):** after tests pass, intentionally break a
secret-detection requirement (e.g., loosen one pattern). Re-run the test cases —
they must catch it. If they do not, the spec/tests are incomplete; iterate until a
broken requirement fails a test. (Same discipline as ThreatPrism's regression
fixtures.)

---

## 7. Out of scope / cautions

- Not product/runtime code; does not affect the Python app, `validate-threatprism.ps1`,
  or CI.
- Hooks must fail safe; a logging-hook crash must not block unrelated work.
- Cross-platform: scripts are Python; the `jq` review queries assume `jq` is
  installed (document as a prerequisite).
- Confirm the exact Claude Code hook schema at build time (see verify-at-build note).
