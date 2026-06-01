# 🪝 Lesson 29 — Dev-Workflow AI Governance Hooks (Claude Code)

> **Goal:** Apply the same Control / Audit / Safety triangle ThreatPrism enforces
> on its *triage* LLM to the *coding assistant* building the repo — using Claude
> Code hooks.
> **Time:** ~30 min · **Prerequisites:** Lesson 04 (guardrails), the
> `docs/AI_GOVERNANCE_ASSESSMENT.md` triangle.

---

## 1. 🎯 The idea

Claude Code (the assistant editing this repo) is itself an AI acting on a system.
The same governance ThreatPrism puts around its triage LLM applies to it:

| ThreatPrism (product) | Dev-workflow hook (this lesson) |
|---|---|
| `AuditEvent` trail per action | `PostToolUse` → `audit.jsonl` |
| `build_llm_call_audit` (hash, never raw) | redacted records (hash + byte count) |
| secret tokenization + output policy | `PreToolUse` secret-block (deny write) |
| `/metrics` + run summary | `Stop` session summary + HTML dashboard |

It's **dev-workflow tooling**, not product code — it never touches the Python app,
tests, or runtime.

---

## 2. 🔌 Verify the schema first (the discipline)

Claude Code hooks evolve, so the build started by **verifying the live schema**
against `code.claude.com/docs/en/hooks` — never trusting memory. Confirmed:

- **Events:** `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`.
- **stdin JSON:** common `session_id` / `cwd` / `hook_event_name`; `tool_name` +
  `tool_input` (PreToolUse), `+ tool_response` (PostToolUse), `prompt`
  (UserPromptSubmit). **Correction found:** `Stop` carries `assistant_message`,
  not a prompt — so the session summary aggregates the JSONL trail instead.
- **Blocking:** `permissionDecision: "deny"` inside `hookSpecificOutput` (exit 0),
  or exit code 2. We use the JSON-deny mechanism (it carries a clear reason).

> 🧭 **Lesson:** for any actively-maintained external surface, verify the contract
> at build time. The `Stop`-payload correction is exactly the kind of stale-memory
> bug verification catches.

---

## 3. 🔒 The secret-block hook (`PreToolUse: Edit|Write`)

`tools/hooks/secret_block.py` scans the **new** content the assistant is about to
write (not `old_string`, so removing a secret is never blocked) against a pattern
catalog mirroring ThreatPrism's own detectors: private-key blocks, `AKIA…` AWS ids,
`ghp_…` GitHub tokens, `sk_live_…` Stripe keys, `sk-…` provider keys, DB connection
strings, and `password=`/`api_key=` assignments.

On a match it emits a `permissionDecision: deny` and appends to `blocked.log` —
**pattern names only, never the secret value**. On any internal error it exits 0
(**fail-open**): a scanner bug must never wedge the workflow. The deliberate secret
match is the *only* thing that blocks.

The `.env` asymmetry: an *assistant* write of a secret-shaped `.env` is blocked; the
human still edits gitignored `.env` by hand. (This session showed the gap a hook
closes — a real key reached a file; an active hook would have blocked the assistant
write of it.)

---

## 4. 🧪 Testing a detector + the mutation check

`tests/test_dev_workflow_hooks.py` runs each hook as a real subprocess with crafted
stdin and a tmp audit dir (`THREATPRISM_HOOK_AUDIT_DIR`) so real logs are never
touched. It asserts: secrets block + log pattern-names-only, benign text passes,
removing a secret passes, audit records carry no raw content, prompt previews are
redacted, the summary generates.

**The challenge — mutation testing:** after green, deliberately break a pattern
(we set the AWS rule to never match) and re-run — exactly one test must fail. It
did. That proves the tests aren't vacuous. A test suite that still passes when you
break a requirement is testing nothing.

> ⚠️ **Meta-gotcha:** the repo's own `check_demo_safety.py` secret-scanner flags the
> test's fake secret-shaped fixtures. Fixed with a *narrow, documented allowlist*
> for that one security-test file — never widen it to product code.

---

## 5. 🗺️ Files

| Concern | File |
|---|---|
| Shared helpers + secret catalog + redaction | `tools/hooks/_common.py` |
| PostToolUse audit | `tools/hooks/audit_post_tool.py` |
| UserPromptSubmit log | `tools/hooks/audit_prompt.py` |
| Stop session summary | `tools/hooks/session_summary.py` |
| PreToolUse secret block | `tools/hooks/secret_block.py` |
| HTML dashboard generator | `tools/hooks/gen_dashboard.py` |
| Wiring | `.claude/settings.json` |
| Tests | `tests/test_dev_workflow_hooks.py` |

Logs land in gitignored `.claude/audit/`. Build the dashboard with
`python tools/hooks/gen_dashboard.py`.

---

## 6. 🎤 Interview talk track

> "I applied our product's AI-governance model to the coding assistant itself with
> Claude Code hooks: a PostToolUse audit trail, a PreToolUse secret-write block, and
> a session summary + dashboard. I verified the hook schema against the live docs
> first — which caught that the Stop event gives `assistant_message`, not a prompt.
> Every record is redacted to hashes and sizes, never raw content. And I mutation-
> tested the secret detector: I broke a pattern and confirmed a test failed, so the
> suite actually defends the requirement. The one trap was the repo's own secret
> scanner flagging the detector's fake fixtures — solved with a narrow allowlist."

Signals: **verify-don't-assume**, **fail-safe vs fail-secure judgment** (logging
fails open, secret-write fails closed), and **mutation testing**.
