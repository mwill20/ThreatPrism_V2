# ThreatPrism Start Here

Use this file for new chats instead of pasting long instructions.

## Compact Startup Prompt

```text
Work in C:\Projects\ThreatPrismV2.
Read START_HERE.md, AGENTS.md, and docs/THREATPRISM_V2_CODEX_HANDOFF.md first.
Verify live repo state with git status and the current files before answering.
Use docs/WORKING_CHECKLIST.md for current completed slices, next slice, validation, and blockers.
Do not use live providers, real credentials, real remediation, or real organization/workplace data.
Keep ALLOW_REAL_ACTIONS=false and run tools/validate-threatprism.ps1 before calling implementation complete.
If context is approaching 75% used or less than roughly 25% remains, output a compact handoff prompt and update durable handoff files before continuing.
```

## Minimal Read Order

1. `START_HERE.md`
2. `AGENTS.md`
3. `docs/THREATPRISM_V2_CODEX_HANDOFF.md`
4. `docs/WORKING_CHECKLIST.md`
5. `docs/ARCHITECTURAL_NORTH_STAR.md`

Read deeper files only when the task needs them:

- `docs/threat-models/README.md` when the task touches security posture, adds a
  trust boundary, introduces a new attacker surface, or asks about threat
  coverage. This pack (v0.2) is the source of truth for security threats — do
  not re-derive threats from prose elsewhere.
- `docs/specs/21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md` when the task is
  about treating an open threat, scheduling a mitigation slice, accepting a
  risk, or making a scope (Avoid) decision.
- `docs/specs/` for any other implementation spec.
- `docs/DATA_STRATEGY_AND_FIXTURE_FACTORY.md` when the task involves datasets
  or synthetic fixtures.
- `docs/CSI_RGOI_ARCHITECTURE.md` and
  `docs/specs/23_CSI_RGOI_FOUNDATION.md` when the task involves governed
  cognition, RAG, retrieval, memory, lineage, replay, or institutional
  learning.
- `docs/DASHBOARD_DATA_CONTRACT.md` and
  `docs/specs/24_DASHBOARD_UI_PREPARATION.md` when the task involves
  dashboard contracts, frontend planning, or dashboard readiness.
- `docs/DASHBOARD_UI_IMPLEMENTATION.md` and
  `docs/specs/25_DASHBOARD_UI_IMPLEMENTATION.md` when the task involves the
  local dashboard UI.
- `docs/DASHBOARD_PRODUCTION_HARDENING.md` and
  `docs/specs/26_PRODUCTION_DASHBOARD_HARDENING.md` when the task involves
  dashboard hardening, browser risk, CSP, or production-style dashboard
  readiness.
- `docs/PRODUCTION_IDENTITY_READINESS.md` and
  `docs/specs/28_PRODUCTION_IDENTITY_READINESS.md` when the task involves
  production auth readiness or OIDC-shaped settings.
- `docs/PRODUCTION_TOKEN_VERIFIER_DESIGN.md` and
  `docs/specs/29_PRODUCTION_TOKEN_VERIFIER_DESIGN.md` when the task involves
  production token-verifier architecture, claim-to-role authorization, or JWKS
  cache design.
- `docs/PRODUCTION_TOKEN_VERIFIER_IMPLEMENTATION.md` and
  `docs/specs/30_PRODUCTION_TOKEN_VERIFIER_IMPLEMENTATION.md` when the task
  involves the local no-network `external_oidc` verifier implementation.
- `DECISIONS.md`
- `LIMITATIONS.md`
- `README.md`
- `RUNBOOK.md`

Claude Code users: the `/threat-model` skill (global) produces output in the
exact v0.2 format used by this pack. Use it to refresh stale files or to model
a newly added component.

## Fast State Check

```powershell
Set-Location C:\Projects\ThreatPrismV2
git status -sb
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

Current known validation baseline:

```text
284 passed (3 skipped: opt-in live Prompt Guard 2 tests)
eval harness dry-run: 15 passed / 0 failed
```

## Generate Compact Handoff

Use this when context is getting tight or before starting a fresh chat.

**Claude Code users (default):**

```text
/compact-handoff
```

Or just ask the assistant: "give me a compact handoff prompt." Either path
produces the prompt inline with no shell required.

**Codex users:** ask for `compact handoff` to trigger the global
`compact-handoff` skill.

**Portability fallback (CLI / non-assistant contexts):**

```powershell
Set-Location C:\Projects\ThreatPrismV2
powershell -ExecutionPolicy Bypass -File .\tools\generate-compact-handoff.ps1
```

The PowerShell script prints the same prompt and exists for tool-agnostic
workflows. Claude Code users do not need to run it.
