# Lesson 15: Threat Model Treatment And Demo Hardening

## Goal

Understand how ThreatPrism turns threat-model findings into explicit treatment
decisions, then backs the POC-scope decisions with demo-safe hardening tests.

This lesson is about the threat treatment and demo hardening slice. It does not
approve live providers, real credentials, real organization data, real PHI/ePHI,
production identity, multi-tenancy, RAG, memory, tool calling, or remediation.

## Primary Files

```text
docs/threat-models/*.md
docs/specs/21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md
docs/runbooks/PATTERN_REFRESH.md
tests/test_quarantine_enforcement.py
tests/test_api_limits.py
tests/test_overclaim_regression.py
tests/test_phi_detector_coverage.py
tests/test_stage1_no_rehydration.py
tests/test_token_vault_isolation.py
```

## What The Slice Adds

Threat Model Pack v0.2 and the Treatment Register follow-up add:

- A structured threat model pack under `docs/threat-models/`.
- A treatment register that labels threats as mitigate, accept, transfer, avoid,
  or gated mitigation.
- Owner decisions for current fake-data POC scope.
- Explicit gates before real LLM, RAG, memory, tool calling, multi-tenancy,
  non-demo data, real PHI, and production persistence work.
- POC hardening for auth defaults, request resource controls, dependency
  tracking, pattern refresh, quarantine enforcement, token vault isolation, and
  stage-1 token non-rehydration.

The important lesson: a threat is not handled just because it is documented.
ThreatPrism records the treatment decision and either lands a control, accepts
the risk for POC scope, transfers the risk to an operator boundary, avoids the
surface, or gates the mitigation before the future feature can land.

## Mental Model

```text
Threat model finding
  -> Treatment decision
  -> Owner and scope
  -> Control or explicit gate
  -> Test coverage
  -> Checklist and review cadence
```

For current POC scope, the treatment register closes cheap, foundational
controls while keeping larger production surfaces gated. That matters because a
demo-safe product can still have disciplined risk ownership without pretending
to be production-ready.

## Threat Model Pack

The threat model pack lives in `docs/threat-models/`.

| File | Purpose |
|------|---------|
| `README.md` | Pack index, current scope, critical findings, and validation path. |
| `system-context.md` | Assets, users, integrations, trust boundaries, data flows, and assumptions. |
| `stride-threat-model.md` | Traditional application/API risks. |
| `llm-agent-threat-model.md` | AI-specific risks from prompt injection, unsafe output, provider supply chain, tools, and agency. |
| `healthcare-data-threat-model.md` | Privacy risks around linkability, identifiability, disclosure, unawareness, and non-compliance. |
| `mitigations-traceability.md` | Threat ID to mitigation and test references. |

Use the pack before adding any new trust boundary, external integration, role,
storage layer, model provider, retrieval layer, memory feature, or dashboard
surface.

## Treatment Register

`docs/specs/21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md` is the binding
POC-scope treatment record.

It separates five outcomes:

| Treatment | Meaning |
|-----------|---------|
| Mitigate | Land a control that lowers the risk for the current scope. |
| Accept | Formally own the risk because it is tolerable at the current scope. |
| Transfer | Assign the control to an operator or provider boundary. |
| Avoid | Do not build the risky surface. |
| Gated mitigation | Commit to mitigation before a future feature lands. |

Examples:

- Prompt quarantine enforcement is mitigated now for POC scope.
- Real LLM semantic prompt-injection defenses are gated until real LLM work.
- Real PHI handling is avoided in current scope.
- Unsalted hashes are accepted only for fake demo data and gated before
  non-demo data.

## Demo Hardening Tests

The hardening tests make the treatment register executable enough for local
development.

| Test file | What it protects |
|-----------|------------------|
| `tests/test_quarantine_enforcement.py` | Prompt-firewall quarantine blocks provider execution and exposes a clear blocked-by-firewall response. |
| `tests/test_api_limits.py` | Oversized request rejection, POST `/cases` rate limiting, and triage concurrency caps. |
| `tests/test_overclaim_regression.py` | Compliance, medical, legal, and action overclaim patterns stay covered by fixtures. |
| `tests/test_phi_detector_coverage.py` | Healthcare detector fixtures cover current sensitive-data detector families. |
| `tests/test_stage1_no_rehydration.py` | Stage-1 healthcare safeguard tokens are never marked rehydratable. |
| `tests/test_token_vault_isolation.py` | Token vault mappings do not leak through serialized cases, reports, API responses, or persistence blobs. |

## Quarantine Enforcement

Prompt-firewall quarantine is a hard stop before provider execution.

The test uses a counting provider that raises if `generate_report()` is called.
When a payload contains quarantine-triggering instructions, triage must:

1. Stop before provider execution.
2. Set the case triage status to `blocked_by_guardrail`.
3. Avoid creating a triage report.
4. Record a `triage_blocked_by_prompt_firewall` audit event.
5. Return a report endpoint message that names the prompt firewall as the
   blocker.

This is stronger than simply recording a sanitization warning. The risky input
does not reach the model-provider boundary.

## HTTP DoS Controls

The API limit tests protect the local demo backend from easy resource abuse:

- Request bodies above `MAX_REQUEST_BODY_BYTES` return HTTP 413 before normal
  case validation.
- POST `/cases` request bursts return HTTP 429 once the configured limit is
  exceeded.
- Background triage calls run behind a bounded semaphore.

These controls are POC safeguards, not a complete production edge-security
story. Production deployment would still need a reverse proxy, centralized rate
limiting, request logging, TLS, and operator-owned infrastructure controls.

## Pattern Refresh

`docs/runbooks/PATTERN_REFRESH.md` keeps detector and prohibited-output rules
from becoming one-time regex decisions.

The pattern refresh process should:

1. Review recent eval failures and near misses.
2. Add fixtures before adding new patterns.
3. Confirm every prohibited phrase category has a regression fixture.
4. Confirm healthcare detector examples cover current detector families.
5. Record the review result in durable project docs.

The paired tests are:

- `tests/test_overclaim_regression.py`
- `tests/test_phi_detector_coverage.py`

## Token Vault And Stage-1 Tokens

Two tests lock down the sensitive-data boundary:

- `tests/test_token_vault_isolation.py` proves token-to-raw-value mappings are
  not serialized into outward-facing or persisted artifacts.
- `tests/test_stage1_no_rehydration.py` proves Stage-1 healthcare safeguard
  tokens are never marked as rehydratable for any role.

This preserves the core architecture: tokenize before model-visible payloads,
validate output before any controlled rehydration, and never expose the vault
mapping as an operational shortcut.

## Run The Focused Tests

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest -p no:cacheprovider `
  tests\test_quarantine_enforcement.py `
  tests\test_api_limits.py `
  tests\test_overclaim_regression.py `
  tests\test_phi_detector_coverage.py `
  tests\test_stage1_no_rehydration.py `
  tests\test_token_vault_isolation.py `
  --basetemp .pytest_tmp_lesson15
```

Full safe validation:

```powershell
Set-Location C:\Projects\ThreatPrismV2
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

## Review Questions

- Does every threat-model finding have a treatment decision?
- Is each accepted risk explicitly scoped to fake-data POC use?
- Are real LLM, RAG, memory, tools, multi-tenancy, non-demo data, and real PHI
  still gated or avoided?
- Does quarantine stop provider execution, or only record a warning?
- Do request limits fail closed before expensive processing?
- Do pattern and detector changes require fixtures first?
- Can any API response, persisted blob, report, or eval artifact expose token
  vault mappings?
- Can Stage-1 healthcare safeguard tokens ever be marked rehydratable?

## Quick Reference

- Threat model pack: `docs/threat-models/`.
- Treatment register: `docs/specs/21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md`.
- Pattern refresh runbook: `docs/runbooks/PATTERN_REFRESH.md`.
- Current scope: fake-data POC only.
- Current action boundary: `ALLOW_REAL_ACTIONS=false`.
- Full validation command: `tools/validate-threatprism.ps1`.

---

## ⚖️ Decisions & Trade-offs

### Decisions Touched

| Decision | Statement | Why It Matters Here |
|----------|-----------|---------------------|
| D-010 | V2 permits recommended/simulated actions only; `ALLOW_REAL_ACTIONS=false` by default | The "Avoid" treatment for real-action threats is the simplest possible treatment: not building the surface means the threat doesn't apply |
| D-011 | V2 must use layered guardrails with fail-closed behavior | Each implementation slice in this lesson (Slice A–G) closes a specific D-011 requirement; the treatment register maps every slice to the guardrail layer it implements |
| D-021 | ThreatPrism treats inbound SOAR data as potentially contaminated | Drives healthcare safeguard slice and the quarantine-enforcement requirement |
| D-025 | `docs/ARCHITECTURAL_NORTH_STAR.md` is the directional architecture guide | The North Star's 10-question decision rubric (see Lesson 42) is the pre-implementation checklist that keeps all future treatments aligned |

### Treatment Pattern: Why Gated Mitigations Exist

The treatment register uses "Gated Mitigation" for controls that are needed but whose trigger surface doesn't exist yet. Building the control before the surface is wasteful; skipping it entirely is unowned risk. The gate makes the commitment explicit: the control must land before the feature lands.

Key gated rows and their triggers:

| Threat ID | Threat | Treatment | Opens When |
|-----------|--------|-----------|------------|
| T1 / OT-1 | SQLite blob tampering not detectable | Gated Mitigation | Non-demo persistence is introduced |
| R1 / RR-R1 / OT-8 | Audit log not tamper-evident; no retention | Gated Mitigation | Non-demo data flows through the system |
| L2 / OT-L1 | Indirect prompt injection via RAG | Gated Mitigation | Live RAG / external retrieval corpus is added |
| L4 / OT-L2 | Training data poisoning | Avoid → Gated Mitigation | Fine-tuning pipeline is added |
| I4 / OT-7 | Prompt firewall bypassable | Mitigated (detector built); gate enablement | Real LLM provider integration is enabled |

### What We Explicitly Rejected

- **Documenting threats without treatment decisions:** "TODO: needs owner" is unowned risk. The treatment register forces every finding to receive one of Mitigate, Accept, Transfer, or Avoid — with a named owner. An undecided threat is not a managed risk.
- **Implementing all mitigations simultaneously:** Gated mitigations are sequenced deliberately. Building a tamper-evident audit log for SQLite makes no sense if the system will switch to PostgreSQL before non-demo data arrives. Sequencing avoids premature controls for surfaces that don't yet exist.

### Trade-off Log

| Choice Made | What We Gained | What We Gave Up |
|-------------|----------------|-----------------|
| Mitigate for POC-scope risks, Accept for low-blast-radius demo risks | Cheap foundational controls land now; full production controls wait for explicit gates | Some threats have residual risk at POC scope with owner sign-off |
| Avoid for real actions (D-010) vs. gated mitigation | Simplest possible treatment for action safety; no surface = no threat | Product must eventually implement real actions with appropriate controls when the surface is built |
| Detector-not-gate for semantic firewall (I4/OT-7) | Semantic classifier adds detection signal without adding a probabilistic block path; byte-identical when disabled | Novel semantic bypasses that neither layer detects remain a residual risk; accepted with owner sign-off |

### Future Gate Conditions

This component's design would change if any of the following trigger conditions are met:

- **Real LLM integration** → re-opens I4/OT-7 (semantic gate enablement), L2/OT-L1 (RAG), L5/OT-L3 (cost/DoS), L6/OT-L4 (output safety framing)
- **Non-demo persistence** → re-opens T1/OT-1 (SQLite tampering), R1/RR-R1/OT-8 (audit retention and tamper-evidence)
- **Real PHI handling** → re-opens the full healthcare and LINDDUN threat set; legal review required before treatment decisions

### Limitations in Scope

- `[Demo-Safe Boundary]` All current POC treatment decisions are scoped to fake-data demo; every Gated Mitigation row requires explicit re-opening before its trigger feature ships
- `[Accepted Risk]` Pattern-based prompt firewall has residual bypassability risk; accepted for POC scope with owner sign-off (I4, 2026-05-24)
- `[Accepted Risk]` Unsalted SHA-256 hash chain tokens are acceptable for demo scope; require salting before non-demo use (T1, 2026-05-24)
