# 21 Threat Model Treatment And Risk Register

## Slice Name

Threat Model Treatment & Risk Register v0.1

Status: owner decision pass recorded for POC scope; Slices A, B, D, E, F, and G plus Production Identity Readiness v0.1, Production Token Verifier Design v0.1, and Production Token Verifier Implementation v0.1 implemented for current POC/readiness scope.

## Goal

Close the loop between the v0.2 threat model pack ([`docs/threat-models/`](../threat-models/README.md)) and shipped code. Every open threat and residual risk surfaced by the pack must receive exactly one treatment decision — **Mitigate**, **Accept**, **Transfer**, or **Avoid** — with a named owner and either a scheduled slice or a formal acceptance record.

A threat without a treatment decision is not a known risk. It is an unowned risk. This spec converts the v0.2 pack's `TODO: needs owner` markers into either:

- A scheduled implementation slice with acceptance criteria, **or**
- A signed acceptance record with named owner and justification, **or**
- A gated decision (Mitigate, but not until a precondition lands), **or**
- A scope decision (Avoid by not building the surface).

## Why This Spec Exists

The v0.2 threat model pack identified 25 open threats and 10 residual risks against the current backend. It assigned severity using a likelihood × impact rubric and mapped every mitigation to a code-level `file:function` reference. It deliberately stopped short of treatment decisions because **treatment is a people-decision, not a technical one** — the threat model author can propose, but the project owner has to choose.

The standing rule for this spec:

```text
Threats are not treated until a decision is recorded, signed by an owner,
and either landed in code or formally accepted.
```

A `TODO: needs owner` is unowned risk. An `Accepted by: <name>, <date>` is owned risk. The format distinction is the whole point of risk treatment.

## Owner Decision Pass - 2026-05-24

The project owner accepted the recommendation to treat this as a fake-data POC
that should remain capable of growing into MVP and later production/enterprise
readiness. This pass records binding decisions for current POC scope only:

- **Mitigated now:** cheap or foundational controls that reduce current POC risk
  without adding live providers or real data handling. Completed order: Slice D,
  Slice A, Slice B, Slice F, Slice E.
- **Accept for POC only:** low-blast-radius demo risks where the fake-data
  boundary makes the risk operationally tolerable.
- **Avoid for current scope:** real PHI, fine-tuning, tools/function-calling,
  memory/write-back, and multi-tenancy stay out of scope until explicitly
  approved.
- **Gated mitigation:** anything needed for MVP, production, enterprise, real
  LLM, RAG, memory, multi-tenancy, non-demo data, or real PHI must be re-opened
  before that feature lands.

Owner field convention for this pass: `Project owner (POC), 2026-05-24`.
This is not an external GRC, HIPAA, HITRUST, legal, or compliance
certification review.

## Treatment Vocabulary

Each open threat or residual risk receives exactly one of:

| Treatment | Meaning | When to choose it |
|-----------|---------|--------------------|
| **Mitigate** | Implement a control that reduces the residual risk to Low. | The threat applies to the current system and a feasible control exists. |
| **Accept** | Formally accept the residual risk with a named owner and justification. | The mitigation cost outweighs the risk, the risk is operationally tolerable, or the mitigation is technically infeasible at this scope. |
| **Transfer** | Push responsibility for the control to another party (vendor, contract, operator, insurance). | Another party is better positioned to control the risk and the transfer is contractually or operationally enforceable. |
| **Avoid** | Change the system so the threat does not apply. | The simplest treatment is to not build the surface that creates the threat. |

A "Gated Mitigation" is a Mitigate decision whose implementation does not start until a precondition lands (e.g., "Mitigate before real LLM provider integration"). It is still a Mitigate decision — the gate just sequences when the slice runs.

## In Scope

This spec covers:

- A complete Treatment Decision Matrix for the 25 open threats and 10 residual risks identified in the v0.2 pack.
- Six implementation slices that group **Mitigate** decisions by code touchpoint.
- A Gated Treatments table for **Mitigate** decisions that depend on preconditions.
- An Accepted Risks log structured to receive owner signatures.
- A Treatment Register Update Process for keeping the register current as treatments land and as new threats emerge.

This spec does not:

- Implement production, enterprise, real-LLM, real-PHI, RAG, memory, tool-calling, or multi-tenant controls. The current implementation pass closed only the POC-scope slices listed below.
- Override or replace any of the lens files in [`docs/threat-models/`](../threat-models/README.md). When a treatment lands, both the lens file and this spec must be updated.
- Make the people-decisions on its own. Every `TODO: needs owner` marker requires explicit owner sign-off before the treatment is considered committed.

---

## Treatment Decision Matrix

Treatment decisions for every open threat (OT-X) and residual risk (RR-X) in the v0.2 pack. POC decisions are owner-approved for current fake-data scope; gated rows must be re-opened when their trigger condition appears.

### From STRIDE

| ID | Threat (short) | Proposed Treatment | Slice | Owner | Notes |
|----|----------------|---------------------|-------|-------|-------|
| S1 / RR-S1 | Default `demo_api_keys` are public in source | **Mitigated** | Slice A | Project owner (POC), 2026-05-24 | Defaults removed from `Settings`; `demo_key` mode now requires explicit `DEMO_API_KEYS`; covered by `tests/test_ops_safety.py` |
| S2 / RR-S2 / OT-4 | `API_AUTH_MODE=none` default + narrow prod guard | **Mitigated** | Slice A | Project owner (POC), 2026-05-24 | Disabled auth now requires explicit local-dev acknowledgement; startup warns; covered by `tests/test_ops_safety.py` |
| S3 | Production identity readiness misconfiguration | **Mitigated for readiness scope** | Production Identity Readiness v0.1 | Codex, 2026-05-26 | `external_oidc` now requires static readiness config, rejects incomplete verifier enablement, and keeps protected routes fail-closed when local verification is disabled; live IdP/JWKS integration remains gated |
| S4 / OT-9 | Production token verifier trusts unverified or unauthorized claims | **Mitigated for local no-network verifier scope; live integration gated** | Production Token Verifier Implementation v0.1 | Codex, 2026-05-26 | Local verifier verifies signature, issuer, audience, time claims, tenant claim, subject claim, role claim, role mapping, and sanitized audit before authorization; live JWKS/IdP integration remains gated |
| T1 / OT-1 | SQLite blob tampering not detectable | **Gated Mitigation** | Gated (real persistence) | Project owner (POC), 2026-05-24 | Append-only audit table + hash chain. Not warranted while the system is demo-only with SQLite; required before any non-demo persistence |
| T2 | LLM provider returns report with unsupported evidence | **Mitigated** (current) | n/a | n/a | Already implemented via `validate_report_evidence()`. No further treatment required |
| T3 / OT-5 / RR-LD3 | `PROHIBITED_PATTERNS` regex needs refresh process | **Mitigated** | Slice F | Project owner (POC), 2026-05-24 | Quarterly review runbook and overclaim fixtures added; first review scheduled 2026-08-24 |
| R1 / RR-R1 / OT-8 | Audit log not tamper-evident; no retention/export | **Gated Mitigation** | Gated (non-demo data) | Project owner (POC), 2026-05-24 | Separate audit table + append-only log + retention policy. Same gate as OT-1 |
| I1 | Raw PHI/PII reaches LLM | **Mitigated** (current) | n/a | n/a | Already implemented via Stage 1 tokenization. No further treatment required |
| I2 / DI3 | Security telemetry leaks to non-analyst roles | **Mitigated** (current) | n/a | n/a | Already implemented via `render_role_view()`. No further treatment required |
| I3 / OT-6 | No test asserts `TokenVault` is never serialized | **Mitigated** | Slice D | Project owner (POC), 2026-05-24 | `tests/test_token_vault_isolation.py` added |
| I4 / RR-I4 / OT-7 | Prompt firewall is pattern-based, bypassable | **Mitigation implemented (default-off), live-verified 4/6** → Mitigated once enabled with the live model | Slice (semantic firewall) implemented + live-verified; enablement gated | Project owner (POC), 2026-05-24; control selection 2026-05-30; implemented + live-verified 2026-05-31 | Local semantic classifier `meta-llama/Llama-Prompt-Guard-2-86M` (pinned rev `a8ded8e6`) per [spec 32](32_SEMANTIC_PROMPT_INJECTION_LAYER.md) is **built, wired, and live-verified** as a detector-not-gate (escalate-only `max(deterministic, semantic)`), default-off. Policy/merge/no-egress/disabled-byte-identical proven with a fake scorer; **live run recovers 4/6 deepset RR-L1 rows** at threshold 0.9 (explicit override injections; 2 generic-instruction rows residual). The classifier adds the OT-L11 surface (model evasion / FP-DoS). Enable only under the real-LLM gate |
| D1 / OT-2 | No HTTP request body size limit | **Mitigated** | Slice B | Project owner (POC), 2026-05-24 | `/cases` now rejects oversized bodies with 413; covered by `tests/test_api_limits.py` |
| D2 / OT-3 | No rate limiting / concurrency cap | **Mitigated** | Slice B | Project owner (POC), 2026-05-24 | In-process rate limiter and triage semaphore added; covered by `tests/test_api_limits.py` |
| D3 | Eval fixture path traversal | **Mitigated** (current) | n/a | n/a | Already implemented via `_resolve_under_approved_dir()`. No further treatment required |
| E1 | `?role=` privilege escalation | **Mitigated** (current) | n/a | n/a | Already implemented via `ROLE_VIEW_POLICY`. No further treatment required |
| E2 | `real_action_executed: true` bypass | **Mitigated** (current) | n/a | n/a | Already implemented via `enforce_action_safety()`. No further treatment required |

### From LLM / ATLAS / OWASP LLM Top 10

| ID | Threat (short) | Proposed Treatment | Slice | Owner | Notes |
|----|----------------|---------------------|-------|-------|-------|
| L1 / RR-L1 / OT-L5 | Quarantine flag did not abort service-layer triage | **Mitigated** (OT-L5 closed); RR-L1 **further mitigated** 2026-06-01 | Slice G + Real-LLM Gate Opening | Codex; Project owner, 2026-06-01 | `run_triage()` blocks on `operation="quarantine"` before provider execution (`triage_blocked_by_prompt_firewall`). The semantic prompt-injection firewall (spec 32, local Prompt Guard 2) is now active as a **detector** with review/quarantine bands; the deterministic firewall + Slice G enforcement remain the hard gate (detector-not-gate, Lesson 30). **Residual:** novel semantic bypass that neither layer detects — accepted with owner sign-off below |
| L2 / OT-L1 | No indirect prompt injection defenses (RAG) | **Gated Mitigation**; read-only CSI/RGOI foundation implemented | Gated (live RAG) | Project owner (POC), 2026-05-24 | CSI/RGOI v0.1 adds read-only retrieval governance, tenant namespace filtering, retrieved-object sanitization, evidence-ID binding, trust scoring, and quarantine exclusion for fake in-memory cognition. Live RAG, external corpora, and production retrieval remain gated per [LLM threat model "Before RAG"](../threat-models/llm-agent-threat-model.md#before-rag--retrieval). |
| L3 | Insecure output handling | **Mitigated** (current) | n/a | n/a | Already implemented via three-layer validation. No further treatment required |
| L4 / OT-L2 | Training data poisoning | **Avoid** (current) → **Gated Mitigation** (if fine-tuning added) | Gated (fine-tuning) | Project owner (POC), 2026-05-24 | Current avoid is "no fine-tuning pipeline exists." If that changes, treat per LLM threat model "Before Memory / Write-Back" preconditions |
| L5 / OT-L3 | LLM DoS (cost, context, recursion) | **Mitigated** (gate opened 2026-06-01) | Real-LLM Gate Opening | Project owner, 2026-06-01 | Per-run spend cap `llm_max_cost_usd_per_run` (default $5) enforced by `metered_generate`/`metered_evaluate` (fail-closed on breach), per-call usage metering (specs 35/36), HTTP body cap bounds input size (Slice B), triage concurrency cap. **Residual:** no separate per-request *token* budget beyond the cost cap; recursion N/A (no agent loop). See Gate-Opening section |
| L6 / RR-L2 / OT-L6 | `requirements.txt` uses `>=` not `==`; no dep scan | **Mitigated** | Slice E | Project owner (POC), 2026-05-24 | Direct dependencies exact-pinned; transitive lock file and advisory `pip-audit` hook added |
| L7 / RR-L3 / OT-L7 | Output regex catches only known credential shapes | **Partially Mitigated** (gate opened 2026-06-01) | Real-LLM Gate Opening | Project owner, 2026-06-01 | Output-policy scan now sources the shared secret catalog (`secret_catalog.py`, spec 34 §3) — broadened from `sk-` only to the full provider-token set. **Residual:** entity-extraction / data-regurgitation detection on output is still future work. Accepted as residual with owner sign-off below |
| L8 / OT-L4 | No tool/plugin design | **Avoid** (current) → **Gated Mitigation** (if tools added) | Gated (function-calling) | Project owner (POC), 2026-05-24 | Per LLM threat model "Before Tool / Plugin / Function-Calling" preconditions: allowlist + parameter validation + human approval + audit per call |
| L9 | Excessive agency | **Mitigated** (current) | n/a | n/a | Already implemented via `ALLOW_REAL_ACTIONS=false` + `enforce_action_safety()`. No further treatment required |
| L10 | Overreliance | **Mitigated** (current) | n/a | n/a | Already implemented via three-layer deterministic validation + `analyst_review_required=True`. No further treatment required |
| L11 | Model theft | **N/A** | n/a | n/a | ThreatPrism does not expose a model API |
| L12 | Hallucinated citations | **Mitigated** (current) | n/a | n/a | Already implemented via `validate_report_evidence()` |
| L13 | Compliance overclaim | **Mitigated** (current pattern set) | n/a | n/a | Pattern-set refresh handled by OT-5 / Slice F |
| OT-L8 | Memory / write-back unspecified | **Avoid** for write-back; read-only CSI/RGOI foundation implemented | Gated (memory write-back) | Project owner (POC), 2026-05-24 | CSI/RGOI v0.1 is not unrestricted AI memory and exposes no write APIs, trust mutation, knowledge approval, or suppression publication. Any memory write-back remains gated per LLM threat model "Before Memory" preconditions. |
| OT-L9 | Cross-tenant isolation unspecified | **Avoid** for production multi-tenancy; defensive CSI namespace implemented | Gated (multi-tenancy) | Project owner (POC), 2026-05-24 | CSI/RGOI v0.1 requires tenant IDs as defensive cognition namespaces and tests cross-tenant suppression. This is not MSSP multi-tenancy or production tenant administration, which remains gated per LLM threat model "Before Multi-Tenancy" preconditions. |

### From LINDDUN

| ID | Threat (short) | Proposed Treatment | Slice | Owner | Notes |
|----|----------------|---------------------|-------|-------|-------|
| LD1 | Per-case token vault prevents cross-case linkage | **Mitigated** (current) | n/a | n/a | Already implemented architecturally — per-case `HealthcareTokenVault` |
| LD2 / ID1 / RR-LD1 / OT-LD2 | `raw_value_hash` is unsalted SHA-256 | **Accept** (demo scope) → **Gated Mitigation** (non-demo) | Gated (non-demo data) | Project owner (POC), 2026-05-24 | Per-record salt or HMAC with service-side key. Risk is tolerable for fake demo data; mandatory before any non-demo data |
| ID2 | Token shape leaks detector class | **Accept** (design tradeoff) | n/a | Project owner (POC), 2026-05-24 | Intentional — analysts need to know what type of sensitive data was tokenized for triage |
| NR1 | Subject non-repudiation | **N/A** | n/a | n/a | Subjects do not interact with ThreatPrism |
| DT1 | `potential_sensitive_data_exposure` flag visible to ops roles | **Accept** (design tradeoff) | n/a | Project owner (POC), 2026-05-24 | Intentional — operational signal for `/queues/healthcare-review` |
| DT2 | Case existence detectable to anyone with read access | **Mitigated** (current via access control) | n/a | n/a | Already implemented via `ROLE_VIEW_POLICY` + audit events |
| DI1 / OT-LD3 | Healthcare detector list needs refresh process | **Mitigated** | Slice F (shared with OT-5) | Project owner (POC), 2026-05-24 | Healthcare detector coverage fixtures and quarterly refresh runbook added |
| DI2 | Stage 1 tokens accidentally rehydrated | **Mitigated structurally** + **Mitigate now** | Slice D | Project owner (POC), 2026-05-24 | Add regression test asserting no Stage 1 token ever appears with `rehydration_allowed=True` |
| DI3 / RR-LD2 | Role-view masking is regex-based; novel formats may leak | **Accept** (current SOAR sources) + **Mitigate** (when adding new sources) | per-source decision | Project owner (POC), 2026-05-24 | Expand `SECURITY_TELEMETRY_PATTERNS` as new sources are added; consider structured-field masking |
| DI4 | Audit event leaks raw PHI in metadata | **Mitigated** (current) | n/a | n/a | Already implemented via `_request_metadata_hash()` + `SafeAuditEvent` projection |
| DI5 | Eval artifact leak | **Mitigated** (current) | n/a | n/a | Already implemented via `_safe_preview()` + `_strip_eval_metadata()` |
| DI6 | Metrics / read model leak | **Mitigated** (current) | n/a | n/a | Already implemented; eval category `metrics_read_model_leakage` tests it |
| UA1 | Subject unawareness | **N/A** | n/a | n/a | Operator responsibility under their own privacy notice |
| NC1 | False compliance/certification claims | **Mitigated** (current pattern set) | n/a | n/a | Pattern-set refresh handled by Slice F |
| NC2 / OT-LD1 | System not HIPAA-compliant for real PHI | **Avoid** (current scope) → **Gated Mitigation** (if real PHI added) | Scope decision | Project owner (POC), 2026-05-24 | Explicitly document in `README.md`, `SECURITY.md`, and `docs/specs/01_PRODUCT_REQUIREMENTS.md` that ThreatPrism does not process real PHI. Treating this as Avoid (rather than Mitigate-via-HIPAA-compliance) is the honest answer for the current project |
| NC2 / OT-LD6 | No breach-notification workflow | **Gated Mitigation** | Gated (non-demo data) | Project owner (POC), 2026-05-24 | Required before any non-demo data; out of scope while NC2 is Avoid |
| NC3 / OT-LD5 | Minimum-necessary policy review | **Accept** (current) + **Mitigate** (operator workflow review before deployment) | non-technical | Project owner (POC), 2026-05-24 | Requires a workflow-review session with the operator, not a code change |
| OT-LD4 | Document `potential_sensitive_data_exposure` flag semantics | **Mitigated** | Slice F/docs | Project owner (POC), 2026-05-24 | Operator-facing semantics added in `docs/HEALTHCARE_SAFEGUARD_GUARDRAILS.md` |
| OT-LD7 | Assert no Stage 1 token ever has `rehydration_allowed=True` | **Mitigated** | Slice D | Project owner (POC), 2026-05-24 | `tests/test_stage1_no_rehydration.py` added |

---

## Implementation Slices

Each slice below is a candidate for its own future spec (`22_...md`, `23_...md`, etc.) when scheduled. The slice descriptions here are the treatment blueprints, not the implementation specs.

### Slice A — Auth Hardening

Status: implemented for current POC scope.

Closes: S1 / RR-S1 / S2 / RR-S2 / OT-4.

**Goal.** Make ThreatPrism fail-closed on authentication when running anywhere except an explicitly-acknowledged local-developer mode.

**Required behavior:**

- Remove the default `demo_api_keys` value from `Settings` at [`config.py:13-20`](../../src/threatprism/config.py). The field must have no default — `Settings.from_env()` reads it from `DEMO_API_KEYS` env var or empty.
- When `api_auth_mode == "demo_key"` and `demo_api_keys` is empty, `validate_runtime()` must raise.
- Add a new env-driven setting `THREATPRISM_AUTH_REQUIRED` (default `true`). When `true`, `api_auth_mode == "none"` is rejected by `validate_runtime()` unless a separate explicit env `THREATPRISM_LOCAL_DEV_ACK=true` is set.
- The current `env in {"prod", "production"}` check stays as a backstop but is no longer the primary guard.
- Startup logs the active auth mode and warns prominently when `api_auth_mode == "none"`.

**Acceptance criteria:**

- `pytest tests/test_ops_safety.py` covers: (a) fail-closed with `demo_key` mode + no keys configured; (b) fail-closed with `none` mode + no `LOCAL_DEV_ACK`; (c) fail-open with `LOCAL_DEV_ACK=true` and prominent warning logged.
- `docs/threat-models/stride-threat-model.md` is updated: S1, S2, OT-4 move to **Mitigated** state; RR-S1, RR-S2 are removed.
- `mitigations-traceability.md` is updated with the new test file and `file:function` references.

**Code touchpoints:**

- [`src/threatprism/config.py`](../../src/threatprism/config.py) — `Settings`, `validate_runtime()`
- [`src/threatprism/api/app.py`](../../src/threatprism/api/app.py) — startup logging
- `tests/test_ops_safety.py` — new test cases

### Slice B — HTTP DoS Protection

Status: implemented for current POC scope with in-process controls.

Closes: D1 / OT-2 / D2 / OT-3.

**Goal.** Bound the resource cost of any single request and any short request burst, before Pydantic parses the body.

**Required behavior:**

- Add a configurable `MAX_REQUEST_BODY_BYTES` setting (default ~256 KB; deliberately small for SOAR payloads — large fixtures should not flow through the live API).
- Reject oversize requests with HTTP 413 before Pydantic validation.
- Add in-process rate limiting on `POST /cases` (default: 60 requests per minute per source IP, configurable).
- Add a `Semaphore` around `BackgroundTasks` triage submissions to cap concurrent triage runs.
- Document the defaults in `SECURITY.md`'s "Pre-Production Hardening" section as configurable but not optional.

**Acceptance criteria:**

- `tests/test_api_limits.py` covers: (a) 413 on oversize body; (b) 429 on rate-limit exceeded; (c) background task concurrency cap honored.
- `docs/threat-models/stride-threat-model.md` is updated: D1, D2 move to **Mitigated** state; OT-2, OT-3 closed.
- `mitigations-traceability.md` is updated.

**Code touchpoints:**

- [`src/threatprism/api/app.py`](../../src/threatprism/api/app.py) — middleware registration
- [`src/threatprism/config.py`](../../src/threatprism/config.py) — new settings
- no new runtime dependency; in-process limiter is implemented in `src/threatprism/api/app.py`
- `tests/test_api_limits.py` — new test file

### Slice D — Test Gap Closure

Status: implemented.

Closes: OT-6 / OT-LD7 / DI2 (test-side).

**Goal.** Convert two architectural-only mitigations into test-enforced mitigations so a future regression cannot silently break them.

**Required behavior:**

- Add `tests/test_token_vault_isolation.py`: walks every API response shape and every SQLite blob, asserts no `tp_<type>_<n>` token-to-raw-value mapping is present in any serialized output.
- Add `tests/test_stage1_no_rehydration.py`: asserts that for every `SanitizationRecord` produced by `safeguard_value()`, `rehydration_allowed == False` and `role_rehydration_allowed[role] == False` for every role.

**Acceptance criteria:**

- Both tests pass in the current codebase (they should — these are guardrail-confirmation tests, not bug fixes).
- A deliberate regression test confirms each test fails when the invariant is broken.
- `docs/threat-models/healthcare-data-threat-model.md` and `stride-threat-model.md` are updated: DI2 moves to **Mitigated + tested**; OT-6, OT-LD7 closed.

**Code touchpoints:**

- `tests/test_token_vault_isolation.py` — new
- `tests/test_stage1_no_rehydration.py` — new
- No application code changes.

### Slice E — Dependency Hardening

Status: implemented for current POC scope.

Closes: L6 / RR-L2 / OT-L6.

**Goal.** Comply with the user's global rule against unpinned dependencies and add automated advisory tracking.

**Required behavior:**

- Update `requirements.txt` to use exact-pin (`==`) for every direct dependency. Generate a `requirements-lock.txt` (via `pip-compile` or `pip freeze`) for full transitive pinning.
- Add `pip-audit` invocation to `tools/validate-threatprism.ps1` (advisory-only initially; CI-blocking once baseline is clean).
- Add a `requirements-dev.txt` separation if helpful for test-only dependencies.
- Document the dependency-update process in `docs/CONTRIBUTING.md` (new file or appended to existing).

**Acceptance criteria:**

- `pip install -r requirements-lock.txt` produces a reproducible install.
- `pip-audit` runs cleanly against the current dep set, OR known advisories are documented in `requirements-lock.txt` with justification.
- `docs/threat-models/llm-agent-threat-model.md` is updated: L6 moves to **Mitigated**; RR-L2, OT-L6 closed.

**Code touchpoints:**

- `requirements.txt`, `requirements-lock.txt` (new)
- `tools/validate-threatprism.ps1` — add audit step
- `docs/CONTRIBUTING.md` — new or updated

### Slice F — Pattern Refresh Process

Status: implemented for current POC scope.

Closes: OT-5 / RR-LD3 / OT-LD3.

**Goal.** Move `PROHIBITED_PATTERNS` ([`policy.py:8`](../../src/threatprism/guardrails/policy.py)) and the healthcare detector rule lists ([`healthcare.py:107-216`](../../src/threatprism/guardrails/healthcare.py)) from hand-curated lists into a process-backed catalog with regression fixtures and a scheduled review.

**Required behavior:**

- Add `docs/runbooks/PATTERN_REFRESH.md` describing the quarterly review process: (a) walk recent eval failures, (b) walk recent LLM provider research for new overclaim phrasings, (c) walk recent PHI/PII detector research, (d) propose pattern additions, (e) add regression fixtures before adding patterns.
- Add `tests/test_overclaim_regression.py` with a curated fixture catalog of overclaim phrasings — one fixture per `PROHIBITED_PATTERNS` regex. Adding a new pattern requires adding fixtures first.
- Add equivalent `tests/test_phi_detector_coverage.py` for the healthcare detectors.
- Add an entry to `docs/WORKING_CHECKLIST.md` for the next quarterly review date.

**Acceptance criteria:**

- The runbook is reviewed and the first quarterly review date is scheduled.
- The two regression test files cover every current pattern, one fixture per pattern at minimum.
- `docs/threat-models/stride-threat-model.md`, `llm-agent-threat-model.md`, and `healthcare-data-threat-model.md` are updated: OT-5, RR-LD3, OT-LD3 close; T3, NC1, L13, DI1 reference the new test files in the traceability matrix.

**Code touchpoints:**

- `docs/runbooks/PATTERN_REFRESH.md` — new
- `tests/test_overclaim_regression.py` — new
- `tests/test_phi_detector_coverage.py` — new
- `docs/WORKING_CHECKLIST.md` — append review schedule

### Slice G — Quarantine Enforcement

Status: implemented in this workspace.

Closes: OT-L5. Narrows RR-L1 to semantic prompt-injection bypass that the pattern firewall does not detect.

**Goal.** Make the prompt firewall's `quarantined=True` signal actually halt triage in the service layer, not just be recorded as a `SanitizationRecord`.

**Implemented behavior:**

- `_prepare_case_for_model()` at [`cases/service.py:453`](../../src/threatprism/cases/service.py) returns `SanitizationRecord` entries with `operation == "quarantine"` for detected quarantine patterns.
- When any quarantine record is present, `run_triage()` sets `triage_status = blocked_by_guardrail`, appends a `triage_blocked_by_prompt_firewall` audit event, and skips the provider call entirely.
- The blocking signal surfaces in `/cases/{case_id}/triage-report` with a message identifying the firewall as the blocker, not as invalid model output.

**Acceptance coverage:**

- `tests/test_quarantine_enforcement.py` submits a case with a quarantine-triggering prompt-injection payload, verifies triage is blocked before provider call, and verifies the audit trail names the firewall.
- The deterministic demo provider is replaced in this test with a counter-based mock that records whether `generate_report` was called; the test asserts it was not called when quarantine fires.
- `docs/threat-models/llm-agent-threat-model.md` now records OT-L5 as closed and RR-L1 as semantic bypass only.

**Code touchpoints:**

- [`src/threatprism/cases/service.py`](../../src/threatprism/cases/service.py) — `_prepare_case_for_model()`, `run_triage()`
- `tests/test_quarantine_enforcement.py` — new

---

## Gated Treatments

These treatments are **Mitigate** decisions whose implementation is deliberately deferred until a precondition lands. They are not "we'll get to it" — they are scheduled work tied to a triggering feature.

| Gate (precondition) | Treatments triggered | Spec entry point |
|---------------------|----------------------|-------------------|
| Real LLM provider integration | OT-L3 (LLM DoS), OT-L7 (output regurgitation), I4/RR-I4/OT-7 + OT-L11 (semantic firewall — [spec 32](32_SEMANTIC_PROMPT_INJECTION_LAYER.md), `Llama-Prompt-Guard-2-86M`) | Spec 32 authored (design-only); build gated on provider work |
| Non-demo dataset onboarding | OT-L10 (corpus provenance: manifest signing, CI license/PII scan gate, integrity verification) | Per [LLM threat model "Before Non-Demo Dataset Onboarding"](../threat-models/llm-agent-threat-model.md#before-non-demo-dataset-onboarding-addresses-ot-l10) |
| Live JWKS / IdP integration | S4 / OT-9 live-integration residuals after local verifier (JWKS fetch, discovery, production tenant operations) | New spec required before live provider work begins |
| RAG / retrieval layer | OT-L1 (indirect prompt injection) | Per [LLM threat model "Before RAG"](../threat-models/llm-agent-threat-model.md#before-rag--retrieval); **design in [spec 38](38_RGOI_LEARNING_LOOP_AND_TRIAGE_CONTEXT.md)** (re-open this Avoid before building) |
| Memory / write-back layer | OT-L8 (memory schema, approval, scoping) | Per [LLM threat model "Before Memory"](../threat-models/llm-agent-threat-model.md#before-memory--write-back); **design in [spec 38](38_RGOI_LEARNING_LOOP_AND_TRIAGE_CONTEXT.md)** (re-open this Avoid before building) |
| Tool / plugin / function-calling | OT-L4 (allowlist, validation, approval) | Per [LLM threat model "Before Tools"](../threat-models/llm-agent-threat-model.md#before-tool--plugin--function-calling) |
| Multi-tenancy | OT-L9 (tenant scoping) | Per [LLM threat model "Before Multi-Tenancy"](../threat-models/llm-agent-threat-model.md#before-multi-tenancy) |
| Fine-tuning pipeline | L4 / OT-L2 (training curation) | New spec required before any training pipeline |
| Non-demo data (any kind) | OT-1, OT-8, RR-R1 (audit integrity), OT-LD2/RR-LD1 (hash salting) | Combined into a "Production Persistence Hardening" spec |
| Real PHI handling | OT-LD1 (HIPAA compliance), OT-LD6 (breach notification), all "non-demo data" gates above | Explicit project-scope decision required before any work; current treatment is **Avoid** |

Gating is not deferral. The treatment decision is committed now; only the implementation timing is gated.

---

## Accepted Risks

Risks the project owner formally accepts at the current scope. Each requires an owner signature before the acceptance is binding.

| ID | Risk | Justification | Owner | Date | Re-evaluate when |
|----|------|---------------|-------|------|-------------------|
| ID2 | Token shape leaks detector class (e.g., `[POTENTIAL_PHI:MRN:phi_0001]`) | Intentional design — analysts need to know what type of sensitive data was tokenized to make triage decisions | Project owner (POC) | 2026-05-24 | A user-facing surface (dashboard) is added where the token shape would be visible to non-analyst roles |
| DT1 | `potential_sensitive_data_exposure` flag visible in queue/metrics responses | Intentional design — operational signal for `/queues/healthcare-review` queue | Project owner (POC) | 2026-05-24 | A non-trusted consumer of the metrics endpoint is added |
| RR-LD1 (demo-scope only) | `raw_value_hash` is unsalted SHA-256 | Acceptable for fake demo data — known plaintext attacks have no value against synthetic IDs. Gated mitigation required before non-demo data | Project owner (POC) | 2026-05-24 | First non-demo data is processed |
| RR-LD2 (current SOAR sources) | Role-view masking is regex-based; novel formats may leak | Current `SECURITY_TELEMETRY_PATTERNS` covers all current SOAR adapter outputs. New SOAR sources trigger pattern review | Project owner (POC) | 2026-05-24 | A new SOAR adapter is added or an existing one starts producing new identifier formats |
| NC3 / OT-LD5 (current minimum-necessary policy) | Per-role minimum-necessary policy may not match operator workflow | Acceptable for demo scope; requires operator-workflow review session, not a code change, before any non-demo deployment | Project owner (POC) | 2026-05-24 | First deployment with a real operator workflow |

**2026-05-26 dashboard re-evaluation.** ID2 was re-evaluated after the local
dashboard became a user-facing surface. The risk remains accepted for fake-data
POC scope because role-safe views expose token classes as exposure metadata
without raw values, and dashboard hardening does not broaden role policy. The
risk must be re-opened before non-demo deployment, production identity, real
PHI, or any external dashboard consumer.

**Acceptance signature format.** When an owner accepts a risk, they edit the row:

- `Owner` → name (e.g., `M. Williams`)
- `Date` → ISO date of acceptance
- `Re-evaluate when` may be updated to add specific trigger conditions

The acceptance becomes binding at that point. Any subsequent change to the conditions surfaced in "Re-evaluate when" requires re-opening the acceptance.

---

## Avoid Decisions

Surface-scope choices that eliminate threats rather than mitigating them. These are project-scope decisions, more permanent than acceptances.

| ID | Threat | Avoid Decision | Documented In |
|----|--------|----------------|----------------|
| NC2 / OT-LD1 | System not HIPAA-compliant for real PHI | ThreatPrism does not process real PHI. Project scope is fake demo data only. HIPAA compliance is out of scope until and unless a future project pivot is approved | `README.md`, `SECURITY.md`, `docs/specs/01_PRODUCT_REQUIREMENTS.md` (treatment slice must update all three) |
| L4 / OT-L2 | Training data poisoning | ThreatPrism does not fine-tune the LLM. Case data is not fed back into training. If a fine-tuning pipeline is ever added, this becomes a Gated Mitigation | `SECURITY.md`, `docs/threat-models/llm-agent-threat-model.md` |
| L8 / OT-L4 | Insecure tool/plugin design | ThreatPrism does not expose tools/functions/plugins to the LLM. All actions are simulated. If tool-calling is ever added, this becomes a Gated Mitigation | `SECURITY.md`, `docs/threat-models/llm-agent-threat-model.md` |
| OT-L8 | Memory / write-back | ThreatPrism does not have a memory or write-back layer. If one is ever added, this becomes a Gated Mitigation | `SECURITY.md`, `docs/threat-models/llm-agent-threat-model.md` |
| OT-L9 | Cross-tenant isolation | ThreatPrism is single-org. If multi-tenancy is ever added, this becomes a Gated Mitigation | `SECURITY.md`, `docs/threat-models/llm-agent-threat-model.md` |
| L11 | Model theft | ThreatPrism does not expose a model API. N/A while this holds | `docs/threat-models/llm-agent-threat-model.md` |

**Avoid is the strongest treatment when honest.** Mitigating a threat that does not apply costs more than just declaring the scope and enforcing it. The discipline is to *enforce* the avoid decision — any spec that proposes adding one of these surfaces must trigger this treatment spec to re-open and the corresponding gated mitigation to schedule.

---

## Transfer Decisions

Risks where another party is contractually or operationally better positioned to control the risk.

| ID | Risk | Transferred To | Conditions |
|----|------|----------------|-------------|
| TLS termination | Plaintext HTTP risk if no TLS terminator deployed | Operator (reverse proxy assumption) | `SECURITY.md` must document the assumption; production-readiness checklist must verify it |
| Host-level access controls | OS-level access to SQLite file | Operator (host hardening assumption) | Same as above |
| Real LLM provider behavior | Provider-side training-data leakage, model availability, latency SLAs | LLM provider (contractual SLA + BAA if PHI is ever in scope) | Gated — only applies when real LLM lands; treatment spec for provider integration must include contract review |

Transfer is not abdication. The transferred control must be explicitly named and the transfer condition must be enforceable.

---

## Treatment Register Update Process

Treatments age. New threats emerge. This register stays current via the following process:

### When a slice lands

1. Update the affected lens file(s) in [`docs/threat-models/`](../threat-models/README.md): change `State` for the closed threats from Partial/Unmitigated to Mitigated; remove closed residual risks.
2. Update [`mitigations-traceability.md`](../threat-models/mitigations-traceability.md) with new `file:function` and test references.
3. Update this spec's Treatment Decision Matrix: change the proposed treatment row from `TODO:` owner to the actual owner who landed the slice, with the slice's commit/PR reference.
4. Log the closure in the slice's own spec acceptance criteria.

### When a new threat is identified

1. Add the threat to the appropriate lens file with full v0.2-format detail (severity, mitigation pointer or open status, residual risk if applicable).
2. Add a row to this spec's Treatment Decision Matrix with a proposed treatment and `TODO:` owner.
3. Surface the new row in the next project review.

### When an acceptance condition triggers

If an Accepted Risk row's "Re-evaluate when" condition fires (e.g., new SOAR adapter added, dashboard work begins):

1. The accepting owner is notified.
2. The acceptance is formally re-evaluated — either re-confirmed with updated justification, or moved to Mitigate with a new slice scheduled.
3. The threat model lens file is updated to reflect the new state.

### When an Avoid decision is at risk

If a feature is proposed that would create one of the avoided surfaces (e.g., adding memory, tools, multi-tenancy, real PHI processing):

1. This spec must be re-opened.
2. The Avoid decision must be either upheld (feature is out of scope) or converted to a Gated Mitigation with a new spec for the underlying control work.
3. The corresponding gate's spec must land before the feature itself.

### Quarterly review

Every quarter, a scheduled review walks:

- The Open Threats and Residual Risk Registers in each lens file
- The Treatment Decision Matrix in this spec
- The `docs/runbooks/PATTERN_REFRESH.md` review (Slice F)
- Any Accepted Risks whose Re-evaluate conditions may have fired

The quarterly review either closes items (slice landed), updates them (new info), or escalates them (treatment proposal needs to change).

---

## Acceptance Criteria For This Spec

This spec is itself a deliverable. It is considered complete and binding when:

- Every row in the Treatment Decision Matrix has an `Owner` field populated (no `TODO:` markers). **Complete for POC owner pass.**
- Every Accepted Risk row has an `Owner` and `Date` signed. **Complete for POC owner pass.**
- Each scheduled implementation slice has either landed or is explicitly gated. **Slices D, A, B, F, and E landed for POC scope on 2026-05-24.**
- Each Avoid decision is reflected in the listed documents (`README.md`, `SECURITY.md`, applicable specs).
- The Treatment Register Update Process is referenced from `docs/WORKING_CHECKLIST.md` so quarterly review is on the working schedule.

This spec is now a **POC treatment register**: owner decisions are binding for current fake-data scope, while MVP/production/enterprise triggers require re-opening the relevant gated decisions.

---

## Out Of Scope

This spec does not:

- Implement MVP, production, enterprise, real-LLM, RAG, memory, tool-calling, multi-tenant, non-demo data, or real-PHI controls.
- Override or replace the v0.2 threat model pack. The pack is the source of truth for threats and their mitigations; this spec is the source of truth for treatment decisions.
- Resolve threats by re-classifying severity. A threat does not become Low because the fix is hard.
- Make external compliance, legal, HIPAA, HITRUST, or enterprise production-readiness decisions. The recorded owner pass is a POC governance decision only.

---

## Real-LLM, Analyst & Local-Model Gate Opening (2026-06-01)

The project owner authorized opening the previously-gated real-LLM preconditions.
Three external/model trust boundaries are now **active** (no longer demo-only):

1. **Anthropic Claude** — real triage brain (`ClaudeTriageProvider`,
   `llm/providers.py`, `LLM_PROVIDER=anthropic_claude`).
2. **OpenAI** — independent baseline analyst for backtests (`MockAnalyst`,
   `llm/mock_analyst.py`).
3. **Local Prompt Guard 2** — semantic prompt-injection firewall
   (`guardrails/semantic_firewall.py`, `SEMANTIC_FIREWALL_ENABLED=true`).

Opening the gate **re-opened** the gated rows L1/RR-L1, L5/OT-L3, and L7/OT-L7
(updated in the tables above). It does **not** open: tool/function-calling (L8),
memory write-back (OT-L8), production multi-tenancy (OT-L9), fine-tuning (L4),
non-demo data, or real PHI — those remain **Avoid/Gated**.

### New trust-boundary threats and treatments

| ID | Threat | Treatment | Mitigation (code + test) | Owner |
|----|--------|-----------|--------------------------|-------|
| OT-L10 | **Data egress to OpenAI (analyst).** Case + report sent to a third party could leak raw PHI/PII/secrets. | **Mitigated** | The analyst grades the **stored, Stage-1-tokenized** case (`run_backtest` → `service.get_case()`, `demo/backtest.py:96`); Stage-1 tokens (`[POTENTIAL_PHI:...]`, `[SECRET:...]`) are never rehydrated. Guarded by `tests/test_analyst_egress.py`. Spend-capped + metered + fail-closed (specs 35/36). | Project owner, 2026-06-01 |
| OT-L11a | **Data egress to Anthropic (triage).** Raw sensitive data could reach the triage provider. | **Mitigated** (covered by I1) | Stage-1 tokenization runs before `_prepare_case_for_model()`; the provider never sees raw PHI/PII/secrets. Now applies to a *live* provider. | Project owner, 2026-06-01 |
| OT-L11b | **Local model supply chain.** A tampered/poisoned Prompt Guard 2 weight set could mis-score injection. | **Mitigated** | Model **revision pinned** in `.env.example` to verified SHA `a8ded8e697ce7c355e395a0df51f94adb4a2fd27` (HF main as of 2025-04-29); a moving tag is rejected at enable; loaded locally (no per-request network). | Project owner, 2026-06-01 |
| OT-L11c | **Probabilistic firewall trusted as a gate.** A semantic detector could be evaded or could over-block. | **Mitigated by design** | Detector-not-gate (Lesson 30): the deterministic prompt firewall + Slice G quarantine enforcement remain the hard gate; the semantic layer only adds review/quarantine *bands*. Fails toward the deterministic layers. | Project owner, 2026-06-01 |

### Residual risks accepted (owner sign-off)

- **RR-L1 (novel semantic prompt-injection bypass):** a payload neither the
  deterministic firewall nor Prompt Guard 2 detects could still reach the live
  triage model. Downstream output policy + evidence validation + action safety
  remain. Accepted for POC live-eval scope. `Accepted by: Project owner, 2026-06-01`.
- **L7 residual (no output entity-extraction):** the output scan catches known
  credential *shapes* (shared catalog) but not arbitrary data regurgitation.
  Accepted for POC scope. `Accepted by: Project owner, 2026-06-01`.
- **Live spend:** real paid calls on both Anthropic and OpenAI. Bounded by
  `llm_max_cost_usd_per_run` (default $5, fail-closed). Owner confirmed cost
  policy is in place. `Accepted by: Project owner, 2026-06-01`.

### Pre-flight before any paid run (owner)

- Verify `anthropic` and `openai` SDK **usage-attribute names** against the pinned
  versions (cost accounting depends on them) — flagged in `providers.py` /
  `mock_analyst.py` VERIFY comments.
- Run against the **curated/synthetic SOC dataset only** — never real workplace
  data (AGENTS.md hard rule).
- Confirm `SEMANTIC_FIREWALL_MODEL_REVISION` is pinned to a verified revision.

## Review Log

| Date | Reviewer | Verdict | Notes |
|------|----------|---------|-------|
| 2026-06-01 | Claude (owner-authorized) | Real-LLM gate opened | Owner authorized live Anthropic triage, OpenAI analyst, and local Prompt Guard 2. Re-opened L1/RR-L1, L5/OT-L3, L7/OT-L7 with current-mitigation evidence; added new-boundary threats OT-L10 (analyst egress, guarded by `tests/test_analyst_egress.py`), OT-L11a/b/c. Recorded residual-risk acceptances with owner-signature placeholders and a pre-flight checklist. Tools/function-calling, memory write-back, multi-tenancy, fine-tuning, non-demo data, and real PHI remain Avoid/Gated. |
| 2026-05-26 | Codex | Production token verifier implementation landed | Added local fake-JWKS `external_oidc` verifier, verified claim-to-role mapping, role-view policy integration, no-network tests, and sanitized audit coverage. Live JWKS fetch and live IdP integration remain gated. |
| 2026-05-26 | Codex | Production token verifier design documented | Added the `external_oidc` verifier contract, S4/OT-9 treatment row, no-network validation requirement, and future test expectations. Superseded by the local implementation row above for fake-JWKS runtime scope. |
| 2026-05-26 | Codex | Production identity readiness implemented | Added static `external_oidc` readiness config checks, unknown auth-mode rejection, incomplete-verifier rejection, and fail-closed protected-route behavior when verification is disabled. |
| 2026-05-26 | Codex | Curated fixture promotion implemented | Added one tracked fake SOC fixture through an explicit manifest review gate. Generated fixture output remains ignored and is not auto-scanned; no raw datasets, downloads, live providers, RAG, memory write-back, or real data were added. |
| 2026-05-26 | Codex | External research provider deferred | Documented Exa.ai or equivalent public-web research as an optional future enhancement only. It is not needed for the current build and must not add live calls, live RAG, CSI/RGOI memory write-back, automatic fixture promotion, trust mutation, or source-of-truth changes without reopening gated treatments. |
| 2026-05-26 | Codex | Production dashboard hardening implemented | Added local dashboard CSP/framing/referrer/permission headers, same-origin request enforcement, request timeouts, keyboard persona navigation markers, and tests. Re-evaluated accepted risk ID2 for the local dashboard; production deployment, production identity, non-demo data, and real PHI remain gated. |
| 2026-05-26 | Codex | CSI/RGOI read-only foundation implemented | Added governed cognition without write-back, live RAG, trust mutation, suppressions, remediation, production tenancy, or real data. Live RAG, memory write-back, and production multi-tenancy remain gated. |
| 2026-05-24 | Codex | Slices A, B, D, E, and F implemented | Followed the owner-approved POC treatment order after Slice G. Closed POC-scope auth hardening, HTTP resource controls, test-gap closure, pattern refresh process, and dependency hardening. Gated MVP/production/enterprise controls remain out of scope. |
| 2026-05-24 | Codex | POC owner decision pass recorded | Under user direction, replaced owner-decision placeholders with POC owner decisions. Scheduled near-term mitigations in order: Slice D, Slice A, Slice B, Slice F, Slice E. Kept MVP/production/enterprise, real LLM, RAG, memory, multi-tenancy, non-demo data, and real PHI risks gated. |
| 2026-05-24 | Codex | Slice G implemented; original register draft state | Implemented quarantine enforcement and tests, updated LLM lens and traceability. This row records the pre-owner-pass state and is superseded by the later POC owner pass. |
| 2026-05-24 | Claude (auto-generated, awaiting human review) | Draft proposal — needs owner decisions | Proposed treatments for 25 open threats and 10 residual risks from the v0.2 pack. Grouped 7 implementation slices (A, B, D, E, F, G; "C" intentionally skipped as audit integrity is gated to non-demo data). Listed 7 gated treatments tied to feature preconditions. Drafted 6 Accepted Risks for owner sign-off. Recorded 6 Avoid decisions reflecting current project scope. Every `Owner` field is `TODO:` — this spec is a proposal, not a commitment, until those are signed |
