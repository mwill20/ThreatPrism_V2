# Healthcare Data Threat Model

**Version:** 2026-05-24 (v0.2 refresh)
**Status:** POC owner decision pass recorded; Slices D and F reconciled
**Framework:** LINDDUN
**Why this framework:** ThreatPrism processes data that becomes PHI when combined with healthcare context; LINDDUN's seven privacy threat categories (Linkability, Identifiability, Non-repudiation, Detectability, Disclosure, Unawareness, Non-compliance) catch privacy-specific threats that STRIDE alone misses.

For traditional STRIDE risks, see [`stride-threat-model.md`](stride-threat-model.md). For LLM-specific risks, see [`llm-agent-threat-model.md`](llm-agent-threat-model.md). For threat-to-test mapping, see [`mitigations-traceability.md`](mitigations-traceability.md).

---

## Healthcare Boundary Statement

**ThreatPrism does not claim to be:**
- HIPAA compliant
- HITRUST certified
- A legal de-identification engine
- A healthcare compliance audit tool

ThreatPrism is a SOC triage automation backend that processes security telemetry. **Healthcare data should not be in the inbound SOAR payload.** When it is — accidentally or maliciously — the Stage 1 healthcare safeguard tokenizes it before it can reach the LLM, the analyst, the manager, or downstream consumers.

This model assumes:
- The operator does not deliberately send PHI to ThreatPrism
- SOAR sources may *accidentally* include identifiers that become PHI when paired with healthcare context (an email address in a case about a patient portal incident is PHI; the same email in a SOC case about an exposed server is not)
- The healthcare safeguard layer is the last line of defense, not the only line

---

## Severity Rubric

Severity is `Likelihood × Impact`:

| | Impact: Low | Impact: Med | Impact: High |
|---|---|---|---|
| **Likelihood: Low** | Low | Low | Medium |
| **Likelihood: Med** | Low | Medium | High |
| **Likelihood: High** | Medium | High | **Critical** |

For PHI/PII threats, **regulated-data exposure is always Impact: High** regardless of volume.

See [`stride-threat-model.md`](stride-threat-model.md#severity-rubric) for full definitions.

---

## LINDDUN — Threat Enumeration

| # | LINDDUN Category | Threat | Likelihood | Impact | Severity | Mitigation — `file:function` | State |
|---|------------------|--------|------------|--------|----------|------------------------------|-------|
| LD1 | **Linkability** | Same patient appears in multiple cases; tokenized identifiers allow analyst to correlate cases. | Medium | High | **High** | `HealthcareTokenVault` is per-case at [healthcare.py:47](../../src/threatprism/guardrails/healthcare.py); `safeguard_value(..., case_id=case.case_id)` at [cases/service.py:100](../../src/threatprism/cases/service.py) creates a fresh vault per case — tokens do not carry across cases. | Mitigated |
| LD2 | **Linkability** | `raw_value_hash` (SHA-256, unsalted) on each `SanitizationRecord` allows correlation if an attacker knows candidate raw values. | Low | High | **Medium** | `raw_value_hash` at [healthcare.py:81](../../src/threatprism/guardrails/healthcare.py) is stored but never returned via API; audit views expose hashes for forensic purposes. | Partial — see RR-LD1 |
| ID1 | **Identifiability** | Tokenized record is re-identified via hash brute-force, dictionary attack, or known-plaintext attack against `raw_value_hash`. | Low | High | **Medium** | Same as LD2; tokens themselves contain no information about raw value beyond detector type and counter. | Partial — see RR-LD1 |
| ID2 | **Identifiability** | `[POTENTIAL_PHI:DETECTOR:phi_NNNN]` token shape leaks the detector class (MRN vs. SSN vs. DOB), giving an attacker structural information. | High | Low | **Medium** | Intentional design choice — analysts/auditors need to know *what type* of sensitive data was tokenized for triage and review. Tradeoff documented. | Accepted (design tradeoff) |
| NR1 | **Non-repudiation** (privacy sense) | Subject cannot deny being processed by ThreatPrism. | N/A (subject doesn't interact directly) | N/A | N/A | Not applicable — subjects do not interact with ThreatPrism. | N/A |
| DT1 | **Detectability** | An observer with API access can detect that *some* PHI was present in a case via `source_metadata.healthcare_safeguard.potential_sensitive_data_exposure` flag. | High | Low | **Medium** | Flag is intentional — operational signal for `/queues/healthcare-review`. Visible to manager/GRC/legal/audit roles by design ([cases/service.py:684](../../src/threatprism/cases/service.py)). | Accepted (design tradeoff) |
| DT2 | **Detectability** | Existence of a case for a given subject is detectable to anyone with read access on that case. | Medium | Medium | **Medium** | Role-based access via `ROLE_VIEW_POLICY` ([auth/demo.py:24](../../src/threatprism/auth/demo.py)); audit events on every read at [auth/demo.py:243](../../src/threatprism/auth/demo.py). | Mitigated by access control |
| DI1 | **Disclosure of Information** — PHI/PII to LLM | Raw PHI/PII reaches the LLM provider via case text. | High | High | **Critical** | Stage 1: `safeguard_value()` at [healthcare.py:219](../../src/threatprism/guardrails/healthcare.py); 7 PHI rules at [healthcare.py:122-171](../../src/threatprism/guardrails/healthcare.py); 3 PII rules at [healthcare.py:197-216](../../src/threatprism/guardrails/healthcare.py); 3 context-aware identifier rules at [healthcare.py:173-195](../../src/threatprism/guardrails/healthcare.py); pattern coverage in `tests/test_phi_detector_coverage.py`. | Mitigated + process-backed |
| DI2 | **Disclosure of Information** — Token rehydration | Stage 1 PHI/PII/secret tokens are accidentally rehydrated, exposing raw values. | Low | High | **Medium** | `HealthcareTokenVault.token_for()` at [healthcare.py:53](../../src/threatprism/guardrails/healthcare.py) sets `rehydration_allowed=False` ([healthcare.py:81](../../src/threatprism/guardrails/healthcare.py)) AND populates `role_rehydration_allowed` with every role set to `False` ([healthcare.py:86-93](../../src/threatprism/guardrails/healthcare.py)); `tests/test_stage1_no_rehydration.py` asserts the invariant. | Mitigated + tested |
| DI3 | **Disclosure of Information** — Cross-role leakage | Manager/GRC/legal/audit role accesses analyst-only security telemetry (IPs, URLs, emails, hashes). | Medium | Medium | **Medium** | `render_role_view()` at [views.py:32](../../src/threatprism/guardrails/views.py); `_render_text()` at [views.py:67](../../src/threatprism/guardrails/views.py) — only `analyst` and `engineer` see raw telemetry; all other roles get `[SECURITY_TELEMETRY:TYPE:masked]`. | Mitigated |
| DI4 | **Disclosure of Information** — Audit event contains raw PHI | An audit event accidentally captures raw PHI/PII or token vault mapping in its `metadata` field. | Low | High | **Medium** | Audit event metadata is constructed from sanitized data (post-safeguard); authorization audit metadata uses `_request_metadata_hash()` SHA-256 ([auth/demo.py:263](../../src/threatprism/auth/demo.py)) not raw credentials; `SafeAuditEvent` projection in `cases/read_models.py` strips additional fields for audit-view consumers. | Mitigated |
| DI5 | **Disclosure of Information** — Eval artifact leak | Eval result artifact under `.eval_runs/` contains raw PHI/PII from fixture payload. | Medium | High | **High** | `_safe_preview()` at [evals/runner.py:262](../../src/threatprism/evals/runner.py) runs every fixture payload through `sanitize_value` → `safeguard_value` → `render_role_view(role="audit_debug")` before writing. `_strip_eval_metadata()` at [evals/runner.py:276](../../src/threatprism/evals/runner.py) drops 16 blocked keys including `password`, `api_key`, `token`, `vault_mappings`. | Mitigated |
| DI6 | **Disclosure of Information** — Read model / metrics leak | `/metrics` or `/cases/read-model` exposes aggregated PHI counts in a way that allows inference. | Low | Medium | **Low** | Metrics only count tokenization summary fields (`potential_sensitive_data_exposure`, `secret_exposure_detected`) at [cases/service.py:247-250](../../src/threatprism/cases/service.py) — boolean flags, not values. Eval category `metrics_read_model_leakage` at [evals/runner.py:179](../../src/threatprism/evals/runner.py) tests this. | Mitigated |
| UA1 | **Unawareness** | Data subject is unaware their data is being processed by ThreatPrism. | N/A | N/A | N/A | Not applicable — ThreatPrism processes SOAR data; subject relationship is upstream with the data controller (operator). The operator's own privacy notice governs subject awareness. | N/A (operator responsibility) |
| NC1 | **Non-compliance** | ThreatPrism's output makes false compliance/certification claims. | High | High | **Critical** | `PROHIBITED_PATTERNS` at [policy.py:13-17](../../src/threatprism/guardrails/policy.py) blocks 5 compliance overclaim patterns; `tests/test_overclaim_regression.py` covers the current pattern catalog; [PATTERN_REFRESH.md](../runbooks/PATTERN_REFRESH.md) schedules periodic review. | Mitigated + process-backed |
| NC2 | **Non-compliance** | ThreatPrism's processing itself violates HIPAA/regulation (data retention, encryption-at-rest, access logs, breach notification readiness). | High | High | **Critical** (for real PHI) | `SECURITY.md` "Pre-Production Hardening Checklist" documents 12 items required before non-demo data; `validate_runtime()` at [config.py:38](../../src/threatprism/config.py) blocks `env=prod` with demo auth. **Not mitigated for actual healthcare deployment.** | Unmitigated — see OT-LD1 |
| NC3 | **Non-compliance** — Minimum necessary | Manager/GRC/legal/audit views receive more data than they need (HIPAA minimum-necessary principle). | Medium | Medium | **Medium** | Role-view masking enforces minimum-necessary at read time via `render_role_view()` ([views.py:32](../../src/threatprism/guardrails/views.py)). `ROLE_VIEW_POLICY` ([auth/demo.py:24-31](../../src/threatprism/auth/demo.py)) restricts which views each effective role can request. | Mitigated |

---

## Two-Stage Tokenization Detail

Understanding the two-stage design is critical for evaluating PHI safety. The threats above assume this structure holds.

### Stage 1 — Healthcare Safeguard (Permanent Tokenization)

- **When:** At case intake via `_apply_healthcare_safeguards()` ([cases/service.py:99](../../src/threatprism/cases/service.py)) — runs *before* `save_case()`.
- **What:** Detects PHI, PII, secrets; replaces with typed tokens like `[POTENTIAL_PHI:MRN:phi_0001]`.
- **Vault:** `HealthcareTokenVault` ([healthcare.py:47](../../src/threatprism/guardrails/healthcare.py)) — per-case, holds the mapping during scan.
- **Persistence:** Records the `SanitizationRecord` (with `raw_value_hash` only) on the case. **The raw-to-token mapping is discarded after the scan returns.** No code path can reverse Stage 1 tokens.
- **Rehydration:** `rehydration_allowed=False` permanently. `role_rehydration_allowed` is all-False for every role.

### Stage 2 — Prompt Firewall + TokenVault (Controlled Rehydration)

- **When:** During triage prep via `_prepare_case_for_model()` ([cases/service.py:453](../../src/threatprism/cases/service.py)) — runs *after* persistence, before LLM call.
- **What:** Tokenizes security telemetry (IPs, URLs, emails, file hashes, secret-shape strings) into `tp_ip_001`, `tp_url_002`, etc.
- **Vault:** `TokenVault` ([tokenization.py:23](../../src/threatprism/guardrails/tokenization.py)) — per-triage-execution, in-memory only.
- **Rehydration:** `REHYDRATABLE_TYPES` ([tokenization.py:19](../../src/threatprism/guardrails/tokenization.py)) = `{"email", "ip", "url", "host", "domain", "user", "file_hash"}` — explicitly **excludes** `secret_like`. `_rehydrate_report()` ([cases/service.py:522](../../src/threatprism/cases/service.py)) runs only after the report passes all guardrail checks.

### Why Both Stages

- **Stage 1 protects regulated data permanently** — PHI/PII/secrets never come back, by design. The LLM never sees them. Analysts never see them. The audit log only has hashes.
- **Stage 2 protects telemetry from the LLM but allows analyst utility** — analysts need to see the actual IP/URL/email after triage so they can investigate. Rehydration is gated on the report passing all four guardrail layers.
- **Secret tokens are in both vaults' deny-list** — Stage 1 catches them at intake (permanent); Stage 2's `display_value()` ([tokenization.py:52](../../src/threatprism/guardrails/tokenization.py)) returns `[REDACTED_SECRET]` for `secret_like` even on the rehydration path.

---

## Minimum-Necessary View Matrix

| View Role | Sees Raw Security Telemetry | Sees Stage 1 Tokens | Sees Stage 2 Telemetry (Post-Rehydration) | Sees Audit Hashes |
|-----------|------------------------------|---------------------|-------------------------------------------|--------------------|
| `ai` (model) | No (Stage 2 tokens only) | Yes (typed tokens visible, never rehydrated) | No (sees tokens, not values) | No |
| `analyst` | Yes | Yes (typed tokens visible, never rehydrated) | Yes | Limited |
| `engineer` | Yes | Yes (typed tokens visible, never rehydrated) | Yes | Yes (via `audit_debug` per `ROLE_VIEW_POLICY`) |
| `manager_grc` | **No** (`[SECURITY_TELEMETRY:masked]`) | Yes (typed tokens visible, never rehydrated) | **No** (masked) | No |
| `legal_privacy` | **No** (masked) | Yes (typed tokens — privacy team needs to know exposure) | **No** (masked) | Yes (via `audit_debug`) |
| `audit_debug` | **No** (masked) | Yes (typed tokens) | **No** (masked) | Yes |

Enforcement: `_render_text()` at [views.py:67-80](../../src/threatprism/guardrails/views.py) returns text unchanged only for `{"analyst", "engineer"}`; all other roles get `SECURITY_TELEMETRY_PATTERNS` regex masking.

---

## Compliance Language Boundary

Documented in [healthcare-data-threat-model.md (v0.1)](../threat-models/healthcare-data-threat-model.md) — preserved here.

**Allowed wording:**
- "HIPAA Security Rule safeguard theme"
- "HITRUST-aligned category mapping"
- "Evidence alignment"
- "Evidence-to-control traceability"
- "Requires human review"

**Blocked wording (enforced by `PROHIBITED_PATTERNS`):**
- "HIPAA compliant" / "HIPAA certified"
- "HITRUST compliant" / "HITRUST certified"
- "Control satisfied" / "Certification-ready" / "Audit-ready"
- "Evidence proves compliance"

---

## Residual Risk Register

| ID | Threat | Residual Risk | Accepted By | Justification |
|----|--------|---------------|-------------|---------------|
| RR-LD1 | LD2/ID1 — `raw_value_hash` is unsalted SHA-256 | An attacker who knows candidate raw values can brute-force matches against stored hashes. | Project owner (POC), 2026-05-24 | Accepted for fake demo data only. Add per-record salt or HMAC with a service-side key before non-demo data. Tracked as OT-LD2. |
| RR-LD2 | DI3 — Role-view masking is regex-based | Novel telemetry formats not matching `SECURITY_TELEMETRY_PATTERNS` ([views.py:13-18](../../src/threatprism/guardrails/views.py)) leak unmasked to non-analyst roles. | Project owner (POC), 2026-05-24 | Accepted for current SOAR sources. Expand patterns as new sources are added; consider type-aware structured masking. |

---

## Open Threats and TODOs

| ID | Threat | Severity | Owner | Target Date |
|----|--------|----------|-------|-------------|
| OT-LD1 | NC2 — ThreatPrism processing itself is not HIPAA-compliant (no encryption at rest, no production access controls, no breach notification workflow, no BAA process) | Critical (for real PHI) | Project owner (POC), 2026-05-24 | Before any non-demo healthcare data |
| OT-LD2 | RR-LD1 — Replace unsalted SHA-256 with per-record salt or HMAC | Medium | Project owner (POC), 2026-05-24 | Before any non-demo data |
| OT-LD5 | NC3 — Per-role minimum-necessary policy should be reviewed against the operator's actual workflow (e.g., does GRC really need to see `triage_status`?) | Medium | Project owner (POC), 2026-05-24 | Before any non-demo deployment |
| OT-LD6 | NC2 — No breach-notification workflow for the case where ThreatPrism's own data is compromised | High | Project owner (POC), 2026-05-24 | Before any non-demo data |

---

## Pre-Production Hardening for Real PHI

ThreatPrism cannot handle real PHI without all of the following:

- [ ] Business Associate Agreement (BAA) workflow with the data controller
- [ ] Encryption at rest for SQLite (or migration to encrypted PostgreSQL)
- [ ] Encryption in transit enforced (TLS terminator, no plaintext fallback)
- [ ] Production IdP integration (OAuth/OIDC/Entra ID)
- [ ] Tamper-evident audit log — see STRIDE OT-1, OT-8
- [ ] Retention policy and automated deletion
- [ ] Breach-notification workflow and runbook
- [ ] Access logs separated from application logs
- [ ] Per-record salt or HMAC on `raw_value_hash` (OT-LD2)
- [ ] External privacy review of the LINDDUN model (this document)
- [ ] External security review of the STRIDE model
- [ ] Pen test against the deployed instance

---

## Out-of-Scope Improvements

- **De-identification certification** (e.g., HIPAA Safe Harbor or Expert Determination) — explicitly out of scope; ThreatPrism is not a de-identification engine
- **Re-identification testing** with synthetic linked records — useful for validating LD2/ID1 mitigations; defer until real PHI is in scope
- **Differential privacy** on aggregated metrics — defensive overkill for the current Boolean flag design
- **Subject access request (SAR) workflow** — operator responsibility under GDPR/CCPA, not ThreatPrism's

---

## Review Log

| Date | Reviewer | Verdict | Notes |
|------|----------|---------|-------|
| 2026-05-24 | Codex | Slices D and F reconciled | Added dedicated Stage 1 non-rehydration tests, healthcare detector coverage fixtures, pattern-refresh runbook, and operator-facing semantics for `potential_sensitive_data_exposure`. Closed OT-LD3, OT-LD4, OT-LD7, and RR-LD3 for POC scope. |
| 2026-05-24 | Claude (auto-generated, awaiting human review) | Draft — needs review | Refreshed from v0.1 to v0.2 format. Reframed under LINDDUN. Added explicit walk through all 7 LINDDUN categories with severity ratings. Surfaced 7 open threats (OT-LD1 through OT-LD7) and 3 residual risks. Critical findings: NC2 (system not HIPAA-compliant for real PHI), NC1 (overclaim guard is mitigated but pattern-curated). Notable design strength documented: Two-stage tokenization architecture — Stage 1 tokens are structurally unable to be rehydrated (no carrier from `_apply_healthcare_safeguards` into `_rehydrate_report`). |
