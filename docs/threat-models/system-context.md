# ThreatPrism System Context

**Version:** 2026-05-24 (v0.2 refresh)
**Status:** Draft — awaiting first review under v0.2 format
**Purpose:** Define the assets, users, integrations, trust boundaries, and data flows that the three lens-specific threat models ([STRIDE](stride-threat-model.md), [LLM/ATLAS](llm-agent-threat-model.md), [LINDDUN](healthcare-data-threat-model.md)) analyze.

This file is shared scope and asset context. Threats themselves are enumerated in the lens files. The traceability matrix ([`mitigations-traceability.md`](mitigations-traceability.md)) maps each threat to its code-level mitigation and test.

---

## Framework Selection — Why Three Lenses

ThreatPrism's surface combines traditional API/auth/persistence risks, AI-specific risks, and privacy risks. No single framework covers all three well. The per-component selection:

| Component | Primary Framework | Why | Lens File |
|-----------|-------------------|-----|-----------|
| FastAPI ingress + routes ([api/app.py](../../src/threatprism/api/app.py)) | **STRIDE** | Request/response surface with trust boundary at ingress | [stride-threat-model.md](stride-threat-model.md) |
| Demo auth + role-view authorization ([auth/demo.py](../../src/threatprism/auth/demo.py)) | **STRIDE** | Authentication, authorization, audit are classic STRIDE concerns | [stride-threat-model.md](stride-threat-model.md) |
| Prompt firewall ([guardrails/prompt_firewall.py](../../src/threatprism/guardrails/prompt_firewall.py)) | **OWASP LLM Top 10 (LLM01)** | Prompt injection is an LLM-specific class STRIDE doesn't name | [llm-agent-threat-model.md](llm-agent-threat-model.md) |
| Healthcare safeguard ([guardrails/healthcare.py](../../src/threatprism/guardrails/healthcare.py)) | **LINDDUN** | Privacy threats need privacy framework — Stage 1 tokenization is the PHI/PII boundary | [healthcare-data-threat-model.md](healthcare-data-threat-model.md) |
| Stage 2 tokenization ([guardrails/tokenization.py](../../src/threatprism/guardrails/tokenization.py)) | **STRIDE + LINDDUN** | Information disclosure (STRIDE) + identifiability (LINDDUN) | Both |
| Output policy / evidence / action safety ([guardrails/policy.py](../../src/threatprism/guardrails/policy.py), [guardrails/evidence.py](../../src/threatprism/guardrails/evidence.py)) | **OWASP LLM Top 10 (LLM02, LLM08, LLM09)** | Insecure output handling, excessive agency, overreliance — LLM application concerns | [llm-agent-threat-model.md](llm-agent-threat-model.md) |
| Role-view masking ([guardrails/views.py](../../src/threatprism/guardrails/views.py)) | **STRIDE (I) + LINDDUN (DI, NC3)** | Information disclosure (STRIDE) + minimum-necessary access (LINDDUN) | Both |
| LLM provider ([llm/providers.py](../../src/threatprism/llm/providers.py)) | **MITRE ATLAS + OWASP LLM Top 10** | AI-specific adversary tactics and application risks | [llm-agent-threat-model.md](llm-agent-threat-model.md) |
| SQLite persistence ([persistence/sqlite.py](../../src/threatprism/persistence/sqlite.py)) | **STRIDE** | Standard data-at-rest, tampering, repudiation concerns | [stride-threat-model.md](stride-threat-model.md) |
| Eval harness ([evals/runner.py](../../src/threatprism/evals/runner.py)) | **STRIDE** | Path sandboxing, fixture handling, artifact hygiene | [stride-threat-model.md](stride-threat-model.md) |
| SOAR adapters ([soar/generic.py](../../src/threatprism/soar/generic.py)) | **STRIDE** | Input validation, source provenance | [stride-threat-model.md](stride-threat-model.md) |

**Hybrid by design.** Most components appear in more than one lens file because most threats are not framework-pure. Cross-references live in the threat tables themselves (e.g., `T2 / L12` means a threat enumerated as `T2` in STRIDE and `L12` in the LLM file).

---

## Security Objectives

ThreatPrism should:

- Preserve evidence provenance from intake through report and review.
- Keep analysts in control of all triage and response decisions.
- Prevent raw potential PHI/ePHI, PII, secrets, credentials, raw payload bodies, and token vault mappings from reaching model-visible prompts, manager/GRC views, audit/debug views, eval artifacts, logs, or reports.
- Treat inbound case text, SOAR payloads, logs, and LLM output as untrusted.
- Deny role escalation and audit allow and deny authorization decisions.
- Keep real remediation disabled with `ALLOW_REAL_ACTIONS=false`.
- Return structured `not_configured` results for missing live enrichment keys.
- Avoid healthcare compliance, certification, control-satisfied, and audit-ready claims.

---

## Protected Assets

| Asset | Why It Matters | Current Protection | Lens Files Covering |
|-------|----------------|---------------------|---------------------|
| Case records | Primary SOC analysis objects | Pydantic schemas, SQLite demo persistence, safe role views | STRIDE (T1, I2), LINDDUN (DI3, NC3) |
| Evidence and provenance | Basis for findings, MITRE, GRC, and analyst review | Evidence IDs, source metadata, evidence-grounding checks | STRIDE (T2), LLM (L12) |
| Triage reports | AI-assisted decision support | Schema validation, output policy scan, evidence checks, action safety | STRIDE (T3, E2), LLM (L3, L9, L10, L13) |
| Analyst feedback and disagreement records | Management and process improvement signal | Structured feedback models and audit events | STRIDE (R1) |
| Audit trail | Accountability for intake, guardrails, role views, auth, and feedback | `AuditEvent` records and safe audit summaries | STRIDE (R1, I4-related), LINDDUN (DI4) |
| Token vault mappings | Sensitive link between raw values and safe tokens | Kept in-memory only, excluded from role views and eval artifacts | STRIDE (I3) |
| Stage 1 healthcare tokens | Permanent PHI/PII redaction | `rehydration_allowed=False`; vault not carried into rehydration path | LINDDUN (DI2) |
| Demo API credentials | Demo identity-to-role mapping | Fake credentials, role authorization, full credential non-logging | STRIDE (S1, S2) |
| Eval artifacts | Regression evidence for safety checks | `.eval_runs/` only, sanitized previews, path traversal rejection | STRIDE (D3), LINDDUN (DI5) |

---

## Users and Roles

| User or System | Role in ThreatPrism | Security Expectation |
|----------------|----------------------|----------------------|
| SOC analyst | Reviews case details, evidence, and reports | Sees raw security telemetry; never sees raw PHI/PII (Stage 1 tokens visible only) |
| Detection engineer | Reviews technical telemetry and detection gaps | Same as analyst plus `audit_debug` access |
| Manager/GRC reviewer | Reviews aggregate risk, queues, metrics, and GRC alignment | Receives masked or tokenized views and evidence alignment, not raw sensitive values or raw security telemetry |
| Legal/privacy reviewer | Reviews exposure metadata and privacy/legal flags | Receives detector metadata, audit context, and Stage 1 token classes; not raw sensitive values |
| Audit/debug reviewer | Reviews decisions, hashes, token IDs, and audit metadata | Sees hashes and decision metadata; not raw PHI/PII/secrets/credentials |
| AI/model provider | Produces structured triage assistance | Receives Stage 1 tokenized + Stage 2 tokenized payloads only — never raw security telemetry or raw PHI/PII |
| SOAR/SIEM/webhook source | Sends case or alert payloads | Treated as untrusted and potentially contaminated |
| Future dashboard | Consumes read models and metrics | Must use role-safe backend routes and not bypass authorization |

**Role-view policy** is defined in [auth/demo.py:24-31](../../src/threatprism/auth/demo.py):

```python
ROLE_VIEW_POLICY = {
    "analyst": {"analyst", "ai"},
    "engineer": {"engineer", "analyst", "ai", "audit_debug"},
    "manager_grc": {"manager_grc", "ai"},
    "legal_privacy": {"legal_privacy", "audit_debug", "ai"},
    "audit_debug": {"audit_debug", "ai"},
    "admin": set(VIEW_ROLES),
}
```

---

## Integrations

### Currently Implemented (Fake-Data, Local Only)

- Generic SOAR adapter and fake payloads
- Microsoft-friendly fake payload examples (Sentinel, Defender XDR, Logic Apps)
- Swimlane fake adapter
- Deterministic demo LLM provider (no live calls)
- SQLite demo persistence
- Dry-run eval harness
- Demo scenario pack
- Structured enrichment stubs that return `not_configured`

### Future Integrations — Must Remain Provider-Agnostic

| Integration | Status | Required Threat Model Update Before |
|-------------|--------|---------------------------------------|
| Real LLM providers (OpenAI, Anthropic, local) | Planned | See [LLM threat model](llm-agent-threat-model.md) "Pre-Implementation Requirements" |
| RAG / retrieval layer | Planned | LLM threat model — Before RAG section |
| Memory / write-back layer | Planned | LLM threat model — Before Memory section |
| Tool / plugin / function-calling | Planned | LLM threat model — Before Tools section |
| Multi-tenancy | Planned | LLM threat model — Before Multi-Tenancy section |
| Production IdP (OAuth/OIDC/Entra ID) | Planned | Production-readiness gate before non-demo deployment |
| TLS termination at reverse proxy | Planned | Operational concern; STRIDE assumes trusted proxy |
| Threat intelligence (VirusTotal, AbuseIPDB, URLScan) | Stub only | New trust boundary — model before activation |
| Dashboard UI | Planned | Must consume backend role-safe routes |
| Production persistence (PostgreSQL) | Planned | STRIDE OT-1, OT-8 — needs tamper-evident audit |

---

## Trust Boundaries

| Boundary | Trusted Side | Untrusted Side | Required Control | Code Reference |
|----------|--------------|-----------------|-------------------|----------------|
| API ingress | FastAPI route validation | HTTP request body, headers, query params | Pydantic validation, demo auth when enabled, no raw body audit logging | `create_app()` at [api/app.py:26](../../src/threatprism/api/app.py); `_authorized_view_role()` at [api/app.py:261](../../src/threatprism/api/app.py) |
| SOAR intake | ThreatPrism canonical case model | SOAR webhook payloads and source fields | Normalization, source hash, provenance, healthcare scan | `normalize_soar_payload()` in `soar/generic.py`; `_payload_hash()` at [cases/service.py:714](../../src/threatprism/cases/service.py) |
| Healthcare safeguard boundary | Tokenized case ready for persistence | Raw inbound case with potential PHI/PII | Stage 1 tokenization (permanent) | `_apply_healthcare_safeguards()` at [cases/service.py:99](../../src/threatprism/cases/service.py); `safeguard_value()` at [healthcare.py:219](../../src/threatprism/guardrails/healthcare.py) |
| Pre-model boundary | Sanitized + Stage 2 tokenized case | Persisted case (could contain prompt injection or unmasked telemetry) | Prompt firewall + tokenization | `_prepare_case_for_model()` at [cases/service.py:453](../../src/threatprism/cases/service.py); `sanitize_text()` at [prompt_firewall.py:26](../../src/threatprism/guardrails/prompt_firewall.py); `tokenize_text()` at [tokenization.py:67](../../src/threatprism/guardrails/tokenization.py) |
| Model boundary | Schema-validated output that passes all guardrails | LLM/provider output | Pydantic schema, `scan_output_policy()`, `validate_report_evidence()`, `enforce_action_safety()` | `run_triage()` at [cases/service.py:149-167](../../src/threatprism/cases/service.py) |
| Role-view boundary | Authorized effective role | Requested `?role=` view | Identity-derived role, deny escalation, audit decisions | `authorize_role_view()` at [auth/demo.py:73](../../src/threatprism/auth/demo.py); `render_role_view()` at [views.py:32](../../src/threatprism/guardrails/views.py) |
| Persistence boundary | SQLite demo repository | Raw inbound payloads and token vault internals | Store sanitized case records and safe audit events only | `SQLiteRepository.save_case()` at [persistence/sqlite.py:73](../../src/threatprism/persistence/sqlite.py) — receives already-tokenized `CaseRecord` |
| Eval artifact boundary | `.eval_runs/` sanitized outputs | Eval fixture content and failure text | Approved paths, sanitized previews, artifact scan | `_resolve_under_approved_dir()` at [evals/runner.py:334](../../src/threatprism/evals/runner.py); `_safe_preview()` at [evals/runner.py:262](../../src/threatprism/evals/runner.py) |
| Future retrieval/memory boundary | Approved retrieval corpus and memory records | Untrusted generated summaries and source payloads | **Not implemented yet** — see LLM threat model "Pre-Implementation Requirements" | N/A |

---

## Data Flows

### Case Intake and Triage

```
1. POST /cases (untrusted)
   ↓
2. service.create_case(payload)              [api/app.py:43, cases/service.py:59]
   ↓
3. normalize_soar_payload()                  [soar/generic.py]
   ↓
4. _apply_healthcare_safeguards()            [cases/service.py:99]  ← Stage 1 tokenize (PHI/PII/secrets, permanent)
   ↓
5. repository.save_case(tokenized_case)      [persistence/sqlite.py:73]
   ↓
6. background_tasks.add_task(run_triage)     [api/app.py:54]
   ↓
7. run_triage()                              [cases/service.py:135]
   ↓
8. _prepare_case_for_model()                 [cases/service.py:453]  ← prompt firewall + Stage 2 tokenize
   ↓
9. provider.generate_report()                [llm/providers.py:30]
   ↓
10. scan_output_policy()                     [policy.py:22]
    validate_report_evidence()               [evidence.py:6]
    enforce_action_safety()                  [policy.py:31]
    ↓
11. _rehydrate_report()                      [cases/service.py:522]  ← Stage 2 tokens only; Stage 1 stays redacted
    ↓
12. repository.save_report()                 [persistence/sqlite.py:105]
```

### Read Models and Role Views

```
1. GET /cases/{case_id}/<detail> ?role=<requested>
   ↓
2. _authorized_view_role()                   [api/app.py:261]
   ↓
3. authorize_role_view()                     [auth/demo.py:73]
   - Extract credential
   - Map credential → principal (identity, effective_role)
   - Check requested_role ∈ ROLE_VIEW_POLICY[principal.role]
   - Emit AuditEvent (allow or deny)
   ↓ (if allowed)
4. service.get_<detail>_view(case_id, role)  [cases/service.py:354-386]
   ↓
5. render_role_view(payload, role)           [views.py:32]
   - Masks security telemetry for non-analyst/engineer roles
   - Notes sensitive_tokens_present count
   - Emits role_view_policy_applied AuditEvent
   ↓
6. Response (filtered per role)
```

### Analyst Feedback

```
1. POST /cases/{case_id}/analyst-feedback (analyst-authenticated)
   ↓
2. service.submit_feedback()                 [cases/service.py:422]
   ↓
3. _disagreement()                           [cases/service.py:526]
   - Compares analyst determination/severity/disposition vs. report
   - Computes manager_review_required
   ↓
4. repository.save_feedback(feedback, disagreement)  [persistence/sqlite.py:131]
   ↓
5. AuditEvent appended to case
```

### Eval and Validation

```
1. tools/validate-threatprism.ps1
   ↓
2. Demo safety scanner (tools/check_demo_safety.py)
   ↓
3. pytest with PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
   ↓
4. python -m threatprism.evals.cli
   ↓
5. run_eval_suite()                          [evals/runner.py:29]
   - _approved_fixture_dir() / _approved_output_dir() sandboxing
   - For each fixture: _evaluate_by_category() runs the appropriate guardrail
   - _safe_preview() sanitizes any payload before writing artifact
   ↓
6. Eval artifact hygiene checks
```

---

## Assumptions

These assumptions are the trust premises of all three threat models. Any change to these assumptions requires re-reviewing all three lens files.

- Current data is fake demo data only.
- Single-org internal SOC is the only supported tenancy model.
- Demo API-key auth is not production identity.
- SQLite is demo persistence, not production hardening.
- The deterministic demo provider stands in for live LLM behavior. **Real LLM integration requires re-reviewing the [LLM threat model](llm-agent-threat-model.md).**
- Live provider keys are absent during safe validation.
- Role-based views are only security boundaries when effective-role authorization is enabled (`API_AUTH_MODE=demo_key`).
- The operator is trusted not to deliberately send real PHI to ThreatPrism.
- Operator-controlled environment overrides for `DEMO_API_KEYS` are honored before any networked deployment.
- Memory, RAG, write-back, live SOAR callbacks, production IdP, and dashboard UI are future work and require new threat-model updates before implementation.

---

## Review Log

| Date | Reviewer | Verdict | Notes |
|------|----------|---------|-------|
| 2026-05-24 | Claude (auto-generated, awaiting human review) | Draft — needs review | Refreshed from v0.1 to v0.2 format. Added per-component Framework Selection table linking each major component to its lens file(s). Added code references (`file:function`) to Trust Boundaries table. Added concrete data flow diagrams with line-number anchors. Preserved all existing asset and role content. |
