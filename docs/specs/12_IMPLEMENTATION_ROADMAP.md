# 12 Implementation Roadmap

## Directional Guide

Before starting a new roadmap slice, check `docs/ARCHITECTURAL_NORTH_STAR.md`.

If a workaround or enhancement changes the direction of the roadmap, update the
North Star, `DECISIONS.md`, and `docs/WORKING_CHECKLIST.md` instead of letting
the roadmap drift.

## Build Order

### Phase 0: Repo Initialization And Baseline Audit

Scope:

- Initialize or sync the local workspace with `mwill20/ThreatPrism_V2`.
- Confirm work is not modifying the original `mwill20/threatprism` repository directly.
- Audit useful V1 concepts for selective porting, including CLI behavior,
  schemas, guardrails, reports, SQLite persistence, tests, and run artifacts.
- Record compatibility decisions without full-copying V1.

Exit criteria:

- V2 work occurs only in the new project.
- The current validated baseline is committed and pushed to the destination
  repository.
- Baseline audit notes are recorded.

### Phase 1: Spec Pack

Scope:

- Create `docs/specs/00` through `14`.
- Create or update `AGENTS.md`, `DECISIONS.md`, and `LIMITATIONS.md`.
- Complete the original spec pack before broader implementation.

Exit criteria:

- Specs define concrete API payloads, data models, workflows, guardrails, and acceptance criteria.

Current status:

- Complete. Implementation has begun after the spec pack.

### Phase 2: Core Case Model

Scope:

- Add Pydantic models or equivalent schema layer.
- Define case, evidence, IOC, triage report, analyst feedback, and disagreement models.
- Preserve V1-style provenance fields.

Exit criteria:

- Schema tests validate required fields and enum constraints.

### Phase 3: FastAPI Skeleton

Scope:

- Add FastAPI service.
- Implement `/health`, `/cases`, `/cases/{case_id}`, `/cases/{case_id}/triage-report`, and `/cases/{case_id}/analyst-feedback`.
- Keep CLI usable.

Exit criteria:

- API tests pass for core routes.

### Phase 4: Generic SOAR Webhook Ingestion

Scope:

- Add generic SOAR adapter.
- Add demo payloads.
- Normalize into the case model.

Exit criteria:

- Demo payload can be ingested without live credentials.

### Phase 5: Async Triage Job

Scope:

- Add background triage job pattern.
- Return tracking ID immediately.
- Persist job state.

Exit criteria:

- Intake does not block on triage completion.

### Phase 6: Triage Report Schema

Scope:

- Generate structured triage report.
- Validate schema.
- Render deterministic report output.

Exit criteria:

- Report includes evidence, timeline, IOCs, MITRE mapping, hypotheses, GRC controls, limitations, and analyst review statement.

### Phase 7: Analyst Feedback And Disagreement Model

Scope:

- Implement `POST /cases/{case_id}/analyst-feedback`.
- Calculate disagreement metrics.

Exit criteria:

- Feedback and disagreement tests pass.

### Phase 8: Guardrails And Evals

Scope:

- Add prompt firewall, schema validation, output policy scanner, semantic classifier interface, and eval harness.
- Add healthcare safeguard scanner for context-aware potential PHI/ePHI, PII,
  secrets, and security telemetry handling.
- Add compliance-language scanner that blocks HIPAA/HITRUST compliance,
  certification, audit-ready, and control-satisfied claims.

Exit criteria:

- Prompt-injection, hallucination, unsafe action, schema, and evidence citation evals pass.
- Raw potential PHI/ePHI does not appear in model-visible payloads, reports,
  manager/GRC views, logs, or audit/debug views.

### Phase 8A: Access Control And Audit Integrity

Scope:

- Add demo authentication using fake/demo credentials only.
- Map caller identity to an effective role.
- Deny unauthorized role escalation.
- Treat `?role=` as a view request, not authority, outside explicit demo/test
  override behavior.
- Record safe audit events for authorization allow and deny decisions.

Exit criteria:

- Manager/GRC cannot force analyst or engineer views.
- Missing, unknown, or unauthorized roles fail closed when demo auth is
  enabled.
- Authorization audit events do not expose raw potential PHI/ePHI, secrets,
  full credentials, raw payloads, or token vault mappings.

### Phase 9: Threat Intel Stubs

Scope:

- Add VirusTotal, URLScan.io, AbuseIPDB, and WHOIS/RDAP interfaces.
- Return `not_configured` when keys are missing.

Exit criteria:

- Missing-key tests pass without crashes.

### Phase 10: MITRE And GRC Mapping

Scope:

- Add structured MITRE mapping.
- Add HITRUST-aligned GRC category mapping.
- Add healthcare safeguard evidence-alignment language for HIPAA Security Rule
  safeguard themes without making compliance claims.

Exit criteria:

- Mappings cite evidence IDs and avoid compliance claims.

### Phase 11: Microsoft Adapter Examples

Scope:

- Add Sentinel, Defender XDR, and Logic Apps demo adapters.

Exit criteria:

- Demo payloads normalize into the case model.

### Phase 12: Docker, CI/CD, And Demo Guide

Scope:

- Add Docker Compose.
- Add `.env.example`.
- Add basic CI checks.
- Add demo guide and runbook updates.

Exit criteria:

- Demo setup can run locally.
- CI checks are useful but not overly strict.

## First Vertical Slice

```text
Generic SOAR webhook payload
  -> Normalize into ThreatPrism Case
  -> Start async triage job
  -> Generate structured triage report
  -> Add MITRE + IOC + GRC mappings, even if stubbed
  -> Return/report status via API
  -> Analyst submits feedback
  -> ThreatPrism records disagreement metrics
```

## Recently Completed Slice

```text
Healthcare Safeguard & Evidence Alignment Guardrails v0.1
  -> Treat inbound SOAR payloads as potentially contaminated
  -> Detect potential PHI/ePHI only when identifiers are tied to health, patient,
     care, billing, encounter, or similar identifying context
  -> Tokenize PHI/ePHI, PII, secrets, and security telemetry with typed tokens
  -> Preserve security telemetry needed for SOC response through controlled
     role-based rendering
  -> Block compliance/certification/audit-ready claims
  -> Record audit events for tokenization, rehydration, denial, guardrail blocks,
     and report validation
  -> Add tests proving raw sensitive values do not leak into model-visible
     payloads, reports, logs, or manager/GRC views
```

## Prepped Follow-On Slice

```text
Operational Read Models & Metrics API v0.1
  -> Add stable GET /metrics aggregate response shape
  -> Add dashboard-ready case list filtering or a companion list envelope route
  -> Add manager-review and healthcare-review queue behavior
  -> Add safe detail routes for evidence, timeline, MITRE, GRC, and audit events
  -> Apply role-safe rendering to detail and review routes
  -> Track guardrail, healthcare safeguard, disagreement, timing, and GRC metrics
  -> Prove metrics and read models do not expose raw potential PHI/ePHI, secrets,
     or token vault mappings
  -> Keep the slice backend-only, fake-data-only, and no-real-remediation
```

This slice remains important and is already specified. It should follow the
access-control slice so role-safe read models are backed by enforceable
authorization.

## Next Recommended Slice

```text
Access Control & Audit Integrity v0.1
  -> Add demo authentication using fake/demo credentials only
  -> Map caller identity to an effective role
  -> Stop treating ?role= as authority outside explicit demo/test override
  -> Deny role escalation and fail closed for missing or unknown callers
  -> Harden role-view policy for analyst, engineer, manager/GRC,
     legal/privacy, audit/debug, and AI views
  -> Record safe audit events for authorization allow and deny decisions
  -> Prove manager/GRC cannot force analyst or engineer views
  -> Prove authorization audit events do not expose raw potential PHI/ePHI,
     secrets, credentials, raw payloads, or token vault mappings
```

## Roadmap Constraints

- Do not build a full dashboard before the backend is stable.
- Do not implement real remediation actions.
- Do not require live SOAR credentials for demos.
- Do not claim HITRUST compliance.
- Do not make strict CI checks block progress before the inherited codebase is ready.
