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

## Recently Completed Slice

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

This slice is implemented. It preserves the compatibility `GET /cases` list
route and adds `GET /cases/read-model` as the dashboard-ready envelope route.

## Recently Completed Slice

```text
Evaluation Harness & Regression Defense Labs v0.1
  -> Add fixture-based dry-run eval datasets
  -> Exercise prompt injection, evidence grounding, schema, action safety,
     healthcare safeguard, authorization, and leakage controls
  -> Produce structured eval results without live LLM, SOAR, cloud, or
     enrichment calls
  -> Keep ALLOW_REAL_ACTIONS=false and fake data only
  -> Use eval output as a regression signal before dashboards or live providers
```

This slice is implemented as Evaluation Harness & Regression Defense Labs
v0.1.

## Recently Completed Slice

```text
Demo Operations & CI Hardening v0.1
  -> Add safe local validation scripts
  -> Add lightweight CI that runs the validated local test command
  -> Add demo/runbook hardening for API and eval workflows
  -> Keep generated artifacts ignored and sanitized
  -> Keep live LLM, SOAR, cloud, dashboard, production IdP, and remediation out
     of scope
```

This slice is implemented.

## Recently Completed Slice

```text
Demo Scenario Pack & API Contract Freeze v0.1
  -> Add repeatable fake demo scenarios for analyst, manager/GRC,
     legal/privacy, audit/debug, and engineering views
  -> Confirm OpenAPI/API response contracts for current backend routes
  -> Add smoke-testable demo instructions using only fake payloads
  -> Keep dashboard UI, live providers, production IdP, and remediation out of
     scope unless explicitly requested
```

This slice is implemented with typed scenario-pack loading, fake demo scenario
artifacts, OpenAPI route/response-model assertions, and role workflow smoke
tests.

## Next Recommended Slice

```text
No new implementation slice is selected yet.
  -> Docker Compose & Local Demo Packaging v0.1 is complete
  -> Data Strategy & Synthetic Fixture Factory v0.1 remains planned
  -> Dashboard UI, live providers, production IdP, and remediation require
     explicit approval and updated threat treatment
```

## Future Planned Slice

```text
Data Strategy & Synthetic Fixture Factory v0.1
  -> Keep hand-written fake fixtures for deterministic tests
  -> Use public or synthetic datasets only as manually reviewed source material
  -> Add a data-source registry with license-review flags
  -> Add local-only adapters for Synthea, OTRF/Security Datasets, PINT, and
     Giskard prompt-injection samples
  -> Convert small source samples into sanitized ThreatPrism-native fixtures
  -> Ignore raw external datasets and generated fixture outputs by default
  -> Keep live LLM, live SOAR, Caldera execution, production telemetry, and
     remediation out of scope
```

This slice is planned in `docs/DATA_STRATEGY_AND_FIXTURE_FACTORY.md` and
`docs/specs/20_DATA_STRATEGY_AND_FIXTURE_FACTORY.md`.

## Roadmap Constraints

- Do not build a full dashboard before the backend is stable.
- Do not implement real remediation actions.
- Do not require live SOAR credentials for demos.
- Do not claim HITRUST compliance.
- Do not make strict CI checks block progress before the inherited codebase is ready.
- Do not ingest public datasets directly into runtime flows. Convert reviewed
  samples into sanitized ThreatPrism-native fixtures first.
