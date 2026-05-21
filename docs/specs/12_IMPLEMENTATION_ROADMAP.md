# 12 Implementation Roadmap

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

Exit criteria:

- Prompt-injection, hallucination, unsafe action, schema, and evidence citation evals pass.

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

## Roadmap Constraints

- Do not build a full dashboard before the backend is stable.
- Do not implement real remediation actions.
- Do not require live SOAR credentials for demos.
- Do not claim HITRUST compliance.
- Do not make strict CI checks block progress before the inherited codebase is ready.
