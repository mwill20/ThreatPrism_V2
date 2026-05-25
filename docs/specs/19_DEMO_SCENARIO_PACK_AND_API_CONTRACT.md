# 19 Demo Scenario Pack And API Contract

## Status

Implemented as Demo Scenario Pack & API Contract Freeze v0.1.

## Purpose

Provide a repeatable fake-data demo pack and contract tests before dashboard UI,
live integrations, or production authentication work begins.

## Scope

In scope:

- Role-specific fake demo workflows for analyst, manager/GRC, legal/privacy,
  audit/debug, and engineer personas.
- Local FastAPI smoke coverage using the existing deterministic demo provider.
- OpenAPI route and response-model checks for the current backend routes.
- Fake healthcare-context contamination fixture for safeguard review.
- Documentation for the current contract boundary.

Out of scope:

- Dashboard UI.
- Live SOAR callbacks.
- Live LLM, cloud, or enrichment calls.
- Production IdP integration.
- Real remediation or containment.
- Real organization, workplace, tenant, user, host, domain, IP, or secret data.

## Scenario Artifacts

```text
examples/demo_scenarios/demo_scenario_pack.json
examples/demo_scenarios/healthcare_safeguard_review_case.json
```

The scenario pack uses schema version:

```text
demo-scenario-pack/0.1
```

Each scenario declares:

- Persona.
- Fake demo credential.
- Payload path under `examples/`.
- Ordered local API steps.
- Expected status codes.
- Expected JSON paths.
- Forbidden substrings for role-safe views.

## Scenario Personas

Required personas:

- `analyst`.
- `manager_grc`.
- `legal_privacy`.
- `audit_debug`.
- `engineer`.

## Frozen Current API Surface

Current implemented routes covered by the contract test:

```text
GET /health
POST /cases
GET /cases
GET /metrics
GET /cases/read-model
GET /queues/manager-review
GET /queues/healthcare-review
GET /cases/{case_id}
GET /cases/{case_id}/triage-report
GET /cases/{case_id}/evidence
GET /cases/{case_id}/timeline
GET /cases/{case_id}/mitre
GET /cases/{case_id}/grc-controls
GET /cases/{case_id}/audit-events
POST /cases/{case_id}/analyst-feedback
```

Response models asserted through OpenAPI:

- `CaseAcceptedResponse`.
- `list[CaseSummary]`.
- `OperationalMetrics`.
- `CaseReadModelEnvelope`.
- `ReviewQueueEnvelope`.
- `FeedbackResponse`.

## Acceptance Criteria

- The scenario pack validates with typed Pydantic models.
- All required personas are present.
- Scenario payloads stay under `examples/`.
- Scenario steps use local API paths only.
- Scenario smoke tests pass against an in-memory FastAPI app.
- OpenAPI still exposes the current implemented routes.
- Current response model references remain stable for contract-backed routes.
- Contract-declared status codes remain present in OpenAPI for each route.
- Role-specific scenario responses do not leak forbidden raw sensitive values.
- Validation remains fake-data-only with `ALLOW_REAL_ACTIONS=false`.
