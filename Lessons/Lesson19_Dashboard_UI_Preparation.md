# Lesson 19: Dashboard UI Preparation

## Goal

Understand how ThreatPrism prepares for a future dashboard without building a
frontend UI.

## Primary Files

- `docs/DASHBOARD_DATA_CONTRACT.md`
- `docs/specs/24_DASHBOARD_UI_PREPARATION.md`
- `docs/runbooks/DASHBOARD_READINESS.md`
- `examples/dashboard_contract/*.json`
- `tests/test_demo_scenarios_and_api_contract.py`

## Mental Model

Dashboard UI preparation is a backend contract slice. It freezes the API
surfaces, sample response shapes, persona fixtures, and validation expectations
that a future UI can consume.

It does not add:

- frontend routes
- components
- charts
- build tooling
- browser tests
- live providers
- production identity
- real data

## Dashboard Contract Surfaces

The future dashboard can consume:

- `GET /health`
- `GET /metrics`
- `GET /cases/read-model`
- `GET /queues/manager-review`
- `GET /queues/healthcare-review`
- `GET /cases/{case_id}`
- `GET /cases/{case_id}/triage-report`
- `GET /cases/{case_id}/evidence`
- `GET /cases/{case_id}/timeline`
- `GET /cases/{case_id}/mitre`
- `GET /cases/{case_id}/grc-controls`
- `GET /cases/{case_id}/audit-events`
- `GET /csi/objects`
- `GET /csi/objects/{object_id}`
- `GET /csi/lineage/{object_id}`
- `GET /csi/replay/{object_id}`
- `GET /csi/observability`
- `GET /csi/divergence`

## Fixtures

`examples/dashboard_contract/` contains fake static response examples for:

- analyst
- manager/GRC
- legal/privacy
- audit/debug
- engineer
- CSI/RGOI

These are design-contract fixtures. They are not generated dataset fixtures,
runtime captures, or production data.

## Tests

`tests/test_demo_scenarios_and_api_contract.py` now checks:

- CSI/RGOI routes are present in OpenAPI.
- CSI route query parameters remain present.
- CSI response models remain wired.
- Dashboard contract fixtures are fake-data only and persona-complete.

## Safe Extension Rules

Build a frontend only after explicit approval. Do not turn dashboard prep into
live-provider work, production IdP integration, remediation, real data, RAG
write-back, or autonomous knowledge mutation.
