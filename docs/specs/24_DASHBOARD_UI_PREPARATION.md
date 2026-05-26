# Spec 24: Dashboard UI Preparation

## Status

Implemented as dashboard preparation only. No frontend dashboard is built in
this slice.

## Goal

Freeze the backend data contract, sample response fixtures, and runbook needed
for a future dashboard while preserving the current fake-data-only safety
boundary.

## In Scope

- Dashboard data contract doc.
- Fake sample response fixtures for dashboard personas.
- CSI/RGOI route contract coverage alongside the existing API contract freeze.
- Dashboard readiness runbook with fake demo credential examples.
- Documentation, checklist, handoff, limitations, lessons, and validation
  updates.

## Out Of Scope

- Frontend dashboard UI.
- Component libraries, charts, pages, browser automation, or dev server work.
- Live LLM, SOAR, cloud, enrichment, RAG, or production IdP integration.
- Real remediation.
- Real organization, workplace, tenant, user, host, domain, IP, PHI, PII, or
  secret data.
- CSI/RGOI write-back, trust mutation, suppression publication, or autonomous
  knowledge approval.

## Contracted API Surfaces

Core backend surfaces:

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

CSI/RGOI surfaces:

- `GET /csi/objects`
- `GET /csi/objects/{object_id}`
- `GET /csi/lineage/{object_id}`
- `GET /csi/replay/{object_id}`
- `GET /csi/observability`
- `GET /csi/divergence`

## Acceptance Criteria

- Future UI engineers can identify the exact backend surfaces to consume.
- Persona-specific fixture examples exist and are fake-data only.
- Contract tests assert the CSI/RGOI routes and query parameters remain present
  in OpenAPI.
- Runbook explains local fake credential usage for dashboard readiness checks.
- Repository documentation explicitly says dashboard UI is still not
  implemented.
- Standard validation passes.
