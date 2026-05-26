# Dashboard Data Contract

## Purpose

This document defines the backend API surfaces the local ThreatPrism dashboard
consumes. Earlier dashboard preparation used this as a future-UI contract; the
dashboard now uses these same surfaces directly.

The contract is fake-data only and remains bound by the current safety model:

- no live providers
- no real credentials
- no real organization, workplace, tenant, user, host, domain, IP, PHI, PII, or
  secret data
- no remediation or containment
- no memory write-back, trust mutation, or autonomous knowledge approval

## Required Headers

For role-aware demo mode, use fake demo credentials:

```text
X-ThreatPrism-Demo-Key: demo-analyst-key
X-ThreatPrism-Demo-Key: demo-manager-key
X-ThreatPrism-Demo-Key: demo-legal-key
X-ThreatPrism-Demo-Key: demo-audit-key
X-ThreatPrism-Demo-Key: demo-engineer-key
```

## Core Dashboard Surfaces

| Surface | Route | Primary Consumer | Contract Notes |
|---|---|---|---|
| Health | `GET /health` | all views | Confirms mode, version, and `allow_real_actions=false`. |
| Metrics | `GET /metrics` | manager/GRC, analyst lead | Aggregates case, triage, guardrail, disagreement, timing, and GRC metrics. |
| Case list | `GET /cases/read-model` | analyst, manager/GRC | Filterable dashboard envelope with triage summary and operational flags. |
| Manager queue | `GET /queues/manager-review` | manager/GRC | Pre-filtered case-list envelope for manager review. |
| Healthcare queue | `GET /queues/healthcare-review` | legal/privacy, manager/GRC | Pre-filtered case-list envelope for healthcare safeguard review. |
| Case detail | `GET /cases/{case_id}` | analyst, engineer, legal/privacy | Full normalized case view subject to role policy and masking. |
| Report detail | `GET /cases/{case_id}/triage-report` | analyst, manager/GRC | Latest validated report or guarded not-ready/blocker message. |
| Evidence detail | `GET /cases/{case_id}/evidence` | analyst, engineer | Evidence records with role-safe rendering. |
| Timeline detail | `GET /cases/{case_id}/timeline` | analyst, engineer | Normalized timeline entries. |
| MITRE detail | `GET /cases/{case_id}/mitre` | analyst, engineer, manager/GRC | Evidence-linked ATT&CK mappings. |
| GRC detail | `GET /cases/{case_id}/grc-controls` | manager/GRC, legal/privacy | Advisory HITRUST-aligned categories only. |
| Audit detail | `GET /cases/{case_id}/audit-events` | audit/debug, legal/privacy | Safe audit summaries, no raw credentials. |

## CSI/RGOI Dashboard Surfaces

| Surface | Route | Primary Consumer | Contract Notes |
|---|---|---|---|
| Cognitive search | `GET /csi/objects` | analyst, engineer, manager/GRC | Requires `tenant_id`; returns only governed objects visible to role/purpose/zone policy. |
| Cognitive detail | `GET /csi/objects/{object_id}` | analyst, engineer | Includes trust, evidence alignment, authority state, and retrieval decision. |
| Lineage graph | `GET /csi/lineage/{object_id}` | analyst, audit/debug, engineer | Reconstructs visible reasoning lineage only. |
| Replay scaffold | `GET /csi/replay/{object_id}` | audit/debug, engineer | Returns deterministic input hash and visible references; does not rerun an LLM. |
| Cognitive observability | `GET /csi/observability` | engineer, audit/debug | Object counts, stale cognition, AI non-authority, competing groups, active controls. |
| AI-vs-human divergence | `GET /csi/divergence` | analyst, manager/GRC | Shows divergence telemetry where policy permits both sides. |

## Query Parameters

### `GET /cases/read-model`

- `source`
- `status`
- `triage_status`
- `severity`
- `determination`
- `manager_review_required`
- `healthcare_review_required`
- `guardrail_blocked`
- `authorization_denied`
- `created_after`
- `created_before`
- `limit`
- `cursor`
- `role`

### `GET /csi/objects`

- `tenant_id`
- `query`
- `object_type`
- `retrieval_zone`
- `purpose`
- `include_stale`
- `limit`
- `role`

### CSI detail routes

CSI detail, lineage, replay, observability, and divergence routes require
`tenant_id`. Detail, lineage, and replay routes also include the path
parameter `object_id`.

## Persona Fixture Map

Representative fake response fixtures live under
`examples/dashboard_contract/`:

| Persona | Fixture |
|---|---|
| Analyst | `analyst_case_read_model.json` |
| Manager/GRC | `manager_grc_metrics.json` |
| Legal/Privacy | `legal_privacy_healthcare_queue.json` |
| Audit/Debug | `audit_debug_audit_events.json` |
| Engineer | `engineer_case_detail.json` |
| CSI/RGOI | `csi_rgoi_retrieval.json` |

Fixtures are static examples for UI planning and contract review. They are not
runtime outputs, baseline eval fixtures, or generated dataset promotions.

## Explicit Non-Goals

The dashboard contract and local UI still do not add:

- live LLM/provider calls
- live SOAR/cloud/enrichment calls
- production IdP integration
- real data handling
- remediation or containment
- CSI/RGOI write-back or RAG corpus expansion
- external frontend dependencies, third-party assets, analytics, or telemetry
- production deployment, browser matrix certification, or accessibility
  certification
