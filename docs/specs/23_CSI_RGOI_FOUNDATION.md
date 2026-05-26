# Spec 23: CSI/RGOI Foundation

## Status

Implemented as read-only Cognitive Security Infrastructure (CSI) with
Retrieval-Governed Organizational Intelligence (RGOI) v0.1.

## Goal

Add governed organizational cognition to ThreatPrism while preserving the
existing demo-safe, evidence-first, analyst-controlled architecture.

CSI/RGOI must not become unrestricted AI memory. It must enforce provenance,
retrieval policy, tenant namespace isolation, evidence citation, trust scoring,
semantic injection defenses, stale cognition detection, lineage
reconstruction, and human truth ownership.

## In Scope

- Four-tier cognitive architecture.
- Cognitive object schemas.
- Provenance and evidence references.
- Reasoning lineage graph.
- Retrieval governance engine.
- Trust scoring engine.
- Evidence alignment validator.
- Semantic drift/stale cognition detection.
- Cognitive observability.
- Institutional learning loop scaffolding.
- Multi-perspective intelligence support.
- Adversarial memory defense hooks.
- Replay framework scaffolding.
- AI-vs-human divergence telemetry.
- Read-only FastAPI routes.
- Fake demo fixtures and tests.

## Out Of Scope

- Autonomous memory writes.
- Knowledge approval workflows.
- Trust mutation APIs.
- Suppression publication.
- Remediation or containment.
- Live LLM calls.
- Live SOAR, cloud, enrichment, or RAG calls.
- Production IdP.
- Production tenant administration.
- Real PHI, PII, credentials, tenant data, workplace data, or provider output.

## Object Model

Each `CognitiveObject` includes:

- `id`
- `tenant_id`
- `tier`
- `object_type`
- `source_type`
- `source_ref`
- `author`
- `author_type`
- `created_at`
- `modified_at`
- `confidence`
- `trust_score`
- `review_status`
- `sensitivity`
- `evidence_refs`
- `lineage_refs`
- `retrieval_zone`
- `schema_version`
- `validation_state`
- `expiration_policy`
- `lifecycle_state`
- `claims`
- `content`
- `interpretation_group_id`
- `competes_with`

## API Contract

Implemented read-only routes:

| Route | Purpose |
|---|---|
| `GET /csi/objects` | Search governed cognitive objects |
| `GET /csi/objects/{object_id}` | Read one retrievable cognitive object |
| `GET /csi/lineage/{object_id}` | Reconstruct visible reasoning lineage |
| `GET /csi/replay/{object_id}` | Return deterministic replay inputs |
| `GET /csi/observability` | Return cognitive control and state metrics |
| `GET /csi/divergence` | Return AI-vs-human divergence telemetry |

All routes require `tenant_id`. Role and purpose are evaluated together.
Denied same-tenant objects are explained without exposing hidden cross-tenant
objects.

## Required Controls

- Tenant mismatch suppression.
- Role/purpose policy.
- Retrieval-zone policy.
- Quarantine exclusion.
- Evidence citation enforcement.
- Unsupported claim rejection.
- Trust thresholding by purpose.
- Stale cognition hidden by default.
- Prompt-injection quarantine and redaction detection.
- Healthcare safeguard scanning.
- AI-authored cognition marked non-authoritative unless approved.

## Definition Of Done

- New CSI package exists under `src/threatprism/csi/`.
- API routes expose read-only governed retrieval only.
- Tests prove tenant isolation, RBAC/ABAC-style policy, evidence alignment,
  trust scoring, quarantine exclusion, stale cognition behavior, lineage,
  replay, observability, divergence, and OpenAPI route presence.
- Docs, checklist, handoff, limitations, decisions, threat model, workflows,
  examples, and lessons are updated.
- Standard validation passes with `ALLOW_REAL_ACTIONS=false`.
