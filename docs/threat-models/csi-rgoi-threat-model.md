# CSI/RGOI Threat Model

## Scope

This model covers the read-only CSI/RGOI v0.1 foundation:

- Cognitive object schemas.
- Demo seeded cognitive objects.
- Retrieval governance.
- Trust scoring.
- Evidence alignment validation.
- Lineage, replay, observability, and divergence APIs.

It does not approve memory write-back, RAG over external corpora, live LLMs,
production tenancy, real data, or remediation.

## Security Objectives

- Humans own truth.
- AI cognition is non-authoritative unless approved.
- Evidence references remain immutable.
- Retrieval is governed by role, purpose, tenant namespace, zone, trust, and
  evidence alignment.
- Quarantined or poisoned cognition is not retrieved.
- Unsupported claims are rejected.
- Stale cognition is hidden by default and exposed only for authorized
  reconstruction.

## Trust Boundaries

| Boundary | Current Control |
|---|---|
| Caller to CSI API | Existing demo auth and role-view authorization |
| Tenant namespace | Required `tenant_id` and strict object filtering |
| Retrieval zone | Role-specific zone policy |
| Cognitive object to response | Evidence alignment, trust score, stale check, quarantine exclusion |
| AI cognition to human decision | AI authority state remains non-authoritative unless human approved |

## Threats And Mitigations

| Threat | Risk | Mitigation |
|---|---|---|
| Cross-tenant cognition leakage | High | Suppress objects where `object.tenant_id != context.tenant_id`; do not reveal cross-tenant object IDs |
| RAG poisoning or adversarial memory | High | Prompt-injection scan, quarantine zone exclusion, unsupported claim rejection |
| Unsupported AI claim becomes truth | High | Evidence references required; unsupported claims fail alignment; AI objects marked non-authoritative |
| Role overreach | High | Existing demo role authorization plus CSI role/purpose and zone policy |
| Stale cognition influences decisions | Medium | Stale objects hidden by default; audit/debug can request stale objects explicitly |
| Trust score manipulation | Medium | No trust mutation APIs in v0.1; trust is computed deterministically from object metadata and validation |
| Lineage over-disclosure | Medium | Lineage includes only objects visible under the caller's retrieval policy |
| Replay misuse | Medium | Replay returns deterministic input hashes and visible references only; it does not rerun models or mutate state |

## Residual Risks

- The demo seed is in-memory and does not implement append-only persisted audit
  storage yet.
- Tenant namespace filtering is not production multi-tenancy.
- No production IdP, break-glass governance, retention policy, or evidence
  WORM storage exists yet.
- Future RAG, memory write-back, live LLM, or non-demo data work must reopen
  this threat model and the treatment register.

## Tests

Current coverage:

- `tests/test_csi_rgoi.py`

Covered behaviors:

- Tenant suppression.
- Read-only control explanation.
- Competing AI and human interpretation preservation.
- AI non-authority.
- Manager/GRC zone denial.
- Stale cognition default hiding.
- Quarantined adversarial memory exclusion.
- Demo auth and role escalation denial.
- Lineage, replay, observability, divergence, and OpenAPI route presence.
