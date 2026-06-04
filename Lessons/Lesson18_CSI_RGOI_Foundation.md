# Lesson 18: CSI/RGOI Foundation

## Goal

Understand how ThreatPrism implements read-only governed cognition without
creating unrestricted AI memory.

## Primary Files

- `src/threatprism/csi/schemas.py`
- `src/threatprism/csi/governance.py`
- `src/threatprism/csi/service.py`
- `src/threatprism/api/app.py`
- `tests/test_csi_rgoi.py`
- `docs/CSI_RGOI_ARCHITECTURE.md`
- `docs/specs/23_CSI_RGOI_FOUNDATION.md`

## Mental Model

This foundation slice is not a memory write-back system. It is a read-only
retrieval layer that exposes cognitive objects only after policy checks pass.
Later demo-only, human-gated write-back is covered separately in Lesson 41 and
does not wire cognition into triage.

Core principles:

- Humans own truth.
- AI assists interpretation.
- Evidence is immutable.
- Interpretations are attributable and versioned.
- Retrieval is policy governed.
- AI-generated cognition is non-authoritative unless approved.

## Code Walkthrough

`schemas.py` defines the object contract: tier, object type, tenant namespace,
source reference, author, evidence references, lineage references, retrieval
zone, validation state, lifecycle state, review status, trust, confidence,
claims, and competing interpretations.

`governance.py` contains deterministic controls:

- role/purpose policy
- retrieval-zone policy
- evidence alignment
- prompt-injection scanning
- healthcare safeguard scanning
- trust scoring
- stale cognition detection
- AI authority state

`service.py` seeds fake demo objects and exposes read-only search, detail,
lineage, replay, observability, and divergence behavior.

`api/app.py` wires the routes:

- `GET /csi/objects`
- `GET /csi/objects/{object_id}`
- `GET /csi/lineage/{object_id}`
- `GET /csi/replay/{object_id}`
- `GET /csi/observability`
- `GET /csi/divergence`

## What The Tests Prove

`tests/test_csi_rgoi.py` proves:

- tenant beta cognition is suppressed from tenant alpha retrieval
- CSI responses explain read-only controls
- AI and human competing interpretations are preserved
- AI-authored cognition remains non-authoritative
- manager/GRC cannot retrieve SOC-operational cognition
- stale cognition is hidden by default
- quarantined adversarial memory is not retrievable
- demo auth and role escalation checks apply before retrieval
- lineage, replay, observability, divergence, and OpenAPI routes exist

## Safe Extension Rules

Future CSI/RGOI work must not add production write-back, live RAG, trust
mutation, suppression publication, autonomous knowledge approval, or remediation
without reopening the threat model treatment register. Demo-only human approval
work is a separate gated surface.

Any future production path needs production identity, authorization, tenant
administration, retention, append-only audit storage, and non-demo data
controls before real data is used.
