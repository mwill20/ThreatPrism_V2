# ThreatPrism Architectural North Star

## Purpose

This guide is the directional architecture reference for ThreatPrism.

Use it before starting a new implementation slice, accepting a workaround, or
adding a major enhancement. It does not replace the specs, decisions,
limitations, or validation results. It keeps those documents pointed at the
same target.

The North Star can change when the architecture needs to change. If a
workaround or enhancement intentionally changes direction, update this guide,
`DECISIONS.md`, and `docs/WORKING_CHECKLIST.md` in the same change.

## North Star Statement

ThreatPrism is a demo-safe, production-style SOC migration accelerator for
organizations moving from outsourced MSSP-managed SOC operations toward an
internal SOC model.

ThreatPrism ingests security cases from SOAR, SIEM, API, or CLI sources;
normalizes evidence and provenance; applies deterministic guardrails and
healthcare safeguard checks; produces structured, evidence-linked triage and
GRC alignment outputs; captures analyst feedback and disagreement signals; and
exposes role-safe views for analysts, engineers, managers, GRC, legal/privacy,
audit/debug, and AI processing. It can also expose read-only,
retrieval-governed organizational cognition when evidence, provenance, trust,
role, purpose, and tenant namespace controls all permit retrieval.

ThreatPrism must remain analyst-controlled. It may recommend or simulate
response actions, but it must not execute real remediation or containment in
V2.

## Non-Negotiables

- Product name is `ThreatPrism`.
- Canonical path is `C:\Projects\ThreatPrismV2`.
- Destination repository is `mwill20/ThreatPrism_V2`.
- Build a clean V2 architecture with selective V1 concept porting.
- Do not full-copy V1.
- Demo data must stay fake.
- Public or synthetic datasets may be used only as reviewed source material
  for sanitized ThreatPrism-native fixtures. Raw external datasets must not be
  committed or used as runtime data models.
- Do not include real organizations, workplaces, tenants, users, hosts,
  domains, IPs, secrets, or operational details in docs, code, examples, tests,
  or commit messages.
- Keep `ALLOW_REAL_ACTIONS=false` by default.
- Do not add real remediation or containment in V2.
- Treat inbound case text, logs, payloads, and source artifacts as untrusted.
- Treat inbound SOAR payloads as potentially contaminated, even though they are
  expected to contain security-only telemetry.
- Do not classify every identifier as PHI/ePHI by itself.
- Tokenize or sanitize sensitive values before model-visible payload creation.
- Treat LLM output as untrusted until schema validation, output policy scanning,
  evidence grounding, and action-safety checks pass.
- Rehydrate only through controlled, authorized role views after validation.
- Never rehydrate secrets, full API keys, credential values, or token vault
  mappings into reports or role views.
- Do not treat role-based rendering as authorization until identity-to-role
  enforcement exists.
- Do not treat CSI/RGOI as unrestricted AI memory. Humans own truth; AI
  cognition is non-authoritative unless approved by a human governance path.
- Do not add memory write-back, RAG corpus expansion, trust mutation,
  suppression publication, or autonomous knowledge changes without reopening
  the threat model treatment register.
- Do not add external research providers such as Exa.ai to CSI/RGOI, live RAG,
  validation, demos, fixture promotion, or source-of-truth paths without
  explicit approval and updated threat treatment.
- Use healthcare safeguard and evidence-alignment language only.
- Do not claim HIPAA compliance, HIPAA certification, HITRUST compliance,
  HITRUST certification, control satisfaction, certification readiness, or that
  evidence proves compliance.

## Target Architecture

ThreatPrism should evolve toward:

```text
CLI + FastAPI service + dashboard-ready backend
```

The core architecture should stay provider-agnostic:

- SOAR and SIEM intake through adapters.
- LLM access through provider interfaces.
- Threat intelligence through optional provider interfaces.
- External research providers, if added later, through optional disabled-by-default
  adapters that create non-authoritative `external_unreviewed`
  candidates only after provenance capture and human review.
- Microsoft security integrations as first-class adapters, not hardwired core
  dependencies.
- SQLite for demo persistence, with a future PostgreSQL path left open.
- In-process FastAPI background tasks are acceptable for early demo slices.
  Revisit a worker or queue when API, persistence, access control, guardrails,
  and demo flows are stable.

## Safe Data Flow

The default safe path is:

```text
Raw source payload
  -> Source payload hash
  -> Evidence and provenance normalization
  -> Deterministic healthcare safeguard scan
  -> Prompt firewall
  -> Input sanitization and sensitive-value tokenization
  -> Model-visible payload
  -> Provider-agnostic LLM or deterministic demo provider
  -> Strict schema validation
  -> Output policy scan
  -> Evidence-grounding checks
  -> Action-safety checks
  -> Authorization-aware role view
  -> Deterministic report or read model
  -> Safe audit event
```

No raw potential PHI/ePHI, secrets, full credentials, raw payload bodies, or
token vault mappings should enter model-visible payloads, management/GRC views,
audit/debug views, authorization audit events, logs, or deterministic reports.

Public or synthetic datasets must flow through a separate fixture-factory path:

```text
Reviewed source sample
  -> Ignored external_datasets/ local storage
  -> Dataset adapter
  -> Sanitizer and validator
  -> ThreatPrism-native synthetic fixture
  -> Generated fixture review before any tracked test promotion
```

Do not couple runtime case processing directly to public dataset schemas.

Read-only CSI/RGOI retrieval must flow through a governed cognition path:

```text
Retrieval request
  -> Demo identity and role authorization
  -> Tenant namespace filter
  -> Purpose and retrieval-zone policy
  -> Evidence citation validation
  -> Prompt-injection and healthcare safeguard scan
  -> Trust scoring and stale cognition check
  -> Explained read-only response
```

CSI/RGOI v0.1 must not persist new memory, mutate trust, approve knowledge,
publish suppressions, run live RAG, or execute remediation.

## Role And Access Direction

Role-based rendering is useful but is not an access-control boundary by itself.

The architecture direction is:

- `ai`: tokenized model-visible payloads only.
- `analyst`: controlled security telemetry visibility needed for response.
- `engineer`: controlled technical visibility needed for detection and debug.
- `manager_grc`: masked or tokenized views by default.
- `legal_privacy`: exposure metadata and audit trail, not raw sensitive values.
- `audit_debug`: token IDs, detector types, field paths, hashes, timestamps, and
  decisions only.

Access Control & Audit Integrity v0.1 makes these role views enforceable with
demo authentication and authorization before live integrations or any non-demo
data path.

## Evidence And GRC Direction

ThreatPrism should organize security evidence so humans can review it.

GRC output must stay advisory:

- Evidence-linked.
- Category-level.
- Human-reviewed.
- Explicitly not a compliance determination.

Allowed framing includes:

- HIPAA Security Rule safeguard theme.
- HITRUST-aligned category mapping.
- HITRUST-style framework category.
- Evidence-to-control traceability.
- Evidence alignment.
- Requires review.

Blocked framing includes:

- HIPAA compliant.
- HIPAA certified.
- HITRUST compliant.
- HITRUST certified.
- Control satisfied.
- Certification-ready.
- Audit-ready.
- Evidence proves compliance.

## Slice Sequencing

Current direction:

1. Completed: first backend slice.
2. Completed: Healthcare Safeguard & Evidence Alignment Guardrails v0.1.
3. Completed: Access Control & Audit Integrity v0.1.
4. Completed: Operational Read Models & Metrics API v0.1.
5. Completed: Evaluation Harness & Regression Defense Labs v0.1.
6. Completed: Demo Operations & CI Hardening v0.1.
7. Completed: Demo Scenario Pack & API Contract Freeze v0.1.
8. Completed: Docker Compose & Local Demo Packaging v0.1.
9. Completed: Data Strategy & Synthetic Fixture Factory v0.1 for local-only
   reviewed source-shape conversion into sanitized ThreatPrism-native
   fixtures.
10. Completed: CSI/RGOI Foundation v0.1 for read-only retrieval-governed
    organizational cognition.
11. Completed: Dashboard UI Preparation v0.1 for backend data contracts,
    persona fixtures, readiness runbook, and route contract coverage.
12. Completed: Dashboard UI Implementation v0.1 as a local fake-data-only,
    same-origin FastAPI-served dashboard.
13. Completed: Production Dashboard Hardening v0.1 for the local dashboard
    surface: security headers, same-origin request enforcement,
    timeout-bounded fetches, keyboard persona navigation, and threat-model
    traceability updates.
14. Completed: Curated Generated-Fixture Promotion v0.1 for one tiny tracked,
    hand-reviewed fake SOC fixture with manifest review and path-safe
    promotion tests.
15. Production dashboard deployment, production identity, live-integration
    preparation, or broader curated fixture promotion only after explicit user
    approval and any required threat-model treatment updates.

Do not add live LLM calls, live SOAR calls, live enrichment calls, production
IdP integration, real remediation, non-demo data, or production dashboard
deployment before the security and access-control foundation is validated.

## Decision Rubric

Use these questions before accepting a design change:

- Does it preserve analyst control?
- Does it reduce exposure risk or keep exposure risk unchanged?
- Does it preserve evidence provenance and source traceability?
- Does it avoid compliance, certification, and control-satisfaction claims?
- Does it keep data fake and demo-safe?
- Does it keep real remediation disabled?
- Does it avoid hardwiring one vendor into the core model?
- Does it keep Microsoft integrations first-class through adapters?
- Does it remain testable with local safe validation?
- Does it leave a reasonable future production path open?

If the answer to any question is no, either change the design or record the
risk and revisit trigger before implementing.

## Workaround And Enhancement Process

Workarounds are allowed when they unblock validated progress, but they must be
visible.

For each architecture-shaping workaround or enhancement, document:

- Why it is needed.
- What risk it introduces.
- Whether it is temporary or permanent.
- What validation proves it is safe enough for the current slice.
- What future trigger should revisit it.

Required documentation updates:

- Update this file when the direction changes.
- Update `DECISIONS.md` for durable architecture decisions.
- Update `docs/WORKING_CHECKLIST.md` when the active slice or sequencing
  changes.
- Update `docs/THREATPRISM_V2_CODEX_HANDOFF.md` when the next-agent startup
  path changes.

Silent architecture drift is not acceptable. Either update the North Star
through the decision process or bring the implementation back into alignment.
