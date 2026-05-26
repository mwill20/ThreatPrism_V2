# Decisions

This file records locked ThreatPrism V2 decisions from the handoff brief and spec pack.

## D-001 Product Name

Use `ThreatPrism` as the product name.

Use only `ThreatPrism` as the product name in user-facing material.

## D-002 Repository Target

The target repository is `mwill20/ThreatPrism_V2`.

The original V1 repository must not be modified directly.

## D-003 Source Of Truth

The handoff brief is the source of truth for V2. V1 repository context is useful only where it does not conflict with the handoff.

## D-004 Product Direction

ThreatPrism V2 is a production-style, demo-safe SOC migration accelerator for organizations moving from outsourced MSSP-managed SOC operations toward an internal SOC model.

## D-005 Architecture

V2 targets:

```text
CLI + FastAPI service + dashboard-ready backend
```

The CLI should remain usable. FastAPI is the default API framework unless later V1 source review shows a stronger reason to choose another Python API framework.

## D-006 Tenancy

V2 is single-org internal SOC only.

Do not build MSSP multi-tenancy in V2.

## D-007 SOAR Integration

SOAR integration must use provider-agnostic adapters.

Required examples:

- Generic webhook.
- Microsoft Sentinel or Logic Apps style payloads.

## D-008 Microsoft Integration

Microsoft security integrations are a first-class path, but the ingestion model remains provider-agnostic.

Target systems:

- Sentinel.
- Defender XDR.
- Defender for Endpoint.
- Graph Security API.
- Entra ID logs.
- Azure Monitor / Log Analytics / KQL exports.
- Logic Apps / Power Automate.

## D-009 AI Provider Strategy

The LLM layer must be provider-agnostic.

Default provider: OpenAI.

Optional provider: OpenAI-compatible local endpoint or Ollama-compatible provider.

V1 included Gemini support, but V2 defaults to OpenAI per the handoff.

## D-010 Action Safety

V2 permits recommended actions, simulated actions, dry-run planning, and action adapter scaffolding only.

Default:

```text
ALLOW_REAL_ACTIONS=false
```

Real remediation or containment is out of scope for V2 and reserved for a future version.

## D-011 Guardrails

V2 must use layered guardrails:

- Deterministic prompt firewall.
- Input sanitization.
- Schema validation.
- Semantic prompt-injection classifier interface.
- Output policy scanner.
- Strict structured output.
- Evidence-grounding checks.
- No autonomous action enforcement.
- Audit logging.
- Fail-closed behavior where possible.

## D-012 Persistence

Demo mode uses SQLite.

Persistence should be designed so PostgreSQL can be added later.

## D-013 GRC And HITRUST Language

Use HITRUST-aligned control category mapping only.

Do not claim HITRUST compliance, certification, or implementation.

## D-014 Threat Intelligence

Define interfaces or stubs for:

- VirusTotal.
- URLScan.io.
- AbuseIPDB.
- WHOIS/RDAP.

Missing API keys must return structured `not_configured` results.

## D-015 V1 Compatibility Concepts

V2 should preserve these V1 concepts where useful:

- CLI-first workflows for batch mode.
- Common event envelope and provenance fields.
- Deterministic report rendering.
- SQLite demo persistence.
- Pydantic-style structured validation.
- Prompt firewall.
- Dry-run validation.
- Run-level artifacts.

## D-016 First Vertical Slice

The first implementation slice after spec review should be:

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

## D-017 API Security Boundary

Demo mode may use unauthenticated localhost access with fake data only.

Production-style use must require authentication and authorization before exposing case data.

## D-018 Workspace Path

The canonical local workspace path is `C:\Projects\ThreatPrismV2`.

## D-019 Current Async Strategy

The current demo backend slice uses FastAPI in-process background tasks for
triage execution.

This is sufficient for the first fake-data slice. A separate worker and queue
should be considered after the API, persistence, guardrails, and demo workflow
are stable.

## D-020 Demo API Auth Boundary

Demo mode may use `API_AUTH_MODE=none` only with localhost-style fake demo data.

Any non-demo, shared, or real-data use requires an explicit authentication and
authorization design before exposing case payloads or reports.

## D-021 Healthcare Safeguard Framing

ThreatPrism does not classify every identifier as PHI or ePHI by itself.

ThreatPrism treats inbound SOAR data as potentially contaminated and applies
deterministic safeguards to prevent accidental exposure of identifiable health
information.

Identifiers become PHI/ePHI risk when they are connected to health context,
patient context, care context, billing context, encounter context, or other data
that can reasonably identify an individual.

## D-022 Healthcare Evidence Alignment Language

ThreatPrism uses healthcare safeguard language, not compliance-certification
language.

ThreatPrism may support evidence alignment to HIPAA Security Rule safeguard
themes and HITRUST-style framework categories.

ThreatPrism must not claim:

- HIPAA compliance.
- HIPAA certification.
- HITRUST compliance.
- HITRUST certification.
- That a control is satisfied.
- That evidence is audit-ready.
- That a mapped case proves compliance.

All mappings are advisory, evidence-linked, and require human review.

## D-023 Next Implementation Slice

The originally prepped implementation slice after healthcare safeguard
guardrails was:

```text
Operational Read Models & Metrics API v0.1
```

This slice should still be implemented before any frontend dashboard work, but
it is no longer the immediate next slice.

Required focus:

- Stable `GET /metrics` aggregate response shape.
- Dashboard-ready case list filtering or a companion envelope route.
- Manager-review and healthcare-review queue behavior.
- Safe detail routes for evidence, timeline, MITRE, GRC, and audit events.
- Role-safe rendering on read/detail routes.
- Tests proving metrics and read models do not expose raw potential PHI/ePHI,
  secrets, credentials, or token vault mappings.

Out of scope for this slice:

- Frontend dashboard.
- Live LLM calls.
- Live SOAR callbacks.
- Live enrichment calls.
- Production authentication and authorization.
- Real remediation or containment.

## D-024 Access Control Before Metrics

Access Control & Audit Integrity v0.1 supersedes Operational Read Models &
Metrics API v0.1 as the immediate next implementation slice.

Reason:

Role-based rendering is not authorization. A request parameter such as
`?role=analyst` or `?role=manager_grc` must not be treated as authority unless
ThreatPrism has a trusted identity-to-role enforcement layer.

Next implementation target:

```text
Access Control & Audit Integrity v0.1
```

Required focus:

- Demo authentication using fake/demo credentials only.
- Caller identity mapped to an effective role.
- Authorization checks that deny role escalation.
- `?role=` treated as a view request, not authority, outside explicit demo/test
  override behavior.
- Safe audit events for allow and deny decisions.
- Tests proving manager/GRC cannot force analyst or engineer views.
- Tests proving authorization audit events do not expose raw potential PHI/ePHI,
  secrets, full credentials, raw payloads, or token vault mappings.

Out of scope:

- Production IdP integration.
- OAuth/OIDC/Entra integration.
- Frontend dashboard.
- Live LLM calls.
- Live SOAR calls.
- Live enrichment calls.
- Real remediation or containment.

## D-025 Architectural North Star

`docs/ARCHITECTURAL_NORTH_STAR.md` is the directional architecture guide for
ThreatPrism.

It does not replace the specs, decisions, limitations, handoff, or validation
results. It keeps future slices, workarounds, and enhancements aligned with the
same product and security direction.

Before starting a new implementation slice or accepting an architecture-shaping
workaround, check the North Star.

If a workaround or enhancement intentionally changes architecture direction,
update `docs/ARCHITECTURAL_NORTH_STAR.md`, `DECISIONS.md`, and
`docs/WORKING_CHECKLIST.md` in the same change.

## D-026 Demo Access Control

ThreatPrism uses demo API-key authentication for role-aware case and report
views when `API_AUTH_MODE=demo_key`.

This is not a production IdP integration. It exists to make role-based
healthcare views enforceable and auditable before broadening read models,
metrics, dashboards, live integrations, or non-demo data paths.

Demo credentials are fake and configured through `DEMO_API_KEYS` using:

```text
credential:identity:role
```

Supported effective roles:

- `analyst`
- `engineer`
- `manager_grc`
- `legal_privacy`
- `audit_debug`
- `admin`

Role requests such as `?role=analyst` are treated as view requests, not
authority. In `API_AUTH_MODE=demo_key`, the effective role is derived from the
demo credential and role escalation is denied.

Authorization allow and deny decisions must create audit events without storing
raw potential PHI/ePHI, secrets, full credentials, raw payload bodies, or token
vault mappings.

## D-027 Slice Completion Documentation Rule

Every implementation slice must close with documentation and learning updates,
not only code and tests.

Required closeout updates:

- `README.md`.
- `docs/WORKING_CHECKLIST.md`.
- `docs/THREATPRISM_V2_CODEX_HANDOFF.md`.
- Applicable files under `docs/specs/`.
- Applicable top-level docs under `docs/`.
- `LIMITATIONS.md`.
- `DECISIONS.md` when a durable decision was made.
- `AGENTS.md` when future-agent guidance changed.
- `Lessons/00_Index.md`.
- New or updated lesson files when the slice adds learning-worthy behavior.

Validation results must be recorded from the current live repo state. Do not
carry forward stale test counts.

## D-028 Operational Read Models And Metrics

Operational Read Models & Metrics API v0.1 is implemented as a backend-only,
dashboard-ready read slice.

ThreatPrism preserves the existing `GET /cases` list response for compatibility
and adds `GET /cases/read-model` as the stable filterable envelope route.

Implemented read surfaces:

- `GET /metrics`.
- `GET /cases/read-model`.
- `GET /cases/{case_id}/evidence`.
- `GET /cases/{case_id}/timeline`.
- `GET /cases/{case_id}/mitre`.
- `GET /cases/{case_id}/grc-controls`.
- `GET /cases/{case_id}/audit-events`.

These routes remain fake-demo and backend-only. They must not expose raw
potential PHI/ePHI, secrets, full credentials, raw payload bodies, or token
vault mappings. Role-aware detail/read routes must use the same demo
authorization and role-safe rendering policy introduced by Access Control &
Audit Integrity v0.1.

## D-029 Evaluation Harness And Regression Defense Labs

Evaluation Harness & Regression Defense Labs v0.1 is implemented as a local,
dry-run regression safety gate.

The harness reads fake JSONL fixtures only from `tests/evals/` and writes
sanitized artifacts only under `.eval_runs/`. Path traversal is rejected.

The harness must not write raw potential PHI/ePHI, secrets, credentials, full
authorization headers, raw payload bodies, or token vault mappings to result
artifacts.

This harness is not a live-LLM safety proof, HIPAA compliance claim, HITRUST
certification claim, audit-ready claim, or production readiness claim. It proves
the current deterministic and controlled fake-provider safety checks keep
working.

## D-030 Production Environment Rejects Demo Auth

ThreatPrism must not start a production-like environment with authentication
disabled or demo API-key authentication enabled.

If `THREATPRISM_ENV` is `prod` or `production`, `API_AUTH_MODE=none` and
`API_AUTH_MODE=demo_key` are rejected during application startup.

This does not implement production IdP integration. It prevents the current
demo access-control layer from accidentally being treated as production
authentication.

## D-031 Demo Operations And CI Hardening

Demo Operations & CI Hardening v0.1 is implemented as a fake-data-only
operations safety layer.

The preferred local validation path is `tools/validate-threatprism.ps1`. It
sets fake-only environment defaults, clears live-provider credential variables,
runs the demo safety checker, runs pytest with plugin autoload disabled, runs
the dry-run eval harness, and scans eval artifacts.

The CI workflow in `.github/workflows/safe-validation.yml` mirrors this
fake-data-only contract and must not require repository secrets.

Generated validation artifacts must remain ignored. Eval outputs, pytest temp
directories, cache files, local databases, bytecode, and `.env` files must not
be tracked.

This slice does not make ThreatPrism production-ready. It makes unsafe local
and CI operation harder before dashboards, live integrations, production IdP,
or production persistence are introduced.

## D-032 Demo Scenario Pack And API Contract Freeze

Demo Scenario Pack & API Contract Freeze v0.1 is implemented as a fake-data-only
backend demonstration and regression layer.

The scenario pack lives under `examples/demo_scenarios/` and covers analyst,
manager/GRC, legal/privacy, audit/debug, and engineer workflows through local
FastAPI routes only.

The current API contract is frozen by tests that assert the implemented routes
and key OpenAPI response model references remain present. Later slices may add
routes, but removing or renaming the frozen routes is a contract change that
must update docs, tests, and decision records.

This slice does not add dashboard UI, live provider calls, production IdP
integration, real SOAR callbacks, or remediation.

## D-033 Context-Light Handoff

ThreatPrism uses a file-based startup path to reduce new-chat context usage.

`START_HERE.md` is the compact entry point for future AI sessions. Long handoff
docs should be referenced by path, not pasted into chat.

When context is approaching 75% used, or less than roughly 25% remains, the
agent should output a compact handoff prompt and update durable handoff files
before continuing.

The local command for generating the compact prompt is:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\generate-compact-handoff.ps1
```

## D-034 Dataset Strategy

ThreatPrism uses a layered data strategy.

Hand-written fake fixtures remain the baseline for deterministic unit and
regression tests.

Public or synthetic datasets may be used only as source material after manual
license and safety review. They must be converted into sanitized
ThreatPrism-native synthetic fixtures before being used in tests, demos, or
evals.

Raw external datasets must not be committed. Full datasets must not be
auto-downloaded by default. Runtime flows must not depend directly on public
dataset schemas.

The first planned data-realism implementation slice is:

```text
Data Strategy & Synthetic Fixture Factory v0.1
```

Candidate source families include Synthea, OTRF/Security Datasets, Lakera PINT,
and Giskard prompt-injection samples, but each source remains review-required
until the user approves license, safety, and commitability for selected samples.

## D-035 Docker Compose Local Demo Packaging

Docker Compose & Local Demo Packaging v0.1 packages only the existing fake-data
FastAPI backend.

The default Compose service is intentionally single-service:

```text
threatprism-api
```

The slice does not add PostgreSQL, Redis, dashboard UI, production identity,
live LLM, live SOAR, live enrichment, or real remediation. Those surfaces
remain gated by the threat model treatment register and require explicit
future approval.

Compose hard-codes empty live-provider credential variables and fake demo API
keys so host secrets are not passed through by accident. The local image uses
the transitive lock file for dependency installation and stores demo SQLite
state in a named Docker volume.

## D-036 Synthetic Fixture Factory Boundary

Data Strategy & Synthetic Fixture Factory v0.1 is implemented as local tooling
under `tools/fixture_factory/`.

The factory converts explicit, manually reviewed source-shape samples under
`external_datasets/` into sanitized ThreatPrism-native JSONL fixtures under
`fixtures/generated/`.

The factory must remain deterministic:

- Stable fixture IDs.
- Sorted fixture ordering.
- Sorted JSON output.
- No unseeded randomness.
- No timestamps in generated fixture payloads.

The factory must remain local-only:

- No automatic dataset downloads.
- No future download support hidden in this slice.
- No raw third-party dataset commits.
- No live LLM, SOAR, cloud, enrichment, RAG, memory/write-back, dashboard,
  production IdP, or remediation scope.

Generated fixtures are ignored by default and must not silently affect baseline
tests or evals. Any generated fixture promoted into tracked tests or eval
fixtures requires a separate manual review of license, safety, and data
content.

## D-037 CSI/RGOI Read-Only Cognition Boundary

Cognitive Security Infrastructure (CSI) with Retrieval-Governed Organizational
Intelligence (RGOI) is implemented as a read-only governed cognition
foundation.

CSI/RGOI is not unrestricted AI memory. Humans own truth. AI-authored cognition
is non-authoritative unless approved through a future human governance path.

The current implementation may retrieve, correlate, explain, reconstruct
lineage, expose replay scaffolding, surface stale cognition, preserve
competing interpretations, and report AI-vs-human divergence telemetry.

The current implementation must not:

- Persist autonomous memory writes.
- Modify trust scores through an API.
- Approve knowledge.
- Publish suppressions.
- Execute remediation.
- Use live LLM, SOAR, cloud, enrichment, or RAG providers.
- Handle real PHI, real PII, credentials, real tenant data, or real workplace
  data.

Tenant IDs in CSI/RGOI v0.1 are defensive cognition namespaces for testable
isolation. They are not MSSP multi-tenancy or production tenant
administration.

## D-038 Production Identity Readiness Boundary

Production Identity Readiness v0.1 defines `API_AUTH_MODE=external_oidc` as the
explicit production identity readiness mode.

This is a static readiness boundary only. It validates provider, issuer,
audience, JWKS URI, claim names, role coverage, and safe asymmetric algorithms.
It rejects live verifier enablement because no trusted production token
verifier exists yet.

Production-like environments still reject `API_AUTH_MODE=none` and
`API_AUTH_MODE=demo_key`. Protected API routes under `external_oidc` fail closed
with `403 Unsupported API auth mode.` until a future approved slice implements
token validation, trusted principal extraction, claim-to-role mapping, and
production authorization policy.
