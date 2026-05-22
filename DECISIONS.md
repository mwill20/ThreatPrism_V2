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
