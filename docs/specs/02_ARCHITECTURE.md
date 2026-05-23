# 02 Architecture

## Directional Guide

Use `docs/ARCHITECTURAL_NORTH_STAR.md` before starting a new implementation
slice, accepting a workaround, or adding a major enhancement.

If implementation needs to intentionally move away from that guide, update the
North Star, `DECISIONS.md`, and `docs/WORKING_CHECKLIST.md` in the same change.

## Target Shape

ThreatPrism must evolve into:

```text
CLI + FastAPI service + dashboard-ready backend
```

FastAPI is the default API framework unless V1 source review later reveals a stronger existing Python API framework choice.

## Component View

```text
SOAR / SIEM / API client
  -> Intake adapters
  -> Normalization service
  -> Case persistence
  -> Async triage job
  -> Guardrail pipeline
  -> LLM provider abstraction
  -> Structured triage report validator
  -> Enrichment and mapping services
  -> Analyst feedback API
  -> Metrics and audit reporting
```

## Components

### CLI

The CLI should remain usable for batch triage, local demos, evaluation runs, and report generation.

Expected commands for future implementation:

- Import demo SOAR payloads.
- Run batch triage.
- Validate triage reports.
- Run guardrail evals.
- Export reports.

### API Service

The API service should provide dashboard-ready JSON responses.

Demo mode may expose the API on localhost without authentication for development. Any production-style deployment must place authentication and authorization in front of case data routes before real organizational data is used.

Core routes for first implementation:

- `GET /health`
- `GET /cases`
- `POST /cases`
- `GET /cases/{case_id}`
- `GET /cases/{case_id}/triage-report`
- `POST /cases/{case_id}/analyst-feedback`

Documented future routes:

- `GET /metrics`
- `GET /cases/{case_id}/evidence`
- `GET /cases/{case_id}/timeline`
- `GET /cases/{case_id}/ioc-enrichment`
- `GET /cases/{case_id}/mitre`
- `GET /cases/{case_id}/grc-controls`
- `POST /evals/run`

### Intake Adapters

Provider-specific payload adapters normalize source payloads into the core `Case` model.

Required adapters:

- Generic webhook adapter.
- Microsoft Sentinel or Logic Apps style adapter.

Required demo examples:

- `examples/soar_payloads/generic_soar_case.json`
- `examples/soar_payloads/sentinel_incident.json`
- `examples/soar_payloads/defender_xdr_alert.json`
- `examples/soar_payloads/logic_apps_webhook_payload.json`
- `examples/soar_payloads/swimlane_case_mock.json`

### Normalization Service

The normalization service should:

- Preserve the original source payload hash.
- Extract alerts, events, entities, IOCs, timestamps, and evidence references.
- Record missing source fields as warnings.
- Avoid source-specific fields leaking into core business logic.

### Persistence

Demo persistence: SQLite.

Future production-style persistence: PostgreSQL.

Recommended future implementation:

- SQLAlchemy models.
- Repository abstraction.
- Alembic migration notes.
- UUID or ULID case identifiers.
- JSON columns where needed, but avoid hiding all data in opaque blobs.

### Async Triage

The first vertical slice must support an async or background job pattern.

Minimum acceptable implementation:

- Case intake returns quickly with `triage_status: queued`.
- A background worker or in-process task processes the report.
- Job states are persisted.

Job states:

- `queued`
- `running`
- `completed`
- `failed`
- `blocked_by_guardrail`
- `needs_review`

### Guardrail Pipeline

Required pipeline order:

1. Input size and type checks.
2. Deterministic prompt firewall.
3. Input sanitization.
4. Semantic prompt-injection classifier interface.
5. LLM generation through provider abstraction.
6. Structured schema validation.
7. Output policy scanner.
8. Evidence-grounding checks.
9. Action safety scanner.
10. Audit event write.

### LLM Provider Abstraction

Business logic should depend on an internal provider interface, not a vendor SDK.

Required provider capabilities:

- Generate structured triage report.
- Return model name and provider name.
- Return token and latency metadata where available.
- Return explicit provider error classes.
- Support fail-closed behavior.

### Mapping And Enrichment

Threat intelligence providers:

- VirusTotal.
- URLScan.io.
- AbuseIPDB.
- WHOIS/RDAP.

Mapping services:

- MITRE ATT&CK mapping.
- HITRUST-aligned GRC control category mapping.

Missing enrichment credentials must return `not_configured`.

### Audit Trail

Audit events should capture:

- Case creation.
- Payload normalization warnings.
- Guardrail blocks.
- Triage report generation.
- Analyst feedback submission.
- Disagreement calculation.
- Simulated action creation.
- Export events.

## Deployment View

Recommended future Docker Compose services:

- `threatprism-api`
- `threatprism-worker`, if a separate worker is used
- `postgres`, optional production-style profile
- `redis`, only if queue-based jobs are used

Demo mode should stay simple and runnable without live external credentials.

## Configuration

Expected environment variables:

```text
THREATPRISM_ENV=demo
DATABASE_URL=sqlite:///./data/threatprism.db
API_AUTH_MODE=none
API_TOKEN=
LLM_PROVIDER=openai
OPENAI_API_KEY=
LOCAL_LLM_BASE_URL=
ALLOW_REAL_ACTIONS=false
VIRUSTOTAL_API_KEY=
URLSCAN_API_KEY=
ABUSEIPDB_API_KEY=
WHOIS_RDAP_PROVIDER=default
```

## Architecture Constraints

- Single-org internal SOC only.
- Avoid hardcoding assumptions that block future multi-tenant support.
- No full dashboard in the initial build.
- No production-impacting actions.
- No real customer data in demo payloads.
- Demo `API_AUTH_MODE=none` is acceptable only for localhost and fake data.
