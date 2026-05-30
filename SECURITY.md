# Security

This document describes the security architecture, threat model, and
vulnerability reporting process for ThreatPrism.

ThreatPrism is a security tool that processes untrusted security telemetry. Its
own security posture is critical — a vulnerability in ThreatPrism could expose
the threat data it is designed to protect.

---

## Reporting Vulnerabilities

If you discover a security vulnerability, do not open a public issue.

Contact the maintainer directly at mwill.itmission@gmail.com with:

- Description of the vulnerability.
- Steps to reproduce.
- Potential impact.
- Suggested fix (if known).

You will receive an acknowledgment within 72 hours. Confirmed vulnerabilities
will be patched and disclosed after a fix is available.

---

## Current Security Posture

ThreatPrism V2 is demo-safe. It is not deployed to production and does not
process real organizational data. The security controls described below are
implemented and tested, but the system has not undergone external security
review, penetration testing, or production hardening.

### What is implemented

- Four-layer guardrail pipeline (prompt firewall, healthcare safeguards, output
  policy, evidence validation).
- Demo API-key authentication with identity-to-role mapping.
- Role-based authorization with escalation denial.
- Context-aware PHI/PII/secret tokenization at case intake.
- Security telemetry tokenization before LLM exposure.
- Action safety enforcement (`ALLOW_REAL_ACTIONS=false`).
- Audit trail on every authorization decision, tokenization event, and role-view
  access.
- Eval harness with regression tests across 16 security-relevant categories.
- Read-only CSI/RGOI retrieval governance with tenant namespace filtering,
  role/purpose policy, retrieval-zone policy, evidence alignment, trust
  scoring, stale cognition controls, quarantine exclusion, lineage, replay,
  observability, and AI-vs-human divergence telemetry.
- Local dashboard hardening with same-origin static assets, CSP, frame
  blocking, no-sniff, referrer, browser permission, same-origin resource, and
  no-store cache headers.
- Production environment startup guard (rejects disabled and demo auth modes).
- Static production identity readiness for `API_AUTH_MODE=external_oidc`,
  including provider, issuer, audience, JWKS, claim, role, and algorithm
  checks. Protected requests fail closed when local verification is disabled or
  incomplete.
- Production token verifier design for the `external_oidc` runtime path:
  bearer-token acceptance, asymmetric signature validation,
  issuer/audience/time checks, tenant and role claim enforcement, role mapping,
  JWKS cache boundaries, fail-closed error semantics, no-network validation,
  and sanitized audit telemetry.
- Local no-network production token verifier implementation for
  `external_oidc` using fake local JWKS JSON, verified claim-to-role mapping,
  existing role-view policy enforcement, and sanitized audit events.
- POC-grade HTTP request body limits, in-process `POST /cases` rate limiting,
  and triage concurrency caps.
- Exact-pinned direct dependencies plus a transitive `requirements-lock.txt`.

### What is not implemented

- Live production IdP integration (OAuth, OIDC discovery, live JWKS fetch,
  Entra ID).
- TLS termination or transport security (expected from a reverse proxy).
- Edge or distributed rate limiting beyond the in-process POC limiter.
- Network-level access controls.
- Database encryption at rest.
- Secrets management system (Vault, Key Vault, etc.).
- Container hardening or deployment security.
- CI/CD security gates.
- External security audit or penetration test.

---

## Threat Model

### Trust boundaries

```
                          ┌──────────────────────┐
  Untrusted               │                      │
  ─────────────────────── │   SOAR / Webhook      │ ── inbound payloads
                          │   callers             │
                          └──────────┬───────────┘
                                     │
                          ┌──────────▼───────────┐
                          │   FastAPI ingestion   │
                          │   + SOAR adapters     │
                          ├──────────────────────┤
  Semi-trusted            │   Healthcare         │ ── Stage 1 tokenization
  (sanitized, tokenized)  │   safeguard layer    │
                          ├──────────────────────┤
                          │   Prompt firewall     │ ── redact/quarantine
                          │   + Stage 2 tokenize  │    injection attempts
                          ├──────────────────────┤
                          │   LLM provider        │ ── sees only tokenized
                          │   (deterministic demo)│    content
                          ├──────────────────────┤
  Untrusted               │   LLM output          │ ── must pass output
  (until validated)       │                      │    policy + evidence
                          │                      │    + action safety
                          ├──────────────────────┤
                          │   SQLite persistence  │ ── stores full records
                          │                      │    (tokenized at intake)
                          ├──────────────────────┤
  Role-gated              │   Role-view layer     │ ── masks content at
  (auth + masking)        │   + auth layer        │    read time per role
                          └──────────────────────┘
```

### Threat categories and mitigations

| Threat | Mitigation | Location |
|--------|-----------|----------|
| Prompt injection in case payloads | Prompt firewall regex rules with redact/quarantine actions | `guardrails/prompt_firewall.py` |
| PHI/PII contamination in SOAR data | Context-aware healthcare safeguard tokenization at intake; tokens are never rehydrated | `guardrails/healthcare.py` |
| Secret leakage in inbound payloads | Secret-pattern detection (API keys, passwords) with permanent tokenization | `guardrails/healthcare.py`, `guardrails/tokenization.py` |
| LLM hallucinating evidence citations | Evidence validation checks every cited `evidence_id` against the case evidence set | `guardrails/evidence.py` |
| LLM overclaiming compliance or certification | Output policy regex scanner blocks HIPAA/HITRUST compliance, certification, and control-satisfaction language | `guardrails/policy.py` |
| LLM claiming real remediation was executed | Action safety check blocks any report containing `real_action_executed: true` | `guardrails/policy.py` |
| Role escalation (lower-privilege caller requests higher-privilege view) | `ROLE_VIEW_POLICY` enforcement; caller's effective role derived from credential, not request parameter | `auth/demo.py` |
| Unauthorized access to case data | Demo API-key auth required when `API_AUTH_MODE=demo_key`; production env rejects demo auth | `auth/demo.py`, `config.py` |
| Production identity misconfiguration | `external_oidc` requires static OIDC-shaped readiness config and rejects live verifier enablement until an approved verifier slice exists | `auth/production.py`, `config.py`, `tests/test_production_identity_readiness.py` |
| Production token verifier trust mistakes | Local verifier requires signature, issuer, audience, time, tenant, and role checks before claims become authority; live JWKS/IdP integration remains gated | `auth/production.py`, `tests/test_production_token_verifier.py` |
| Security telemetry visible to non-analyst roles | Role-based view masking replaces IPs, URLs, emails, hashes with `[SECURITY_TELEMETRY:TYPE:masked]` for non-analyst roles | `guardrails/views.py` |
| Token vault mapping exposure (raw-to-token map leaked) | Vault mappings stay in-memory on `CaseService`; never serialized to database, API responses, or eval artifacts | `guardrails/tokenization.py` |
| Eval fixture path traversal | `_resolve_under_approved_dir()` rejects paths outside `tests/evals/` and `.eval_runs/` | `evals/runner.py` |
| Demo auth used in production | `validate_runtime()` raises on startup if env is `prod`/`production` with `none` or `demo_key` auth; `demo_key` requires explicit `DEMO_API_KEYS`; `none` requires explicit local-dev acknowledgement | `config.py` |
| HTTP payload abuse | `POST /cases` enforces request body cap, in-process rate limit, and triage concurrency cap | `api/app.py`, `config.py` |
| CSI/RGOI retrieval overreach | Tenant namespace filter, role/purpose policy, retrieval-zone policy, trust thresholding, stale cognition controls, and quarantine exclusion | `csi/governance.py`, `csi/service.py` |
| Unsupported or poisoned cognition becomes truth | Evidence alignment rejects unsupported claims; AI-authored cognition remains non-authoritative unless human approved | `csi/governance.py`, `tests/test_csi_rgoi.py` |
| Dashboard browser abuse | Dashboard responses enforce CSP, frame blocking, no-sniff, no-referrer, permissions, same-origin resource policy, and no-store cache behavior; JavaScript rejects non-same-origin request targets | `api/app.py`, `dashboard/static/app.js`, `tests/test_dashboard_ui.py` |

### Assets requiring protection

- **Case records**: may contain security telemetry, IP addresses, hostnames,
  user identifiers, and — in healthcare environments — data that becomes PHI
  when combined with health context.
- **Triage reports**: contain analyst-facing findings, MITRE mappings, and GRC
  control alignments derived from case evidence.
- **Audit trail**: records every authorization decision, tokenization event, and
  role-view access. Must not contain raw credentials or token vault mappings.
- **Token vault mappings**: the in-memory reverse mapping from tokens to raw
  values. If exposed, all tokenization is defeated.
- **API credentials**: demo API keys in `.env` files. Real API keys for future
  threat intelligence integrations (VirusTotal, AbuseIPDB, URLScan, etc.).
- **Cognitive objects**: evidence-linked CSI/RGOI records used for read-only
  retrieval. They must preserve tenant namespace, provenance, trust, lifecycle,
  and authority metadata.

---

## Security Invariants

These are hard constraints that must hold across all code paths. Breaking any of
these is a security defect.

1. **No raw PHI/PII reaches the LLM.** Stage 1 healthcare safeguard tokenization
   runs at case intake, before persistence or model-visible payload creation.

2. **Stage 1 tokens are never rehydrated.** `[POTENTIAL_PHI:...]`,
   `[POTENTIAL_PII:...]`, and `[SECRET:...]` tokens have
   `rehydration_allowed=False` and no code path reverses them.

3. **Real actions are always blocked.** `enforce_action_safety()` rejects any
   report with `real_action_executed: true`, regardless of provider output.

4. **Every authorization decision is audited.** Both allows and denials generate
   `AuditEvent` records on the case with caller identity, effective role,
   requested role, endpoint, decision, and reason.

5. **Audit events never contain raw credentials.** Authorization audit metadata
   includes a `request_metadata_hash` (SHA-256), not the raw credential value.

6. **Token vault mappings never leave the service layer.** The `TokenVault`
   instance lives on `CaseService` during triage execution. Vault mappings are
   not serialized to the database, API responses, or eval artifacts.

7. **Role views are enforced by identity, not by request parameter.** When
   `API_AUTH_MODE=demo_key`, the caller's effective role is derived from their
   credential. A `?role=` parameter is a view request, not authority — the
   auth layer denies requests for views outside the caller's `ROLE_VIEW_POLICY`.

8. **Production environments cannot start with disabled or demo auth.**
   `validate_runtime()` blocks `THREATPRISM_ENV=prod` or `production` when
   `API_AUTH_MODE` is `none` or `demo_key`.

9. **Production identity readiness is fail-closed.**
   `API_AUTH_MODE=external_oidc` requires static OIDC-shaped configuration and
   rejects incomplete verifier enablement. Protected API routes deny requests
   unless local fake-JWKS verification is explicitly enabled and complete.

10. **Production token verifier trusts verified claims only.**
    The runtime verifier requires local JWKS-backed signatures, issuer and
    audience checks, time checks, tenant and role claim enforcement, explicit
    role mapping, and sanitized audit events before claims become authority.
    Live JWKS fetch and live IdP calls remain gated.

11. **Disabled auth requires explicit local acknowledgement.**
   `API_AUTH_MODE=none` is rejected unless local development is explicitly
   acknowledged with `THREATPRISM_LOCAL_DEV_ACK=true` or auth is explicitly
   disabled for tests.

12. **Case submission cost is bounded for POC scope.** `/cases` has a body
    limit, per-process rate limit, and triage concurrency cap. Production still
    needs edge enforcement and durable queue backpressure.

13. **CSI/RGOI is read-only.** CSI/RGOI routes must not write memory, mutate
    trust, approve knowledge, publish suppressions, execute remediation, or
    call live RAG providers.

14. **Dashboard requests stay same-origin.** The dashboard must not load
    external scripts, styles, fonts, telemetry beacons, or provider URLs. It
    must consume same-origin API routes with fake demo credentials only.

---

## Credential Handling

### Current state

All credentials are environment variables. No credentials are hardcoded in
source code.

| Variable | Purpose | Current state |
|----------|---------|--------------|
| `DEMO_API_KEYS` | Demo API-key authentication | Fake demo keys in `.env.example` |
| `API_TOKEN` | Reserved for future auth modes | Not used |
| `OPENAI_API_KEY` | LLM provider | Not used (deterministic demo provider) |
| `VIRUSTOTAL_API_KEY` | Threat intelligence enrichment | Stub returns `not_configured` |
| `URLSCAN_API_KEY` | Threat intelligence enrichment | Stub returns `not_configured` |
| `ABUSEIPDB_API_KEY` | Threat intelligence enrichment | Stub returns `not_configured` |
| `PRODUCTION_IDENTITY_*` | Static production identity readiness and local fake-JWKS verifier shape | Empty or fake examples only; no live IdP/JWKS fetch |

### Rules

- `.env` files must never be committed. `.gitignore` must exclude them.
- `.env.example` contains only safe placeholder values (empty strings or fake
  demo keys).
- Demo API keys are fake and carry no authority outside the demo system.
- Future production token verifier tests must use fake local keys and fake JWKS
  fixtures. Raw JWTs, Authorization headers, real tenant IDs, real group IDs,
  and key material must not be logged or stored in audit events.
- When real API keys are added for threat intelligence integrations, they must
  be loaded from environment variables, never from code or config files.

---

## Data Classification

| Data type | Sensitivity | Handling |
|-----------|------------|---------|
| Raw SOAR payloads | Untrusted, potentially contaminated | Tokenized at intake before persistence |
| Case records (stored) | Contains tokenized content | Full records in SQLite JSON blobs; role-view masking at read time |
| Triage reports | Contains analyst-facing findings | Rehydrated only for `REHYDRATABLE_TYPES`; Stage 1 tokens stay redacted |
| Security telemetry (IPs, URLs, hashes) | Operational | Visible to analyst/engineer roles; masked for management/GRC/legal roles |
| PHI/PII tokens | Regulated risk | Permanently tokenized; no rehydration path; all roles see tokens only |
| Secret tokens | Critical | Permanently tokenized; display shows `[REDACTED_SECRET]` |
| Token vault mappings | Critical | In-memory only; never persisted or serialized to API responses |
| Audit events | Operational | Recorded for all security decisions; sanitized of raw credentials |
| CSI/RGOI cognitive objects | Demo operational cognition | Read-only retrieval; tenant-scoped; evidence-linked; AI cognition non-authoritative unless approved |
| Demo API keys | Low (fake) | Environment variables only; not valid outside demo system |
| Eval fixtures | Test data | Fake payloads only; path-sandboxed to `tests/evals/` |
| Third-party dataset derivatives | Reviewed external data | Sanitized derivatives only under `fixtures/curated_datasets/` (Synthea/deepset Apache-2.0, OTRF MIT lab telemetry); raw rows never committed (gitignored `external_datasets/`); accepted licenses enforced by an in-code allowlist, not the manifest; lab identifiers dropped by a fail-closed field allowlist |

---

## Secure Development Practices

### For contributors

- Run the full test suite (`pytest`) and eval harness
  (`python -m threatprism.evals.cli`) before submitting changes.
- Never add real organizational data, credentials, or PII to code, tests,
  examples, fixtures, or documentation.
- Use documentation IP ranges (e.g., `203.0.113.x`), reserved domains
  (e.g., `example.com`), and synthetic identifiers in demo data.
- Do not bypass guardrails in tests. Tests should verify that guardrails work,
  not work around them.
- When adding new inbound data paths, ensure Stage 1 healthcare safeguards run
  before persistence.
- When adding new output paths, ensure role-view masking applies before the
  response reaches the caller.
- When adding new eval categories, ensure eval artifacts do not contain raw
  sensitive values — use `_safe_preview()` or equivalent sanitization.

### Dependency policy

Current direct dependencies are minimal and exact-pinned in `requirements.txt`:

- `fastapi==0.115.12`
- `pydantic==2.11.2`
- `uvicorn==0.34.2`
- `pytest==8.2.0`
- `httpx==0.28.1`
- `cryptography==44.0.2`

`requirements-lock.txt` records the reviewed transitive versions used for local
validation. `tools/validate-threatprism.ps1` runs an advisory-only `pip-audit`
check when `pip-audit` is installed locally and skips it otherwise.

When adding dependencies:
- Prefer well-maintained, widely-used packages.
- Pin exact versions in `requirements.txt`.
- Review the dependency's security history before adopting it.
- Do not add dependencies that require network access unless explicitly approved.

---

## Pre-Production Hardening Checklist

Before ThreatPrism handles non-demo data, these items must be addressed:

- [x] Production token verifier implementation with fake-key tests,
  no-network validation, claim-to-role mapping, and sanitized audit coverage.
- [ ] Live production IdP integration (OAuth/OIDC discovery, live JWKS fetch,
  Entra ID).
- [ ] TLS termination (reverse proxy or direct).
- [ ] Edge or distributed rate limiting and durable queue backpressure beyond
  the current in-process POC controls.
- [ ] Database encryption at rest.
- [ ] Secrets management (Vault, Key Vault, or equivalent).
- [ ] Container hardening and deployment security review.
- [ ] Network-level access controls.
- [ ] CI/CD pipeline with security gates (dependency scanning, SAST).
- [ ] External security review or penetration test.
- [ ] Incident response plan for ThreatPrism itself.
- [ ] Logging and monitoring for the ThreatPrism service (not just case audit
  trails).
- [ ] Backup and recovery for the case database.
