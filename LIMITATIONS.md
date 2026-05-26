# Limitations

## Current Repository State

This workspace contains the V2 handoff brief, the companion spec prompt, the
spec pack documentation, and an initial first backend slice.

It does not currently contain a copied V1 source tree. V1 was reviewed read-only from `mwill20/threatprism` for comparison, but no V1 application source was modified here.

The canonical local workspace path is `C:\Projects\ThreatPrismV2`.

The original docs-only baseline is stale. Future work should trust the live
files and validation results over older chat summaries or leaked drafting/debug
text from previous final responses.

## Implemented Baseline

Current implemented baseline:

- FastAPI service.
- Case model code.
- SQLite persistence code.
- SOAR adapter code.
- In-process FastAPI background triage flow.
- LLM provider abstraction code.
- MITRE mapping code.
- GRC mapping code.
- Demo payload files.
- API and guardrail tests.
- Healthcare safeguard guardrails for context-aware potential PHI/ePHI, PII,
  secret, and security telemetry handling.
- Role-based rendering helpers for AI, analyst, engineer, manager/GRC,
  legal/privacy, and audit/debug views.
- Compliance-language scanner for HIPAA/HITRUST compliance, certification,
  audit-ready, control-satisfied, and evidence-proves-compliance claims.
- Demo API-key authentication for role-aware case and report reads.
- Identity-to-role authorization for role views.
- Safe authorization audit events for allow and deny decisions.
- Operational read models and metrics for dashboard-ready backend use.
- Safe detail routes for evidence, timeline, MITRE, GRC, and audit events.
- Local dry-run evaluation harness and regression defense fixtures.
- Production-like environments reject disabled auth and demo API-key auth.
- Safe local validation wrapper and fake-data-only CI workflow.
- Demo safety checks for environment posture, generated artifacts,
  secret-looking content, and eval artifact hygiene.
- Demo scenario pack for analyst, manager/GRC, legal/privacy, audit/debug, and
  engineer workflows.
- OpenAPI contract tests for the current backend route and response-model
  surface.
- Context-light startup file and compact handoff prompt generation tooling.
- Docker Compose local demo packaging for the existing fake-data FastAPI
  backend.
- Data source registry, local-only synthetic fixture factory, fixture models,
  sanitizers, validators, adapters, CLI entry point, and fixture-factory tests.

Validation command confirmed on 2026-05-25:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1 -BaseTemp .pytest_tmp_fixture_factory_validation_done
```

Result after Data Strategy & Synthetic Fixture Factory v0.1:

```text
73 passed
eval harness dry-run: 15 passed / 0 failed
```

If that exact base temp is locked on Windows, rerun with a fresh ignored base
temp such as `.pytest_tmp_run_verify`.

## Still Not Implemented Yet

- Real LLM provider calls.
- Full threat intelligence provider interfaces/stubs.
- Microsoft-specific production adapters.
- Dedicated async worker or external queue.
- Production-grade CI/CD release pipeline.
- Production authentication and authorization beyond demo API-key mode.
- Production deployment hardening.
- Frontend dashboard.
- An API compatibility policy beyond the current tested local route contract.

## Product Limitations

ThreatPrism V2 is not a production deployment yet.

It is designed as a production-style, demo-safe foundation that can be adapted toward production later with additional engineering, testing, deployment hardening, access control, and operational review.

The Architectural North Star is a directional guide, not a substitute for
implementation specs, decision records, limitations, tests, or validation
results. If implementation needs to move away from it, update the North Star
and decision records instead of allowing silent drift.

## AI Limitations

- AI output can be incomplete, incorrect, or overconfident.
- AI output must be treated as untrusted until schema, policy, and evidence-grounding checks pass.
- ThreatPrism does not determine final truth.
- Analyst review is required.
- Missing or incomplete evidence should lower confidence and appear in limitations.

## Action Limitations

ThreatPrism V2 does not execute real remediation or containment.

Blocked:

- Endpoint isolation.
- Account disablement.
- Firewall blocking.
- Email deletion.
- Token revocation.
- Production-impacting changes.

Allowed:

- Recommendations.
- Simulations.
- Dry-run action planning.

## SOAR Limitations

- Demo mode must not require live SOAR credentials.
- Parallel SOAR triage must not block incident response.
- Callback posting is optional and should be implemented only after safe intake and reporting are stable.

## Threat Intelligence Limitations

- VirusTotal, URLScan.io, AbuseIPDB, and WHOIS/RDAP are specified as interfaces or stubs for early implementation.
- Missing keys must return `not_configured`.
- Enrichment results should not be treated as definitive without analyst review.
- The safe validation wrapper clears live enrichment credential variables for
  validation. It does not test live enrichment behavior.

## GRC Limitations

ThreatPrism provides HITRUST-aligned control category mapping only.

It does not provide:

- HIPAA compliance.
- HIPAA certification.
- HITRUST compliance.
- HITRUST certification.
- Licensed HITRUST control implementation.
- Audit opinion.

Mappings are evidence organization aids and require review.

## Healthcare Safeguard Limitations

ThreatPrism assumes SOAR payloads should not contain raw PHI or ePHI, but it
does not trust that assumption as a control.

ThreatPrism must inspect inbound payloads for accidental regulated-data
contamination before persistence, model-visible payload creation, report
rendering, or role-based display.

ThreatPrism does not classify every identifier as PHI/ePHI. Identifiers become
PHI/ePHI risk when connected to health, patient, care, billing, encounter, or
other reasonably identifying context.

The healthcare safeguard guardrails are not a legal determination,
de-identification certification, HIPAA compliance claim, HITRUST certification,
or audit opinion.

Role-based views are protected by demo API-key authorization when
`API_AUTH_MODE=demo_key`. This is not a production access-control boundary or
IdP integration.

Operational metrics and read models are demo-safe backend responses. They are
not a production monitoring, SIEM export, BI/data-warehouse, or compliance
reporting implementation.

The eval harness and CI workflow are deterministic regression gates. They do
not prove live-LLM safety, production readiness, HIPAA compliance, HITRUST
certification, or audit readiness.

The compact handoff prompt is an operator aid, not an automatic context-window
sensor. Agents should use it proactively around the 75% context-used threshold,
and the user can run the command manually when needed.

## Demo Data Limitations

- Demo data must be fake.
- Do not include real tenant IDs, workplace names, customer names, users, hosts, domains, IPs, secrets, or operational details.
- Use reserved domains, documentation IP ranges, and synthetic identifiers where possible.

## Dataset Strategy Limitations

ThreatPrism includes a local-only synthetic fixture factory. It is not a
dataset ingestion pipeline, download manager, runtime data model, or approval
mechanism for third-party data.

Planned public or synthetic dataset use is limited to reviewed source material
for generating sanitized ThreatPrism-native synthetic fixtures. Public datasets
are not runtime data models.

Current dataset boundaries:

- No automatic dataset downloads.
- No committed raw third-party datasets.
- Generated fixtures under `fixtures/generated/` are ignored by git unless a
  tiny curated sample is intentionally promoted in a future reviewed change.
- The eval harness and tests do not auto-scan ignored generated fixture
  folders.
- No production telemetry.
- No real healthcare records.
- No real workplace, customer, tenant, user, host, domain, IP, or secret data.
- No raw prompt-injection or jailbreak samples in public-facing docs or logs.
- No Caldera execution or adversary emulation lab setup without explicit
  future approval.
- No model training or fine-tuning.

The user must manually review dataset license terms, redistribution rules,
attribution requirements, safety constraints, and whether derivative fixtures
can be committed before any source sample is used.

## Docker Packaging Limitations

The Docker Compose packaging is local-demo packaging only.

Current boundaries:

- One FastAPI backend service.
- SQLite demo persistence through a named Docker volume.
- Fake demo API keys only.
- Empty live-provider credential variables.
- No dashboard UI.
- No PostgreSQL, Redis, worker, production IdP, live LLM, live SOAR, live
  enrichment, or remediation profile.

Any production-style packaging profile must re-open the relevant threat-model
treatments before implementation.

## Repository Readiness Limitations

The repo-standards readiness pass improves reviewer entry points and documents
the current validation posture, but it does not make ThreatPrism production
ready.

Known repository-readiness gaps:

- No `LICENSE` file has been selected. Usage rights are unclear until the user
  chooses and adds a license.
- No tracked screenshot, GIF, or rendered architecture image exists yet. Text
  diagrams are available in docs, but dashboard UI is still out of scope.
- Production deployment, live provider operation, production identity,
  monitoring, and remediation remain gated future work.
- Performance, latency, throughput, and load behavior are not yet measured.

## Known Open Items

- Selectively port additional V1 concepts where useful; do not full-copy V1.
- Decide how much V1 CLI behavior is directly preserved versus wrapped around the new case model.
- Decide whether any generated fixture should be manually curated and promoted
  into tracked tests or eval fixtures after license and safety review.
- Decide exact authentication, authorization, and future break-glass governance
  before exposing real case data or raw sensitive values.
- Keep `docs/ARCHITECTURAL_NORTH_STAR.md` updated when future workarounds or
  enhancements intentionally change architecture direction.
