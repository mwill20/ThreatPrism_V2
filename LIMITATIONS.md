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

Validation command confirmed on 2026-05-22:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_healthcare3
```

Result:

```text
22 passed
```

If that exact base temp is locked on Windows, rerun with a fresh ignored base
temp such as `.pytest_tmp_run_verify`.

## Still Not Implemented Yet

- Real LLM provider calls.
- Full threat intelligence provider interfaces/stubs.
- Microsoft-specific production adapters.
- Dedicated async worker or external queue.
- Evaluation harness.
- Docker Compose.
- CI/CD.
- Authentication and authorization beyond demo-mode settings.
- Production deployment hardening.
- Operational metrics/read-model APIs for dashboard-ready manager, GRC,
  legal/privacy, engineer, and audit views.

## Product Limitations

ThreatPrism V2 is not a production deployment yet.

It is designed as a production-style, demo-safe foundation that can be adapted toward production later with additional engineering, testing, deployment hardening, access control, and operational review.

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

## Demo Data Limitations

- Demo data must be fake.
- Do not include real tenant IDs, workplace names, customer names, users, hosts, domains, IPs, secrets, or operational details.
- Use reserved domains, documentation IP ranges, and synthetic identifiers where possible.

## Known Open Items

- Selectively port additional V1 concepts where useful; do not full-copy V1.
- Decide how much V1 CLI behavior is directly preserved versus wrapped around the new case model.
- Implement Operational Read Models & Metrics API v0.1 before building any
  frontend dashboard.
- Decide exact authentication, authorization, and future break-glass governance
  before exposing real case data or raw sensitive values.
