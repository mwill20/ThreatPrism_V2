# 13 Acceptance Criteria

## Spec Pack Acceptance Criteria

- `docs/specs/00_VISION.md` through `docs/specs/14_DEMO_PLAN.md` exist.
- `AGENTS.md`, `DECISIONS.md`, and `LIMITATIONS.md` exist.
- Specs define the product as ThreatPrism.
- Specs frame ThreatPrism as a production-style, demo-safe SOC migration accelerator.
- Specs do not mention real employer, healthcare organization, or specific workplace names.
- Specs do not implement application code.
- Specs include concrete API payload examples.
- Specs include case model fields.
- Specs include triage report schema.
- Specs include analyst feedback fields.
- Specs include acceptance criteria.
- Handoff decisions override old README assumptions.

Status: complete. The repository now also includes an initial backend slice, so
these criteria should not be read as the current project boundary.

## First Foundation Acceptance Criteria

By the end of the first serious V2 foundation:

1. Original V1 is preserved elsewhere.
2. V2 work occurs only in the new project.
3. Clear V2 spec pack exists.
4. CLI remains usable or is clearly migrated.
5. FastAPI service exposes core routes.
6. Async or background triage pattern exists.
7. Demo SOAR payload ingestion works.
8. Provider-agnostic data normalization exists.
9. Microsoft-friendly integration structure exists.
10. Threat intel enrichment interfaces or stubs exist.
11. WHOIS/RDAP, VirusTotal, URLScan.io, and AbuseIPDB provider interfaces exist.
12. MITRE mapping support exists.
13. Case model exists.
14. Analyst feedback and disagreement tracking exists.
15. HITRUST-aligned GRC mapping exists.
16. Guardrails and eval harness exist.
17. Dry-run-only action adapter scaffolding exists.
18. Docker Compose exists.
19. `.env.example` exists.
20. CI/CD workflow exists.
21. Documentation is updated.
22. Clear limitations and next steps are documented.

## API Acceptance Criteria

Core routes:

- `GET /health` returns status, service name, version, mode, and `allow_real_actions`.
- `POST /cases` accepts a generic SOAR payload and returns `case_id`, `tracking_id`, and `triage_status`.
- `GET /cases` returns compatibility case summaries.
- `GET /cases/read-model` returns the dashboard-ready filtered envelope.
- `GET /cases/{case_id}` returns normalized case data.
- `GET /cases/{case_id}/triage-report` returns the latest validated report or a structured not-ready status.
- `POST /cases/{case_id}/analyst-feedback` records analyst feedback and returns disagreement indicators.
- `GET /metrics` has a stable aggregate response shape before dashboard work starts.
- Future detail routes for evidence, timeline, IOC enrichment, MITRE mappings, and GRC mappings return evidence-linked records.
- `POST /evals/run` can run in dry-run or fixture mode without live LLM credentials once implemented.

## Triage Report Acceptance Criteria

Each completed report includes:

- Summary.
- Determination.
- Severity.
- Disposition.
- Confidence.
- Evidence.
- Timeline.
- IOCs.
- MITRE ATT&CK mapping.
- Hypotheses.
- Recommended analyst actions.
- Simulated response actions if applicable.
- HITRUST-aligned GRC control categories.
- Limitations.
- Analyst review required statement.

## Security Acceptance Criteria

- `ALLOW_REAL_ACTIONS=false` by default.
- Real actions cannot execute.
- Prompt-injection text is flagged, sanitized, or quarantined.
- AI output is schema-validated.
- Unsupported claims are blocked or marked for review.
- Every material claim cites evidence.
- Raw secrets are not logged.
- Demo payloads are fake.
- Demo unauthenticated API mode is limited to localhost and fake data.
- Production-style use requires authentication and authorization before exposing case data.

## Evaluation Harness Acceptance Criteria

Status: implemented.

- Fake JSONL eval fixtures cover prompt injection, hallucinated claims, unsafe
  action claims, schema failures, evidence citation failures, healthcare
  leakage, authorization escalation, cross-role leakage, read-model leakage,
  audit leakage, token-vault mapping exposure, compliance overclaims, malformed
  JSON, oversized payloads, and conflicting evidence.
- Eval harness runs without live LLM credentials, live SOAR calls, cloud calls,
  or enrichment calls.
- Eval artifacts are written only under `.eval_runs/`.
- Eval fixture reads are restricted to `tests/evals/`.
- Eval artifacts contain sanitized previews, not raw potential PHI/ePHI,
  secrets, credentials, raw payload bodies, or token vault mappings.
- Malformed fixtures fail safely.

## Healthcare Safeguard Acceptance Criteria

- SOAR payloads are expected to be security-only, but all inbound payloads are
  inspected as potentially contaminated.
- ThreatPrism does not classify every identifier as PHI/ePHI by itself.
- Identifiers tied to health, patient, care, billing, encounter, or other
  reasonably identifying context are treated as possible PHI/ePHI exposure.
- Potential PHI/ePHI is replaced with typed tokens before model-visible payload
  creation.
- Raw potential PHI/ePHI does not appear in reports, logs, manager/GRC views, or
  audit/debug views.
- Security telemetry remains usable for SOC response through controlled
  role-based rendering.
- Secrets are never rehydrated.
- Compliance/certification/audit-ready claims are blocked.
- Audit events are recorded for tokenization, rehydration approval or denial,
  guardrail blocks, and report validation.

## Operational Read Models And Metrics Acceptance Criteria

Status: implemented.

- `GET /metrics` returns case, triage, guardrail, healthcare safeguard,
  disagreement, timing, and GRC aggregates.
- Case-list responses support dashboard-useful filtering or a documented
  companion envelope route.
- Manager-review cases can be queried through `GET /queues/manager-review`
  without exposing raw sensitive values.
- Healthcare-review cases can be queried through `GET /queues/healthcare-review`
  with exposure metadata and review flags, not raw potential PHI/ePHI.
- Evidence, timeline, MITRE, GRC, and audit detail routes return stable JSON
  shapes.
- Role-aware read routes apply role-safe rendering consistently.
- Metrics and audit/debug responses do not expose raw potential PHI/ePHI,
  secrets, credentials, or token vault mappings.
- GRC detail responses cite evidence IDs and avoid compliance/certification
  claims.
- Tests cover aggregation, filtering, manager-review queue behavior,
  healthcare-review queue behavior, detail routes, role-safe rendering, and
  sensitive-value non-leakage.

## Access Control And Audit Integrity Acceptance Criteria

- Demo authentication maps fake/demo credentials to a caller identity and
  effective role.
- Missing or unknown credentials are denied when demo auth is enabled.
- `?role=` is not trusted as authority outside explicit demo/test override
  behavior.
- Role escalation attempts fail closed.
- Analyst and engineer views are not available to manager/GRC callers.
- Manager/GRC, legal/privacy, audit/debug, and AI views remain masked or
  tokenized according to role policy.
- Authorization allow decisions create audit events.
- Authorization deny decisions create audit events.
- Authorization audit events include caller identity, requested role,
  effective role, endpoint, decision, reason, timestamp, and case/report ID
  when available.
- Authorization audit events do not include raw potential PHI/ePHI, secrets,
  full credentials, raw request bodies, or token vault mappings.
- Existing healthcare safeguard leakage tests still pass.

## GRC Acceptance Criteria

- GRC mapping is category-level only.
- Output uses HITRUST-aligned language only.
- No compliance or certification claim is present.
- HIPAA Security Rule references are framed as safeguard themes or evidence
  alignment only.
- Each mapping cites evidence.
- Analyst or GRC review is required.

## Demo Acceptance Criteria

- Demo does not require live SOAR credentials.
- Demo does not require real enrichment API keys.
- Demo can run with fake payloads.
- Missing enrichment keys return `not_configured`.
- Reports clearly state analyst review is required.
