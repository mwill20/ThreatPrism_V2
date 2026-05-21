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
- `GET /cases` returns paginated case summaries.
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

## GRC Acceptance Criteria

- GRC mapping is category-level only.
- Output uses HITRUST-aligned language only.
- No compliance or certification claim is present.
- Each mapping cites evidence.
- Analyst or GRC review is required.

## Demo Acceptance Criteria

- Demo does not require live SOAR credentials.
- Demo does not require real enrichment API keys.
- Demo can run with fake payloads.
- Missing enrichment keys return `not_configured`.
- Reports clearly state analyst review is required.
