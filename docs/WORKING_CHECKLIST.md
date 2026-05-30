# ThreatPrism Working Checklist

Use this checklist to keep current work aligned with the live repository state.
Trust files and validation results over older chat summaries.

## Current Truths

- [x] Product name is `ThreatPrism`.
- [x] Canonical local path is `C:\Projects\ThreatPrismV2`.
- [x] Destination repository is `mwill20/ThreatPrism_V2`.
- [x] V2 uses a clean architecture with selective V1 concept porting.
- [x] Do not full-copy V1 into this repository.
- [x] Demo data must stay fake.
- [x] Real remediation remains disabled by default with `ALLOW_REAL_ACTIONS=false`.
- [x] HITRUST language is category/alignment mapping only, not compliance or certification.
- [x] The original docs-only baseline is stale; implementation has begun.
- [x] The previous final response leaked drafting/debug text; trust files and validation results instead.
- [x] `docs/ARCHITECTURAL_NORTH_STAR.md` is the directional architecture guide
  for new slices, workarounds, and major enhancements.
- [x] `START_HERE.md` is the context-light entry point for new chats.
- [x] `Lessons/00_Index.md` is the learning curriculum entry point for the
  implemented backend, guardrail, persistence, and testing slices.
- [x] Every implementation slice must close with docs, README, checklist,
  handoff, limitations/decisions as needed, lessons, and current validation
  updates.

## Active Target

The first ThreatPrism backend slice is complete:

- [x] Generic SOAR webhook payload intake.
- [x] Case normalization.
- [x] Prompt firewall, sanitization, and tokenization before model processing.
- [x] Deterministic demo LLM provider.
- [x] Structured triage report schema.
- [x] Output policy, evidence-grounding, and action-safety checks.
- [x] Controlled rehydration after validation.
- [x] Deterministic report rendering.
- [x] SQLite demo persistence.
- [x] FastAPI endpoints for health, cases, triage report, and analyst feedback.
- [x] Analyst feedback and disagreement tracking.
- [x] Fake SOAR demo payloads.
- [x] Initial API and guardrail tests.

## Immediate Next Checklist

- [x] Initialize or sync `C:\Projects\ThreatPrismV2` as the local checkout for `mwill20/ThreatPrism_V2`.
- [x] Commit and push the current validated baseline to `main`.
- [x] Add a dedicated Architectural North Star so future slices stay aligned.
- [x] Add or update a user-facing `README.md` with setup, validation, and demo workflow.
- [x] Add a lesson curriculum for the implemented project slices before
  continuing new application code.
- [x] Add a concise local runbook for starting the FastAPI service.
- [x] Review docs/specs against the implemented slice and remove remaining stale no-code wording.
- [x] Add targeted tests for guardrail-blocked triage output.
- [x] Add targeted tests for unsupported evidence IDs in generated reports.
- [x] Add targeted tests that real actions fail closed if a report claims `real_action_executed=true`.
- [x] Add threat intelligence stub interfaces that return structured `not_configured` results.
- [x] Add Microsoft-friendly adapter examples without hardwiring Microsoft into the core model.
- [x] Decide whether the next async step stays with in-process FastAPI background tasks or moves to a worker/queue.
- [x] Decide the demo API auth model before using anything beyond fake demo data.

## Completed Slice

Healthcare Safeguard & Evidence Alignment Guardrails v0.1:

- [x] Add spec for context-aware healthcare safeguard guardrails.
- [x] Add top-level healthcare safeguard guardrail doc.
- [x] Record decision that identifiers are not PHI/ePHI by themselves.
- [x] Record decision to use safeguard/evidence-alignment language, not
  compliance-certification language.
- [x] Implement context-aware detector taxonomy for potential PHI/ePHI, PII,
  secrets, and security telemetry.
- [x] Add typed replacement tokens such as `[POTENTIAL_PHI:MRN:phi_0001]` and
  `[SECRET:API_KEY:secret_0001]`.
- [x] Add pre-persistence scanning before model-visible payload creation,
  report rendering, logging, or role-based display.
- [x] Add role-based rendering policies for AI, analyst, engineer, manager/GRC,
  legal/privacy, and audit/debug views.
- [x] Add compliance-language scanner for HIPAA/HITRUST compliance,
  certification, audit-ready, control-satisfied, and evidence-proves-compliance
  claims.
- [x] Record audit events for tokenization, rehydration approval or denial,
  guardrail blocks, role-view policy application, and report validation.
- [x] Add fake fixtures for potential PHI/ePHI contamination, normal security
  telemetry, PII, and secrets.
- [x] Add tests proving raw potential PHI/ePHI does not appear in model-visible
  payloads, reports, logs, manager/GRC views, or audit/debug views.
- [x] Add tests proving security telemetry remains usable for analyst/engineer
  response when it is not tied to health context.
- [x] Add tests proving secrets are never rehydrated.
- [x] Add tests proving compliance/certification/audit-ready claims are blocked.
- [x] Add tests proving GRC mappings still cite evidence IDs.

## Completed Slice

Operational Read Models & Metrics API v0.1:

- [x] Add implementation-ready spec for operational read models and metrics.
- [x] Add Pydantic response models for metrics, case-list envelopes, detail
  route envelopes, and safe audit summaries.
- [x] Add `GET /metrics` with case, triage, guardrail, healthcare safeguard,
  disagreement, timing, and GRC aggregates.
- [x] Add dashboard-ready case list filtering for source, status,
  triage_status, severity, determination, manager review, healthcare review,
  guardrail block, and created time windows.
- [x] Add dedicated manager-review queue route: `GET /queues/manager-review`.
- [x] Add dedicated healthcare-review queue route:
  `GET /queues/healthcare-review`.
- [x] Add detail routes for evidence, timeline, MITRE mappings, GRC mappings,
  and audit events.
- [x] Apply role-safe rendering to detail/read-model routes where case content
  or security telemetry can appear.
- [x] Ensure metrics and read-model routes never expose raw potential PHI/ePHI,
  secrets, or token vault mappings.
- [x] Add tests for metrics aggregation, filtering, manager-review queue,
  healthcare-review queue, detail routes, role-safe views, and no sensitive
  value leakage.
- [x] Keep `ALLOW_REAL_ACTIONS=false`, fake fixtures only, and no live LLM,
  SOAR, enrichment, cloud, or remediation calls.

Implemented as `GET /cases/read-model` to preserve the existing compatibility
`GET /cases` list response.

## Completed Slice

Access Control & Audit Integrity v0.1:

- [x] Check `docs/ARCHITECTURAL_NORTH_STAR.md` before implementation and record
  any intentional architecture changes in `DECISIONS.md`.
- [x] Document why this slice supersedes metrics/read models as the next
  implementation target.
- [x] Add implementation-ready spec for demo authentication, authorization,
  and audit integrity.
- [x] Add demo authentication middleware or dependency using fake/demo
  credentials only.
- [x] Map authenticated callers to effective roles.
- [x] Stop treating `?role=` as authority outside explicit demo/test override
  behavior.
- [x] Deny role escalation attempts and fail closed for missing, unknown, or
  unauthorized roles.
- [x] Harden role-view policy so manager/GRC, legal/privacy, audit/debug, and
  AI views cannot receive analyst/engineer-only data.
- [x] Record authorization audit events for allow and deny decisions.
- [x] Ensure authorization audit events include caller identity, requested role,
  effective role, endpoint, case/report ID, decision, reason, timestamp, and a
  redacted request metadata hash.
- [x] Ensure authorization audit events never store raw potential PHI/ePHI,
  secrets, full credentials, raw payload bodies, or token vault mappings.
- [x] Add tests for unauthenticated denial when demo auth is enabled.
- [x] Add tests proving manager/GRC cannot force analyst or engineer views.
- [x] Add tests proving invalid role escalation fails closed.
- [x] Add tests proving allow and deny decisions create audit events.
- [x] Add tests proving healthcare leakage protections still pass.
- [x] Keep `ALLOW_REAL_ACTIONS=false`, fake fixtures only, and no live LLM,
  SOAR, enrichment, cloud, dashboard, production IdP, or remediation work.

## Completed Slice

Evaluation Harness & Regression Defense Labs v0.1 is complete:

- [x] Re-check `docs/ARCHITECTURAL_NORTH_STAR.md` before implementation.
- [x] Add fake JSONL eval fixtures for prompt injection, hallucinated claims,
  unsafe action claims, schema violations, evidence citation failures,
  healthcare safeguard leakage, authorization escalation, and benign/suspicious
  ambiguity.
- [x] Add additional eval coverage for compliance overclaiming, cross-role
  leakage, read-model leakage, audit leakage, token-vault mapping exposure,
  oversized payload handling, malformed JSON, and conflicting evidence.
- [x] Add a dry-run eval harness that uses the deterministic demo provider or
  controlled fake providers only.
- [x] Add structured eval result models with pass/fail counts, category counts,
  failure reasons, and safe artifact paths.
- [x] Add a local API or CLI entry point for eval execution only if it remains
  fake-data and no-live-provider safe.
- [x] Ensure eval outputs do not expose raw potential PHI/ePHI, secrets,
  credentials, raw payload bodies, or token vault mappings.
- [x] Add tests proving eval failures are visible and real remediation remains
  disabled.
- [x] Reject fixture and output path traversal.
- [x] Reject disabled or demo auth in production-like environments.
- [x] Update docs, README, lessons, checklist, handoff, limitations, and
  validation notes when complete.

## Completed Slice

Demo Operations & CI Hardening v0.1 is complete:

- [x] Re-check `docs/ARCHITECTURAL_NORTH_STAR.md` before implementation.
- [x] Add safe local validation script around the known-good pytest command:
  `tools/validate-threatprism.ps1`.
- [x] Add demo safety checker for environment posture, `.env.example`,
  generated artifacts, secret-looking content, runtime guard behavior, and eval
  artifact hygiene.
- [x] Add lightweight CI that avoids live credentials and runs fake-data tests
  only.
- [x] Run the eval harness in deterministic dry-run mode in CI.
- [x] Add demo/runbook hardening for API startup, SOAR intake, metrics, review
  queues, and eval workflows.
- [x] Ensure generated artifacts stay ignored and sanitized.
- [x] Keep live LLM, live SOAR, cloud/enrichment calls, dashboard UI,
  production IdP, and remediation out of scope.
- [x] Update docs, README, lessons, checklist, handoff, limitations, and
  validation notes when complete.

## Completed Slice

Demo Scenario Pack & API Contract Freeze v0.1 is complete:

- [x] Re-check `docs/ARCHITECTURAL_NORTH_STAR.md` before implementation.
- [x] Keep fake/demo data only.
- [x] Add repeatable fake demo scenarios for analyst, manager/GRC,
  legal/privacy, audit/debug, and engineering views.
- [x] Confirm OpenAPI/API response contracts for current backend routes.
- [x] Add smoke-testable demo instructions using fake payloads only.
- [x] Keep dashboard UI, live providers, production IdP, and remediation out of
  scope unless explicitly requested.
- [x] Update docs, README, lessons, checklist, handoff, limitations, and
  validation notes when complete.

Implemented with typed scenario-pack loading under `src/threatprism/demo/`,
scenario artifacts under `examples/demo_scenarios/`, and OpenAPI/smoke tests in
`tests/test_demo_scenarios_and_api_contract.py`.

## Completed Slice

Threat Model Pack v0.1 is complete:

- [x] Add `docs/threat-models/README.md` as the index for the threat model
  pack.
- [x] Document current system assets, users, trust boundaries, data flows,
  integrations, assumptions, and security objectives.
- [x] Add STRIDE coverage for spoofing, tampering, repudiation, information
  disclosure, denial of service, and elevation of privilege.
- [x] Add LLM/agent threat coverage for prompt injection, tool abuse, RAG
  poisoning, unsafe memory writes, over-permissive retrieval, hallucinated
  evidence, untrusted webhook input, and cross-tenant leakage.
- [x] Add healthcare data threat coverage for PHI/PII exposure, minimum
  necessary access, role-view bypass, audit logging, sensitive evidence
  persistence, and compliance-language overclaiming.
- [x] Add mitigation traceability from threat to guardrail to current or
  proposed test file.
- [x] Keep this slice documentation-only with no runtime security logic changes.
- [x] Use this pack before memory, RAG, write-back, multi-tenancy, dashboard UI,
  live provider, or production identity work.
- [x] Validate after the documentation slice with
  `powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
  -BaseTemp .pytest_tmp_run_threat_model_pack`.

Original documentation-slice validation result:

```text
48 passed
eval harness dry-run: 15 passed / 0 failed
```

## Active Draft / Follow-Up

Threat Model Pack v0.2 and Treatment Register follow-up:

- [x] Add v0.2 threat-model refresh with severity, residual risk, open threat,
  and traceability tables.
- [x] Add draft treatment register in
  `docs/specs/21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md`.
- [x] Record POC owner decision pass in the treatment register.
- [x] Implement Slice G quarantine enforcement so prompt-firewall quarantine
  records block provider execution before triage generation.
- [x] Add `tests/test_quarantine_enforcement.py` for provider-call blocking and
  prompt-firewall blocker messaging.
- [x] Implement Slice D test gap closure:
  `tests/test_token_vault_isolation.py` and
  `tests/test_stage1_no_rehydration.py`.
- [x] Implement Slice A auth hardening:
  fail-closed demo keys, explicit local-dev ack for disabled auth, and startup
  warnings.
- [x] Implement Slice B HTTP DoS protection:
  request body cap, in-process rate limit, and triage concurrency cap.
- [x] Implement Slice F pattern refresh process:
  quarterly runbook, overclaim fixture catalog, healthcare detector fixtures,
  and `potential_sensitive_data_exposure` operator semantics.
- [x] Implement Slice E dependency hardening:
  exact direct pins, transitive lock file, safety-check pin validation, and
  advisory dependency-audit hook.
- [x] Add `Lessons/Lesson15_Threat_Model_Treatment_And_Demo_Hardening.md` and
  index coverage for the threat treatment and demo hardening slice.
- [ ] Gated mitigations for real LLM, RAG, memory/write-back, tools,
  multi-tenancy, fine-tuning, non-demo data, and real PHI remain out of scope
  until explicitly requested.
- [x] First pattern refresh review is scheduled for 2026-08-24.

Validation after owner pass and Slices A, B, D, E, F, and G:

```text
63 passed
eval harness dry-run: 15 passed / 0 failed
```

## Completed Slice

Docker Compose & Local Demo Packaging v0.1 is complete:

- [x] Re-check `docs/ARCHITECTURAL_NORTH_STAR.md` before implementation.
- [x] Add a Dockerfile for the existing fake-data FastAPI backend.
- [x] Add Docker Compose local demo startup with a single backend service.
- [x] Preserve demo-safe defaults: fake demo API keys, deterministic provider,
  SQLite demo persistence, and `ALLOW_REAL_ACTIONS=false`.
- [x] Keep live providers, production IdP, PostgreSQL, Redis, dashboard UI,
  workers, and remediation out of scope.
- [x] Add `.dockerignore` coverage for `.env`, generated artifacts, local
  databases, pytest temp files, ignored dataset staging, and git metadata.
- [x] Add tests for the Dockerfile, Compose file, and Docker ignore safety
  boundary.
- [x] Update docs, README, runbook, lessons, checklist, handoff, decisions, and
  limitations.

Implemented with `Dockerfile`, `docker-compose.yml`, `.dockerignore`,
`tests/test_docker_packaging.py`,
`docs/DOCKER_COMPOSE_LOCAL_DEMO_PACKAGING.md`, and
`docs/specs/22_DOCKER_COMPOSE_LOCAL_DEMO_PACKAGING.md`.

## Completed Slice

Data Strategy & Synthetic Fixture Factory v0.1 is complete:

- [x] Re-check `docs/ARCHITECTURAL_NORTH_STAR.md` before implementation.
- [x] Add `data_sources/registry.json` with review-required, no-download,
  no-raw-commit defaults.
- [x] Add ignored `external_datasets/` staging with README and `.gitkeep`.
- [x] Add ignored `fixtures/generated/` output with `.gitkeep`.
- [x] Add `tools/fixture_factory/` models, sanitizers, validators, adapters,
  and CLI entry point.
- [x] Reuse existing ThreatPrism schemas and guardrails where practical.
- [x] Keep generated fixtures ThreatPrism-native rather than adding a second
  runtime data model.
- [x] Enforce deterministic fixture IDs, sorted fixture ordering, sorted JSON,
  and no unseeded randomness.
- [x] Enforce input paths under `external_datasets/` and output paths under
  `fixtures/generated/`.
- [x] Reject path traversal, absolute escapes, unsafe extensions, and
  overwrite attempts unless `--force` is explicit.
- [x] Keep adapters local-only with no downloads or network calls.
- [x] Add tests for registry metadata, fixture models, sanitizer behavior,
  adapters, CLI behavior, path safety, deterministic output, no-network
  behavior, schema validity, and no sensitive data leakage.
- [x] Update docs, README, runbook, checklist, handoff, decisions,
  limitations, lessons, `.gitignore`, and `.dockerignore`.
- [x] Validate with
  `powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
  -BaseTemp .pytest_tmp_fixture_factory_validation_done`.

Implemented with `data_sources/registry.json`, `external_datasets/README.md`,
`fixtures/generated/.gitkeep`, `tools/fixture_factory/`, and
`tests/test_fixture_factory.py`.

## Completed Slice

Repo Standards Readiness Pass v0.1:

- [x] Run an audit-first repository standards pass in documentation-fix mode.
- [x] Create `REPO_AUDIT.md` with strengths, gaps, scorecard, priority order,
  and remaining reviewer-readiness risks.
- [x] Add reviewer-focused entry points for usage, evaluation, dataset
  handling, model/provider behavior, deployment boundary, monitoring, and
  troubleshooting.
- [x] Add root-level `CONTRIBUTING.md` and `CHANGELOG.md`.
- [x] Update README with purpose, audience, project status, requirements,
  documentation map, evaluation summary, license status, and support path.
- [x] Keep the pass documentation-only; no app-code changes, live providers,
  real credentials, real data, or remediation work.
- [x] Leave license selection explicit and unresolved until the user chooses a
  license.
- [x] Validate with
  `powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
  -BaseTemp .pytest_tmp_repo_standards_final_fresh`.

## Completed Slice

Cognitive Security Infrastructure (CSI) and Retrieval-Governed Organizational
Intelligence (RGOI) Foundation v0.1:

- [x] Re-check `docs/ARCHITECTURAL_NORTH_STAR.md` before implementation.
- [x] Read the CSI/RGOI source specs under `CSI/`.
- [x] Add `src/threatprism/csi/` schemas, governance controls, trust scoring,
  evidence alignment validation, and read-only retrieval service.
- [x] Implement four-tier cognitive architecture scaffolding: immutable
  evidence, structured intelligence, approved knowledge, and ephemeral
  cognitive workspace.
- [x] Add cognitive object metadata for tenant namespace, provenance, evidence
  references, lineage, retrieval zone, validation state, lifecycle state,
  review status, trust, confidence, and competing interpretations.
- [x] Enforce read-only retrieval: no write APIs, no trust mutation, no
  autonomous knowledge approval, no suppression publication, and no
  remediation.
- [x] Add retrieval governance for tenant namespace, role/purpose policy,
  retrieval-zone policy, trust threshold, stale cognition, and quarantine
  exclusion.
- [x] Add evidence citation enforcement, unsupported claim rejection,
  prompt-injection checks, and healthcare safeguard scanning for cognitive
  objects.
- [x] Add lineage graph, replay scaffolding, observability snapshot, and
  AI-vs-human divergence telemetry routes.
- [x] Preserve competing interpretations and mark AI-authored cognition
  non-authoritative unless human approved.
- [x] Add fake demo fixtures under `examples/csi/` with no real organization,
  tenant, workplace, user, host, domain, IP, PHI, PII, or secret data.
- [x] Add tests for tenant isolation, RBAC/ABAC-style retrieval policy,
  evidence alignment, trust scoring, quarantine exclusion, stale cognition,
  lineage, replay, observability, divergence, demo auth, and OpenAPI routes.
- [x] Update docs, specs, threat model, workflows, README, handoff,
  limitations, decisions, lessons, and checklist.
- [x] Validate with
  `powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
  -BaseTemp .pytest_tmp_csi_final_validation`.

## Completed Slice

Dashboard UI Preparation v0.1:

- [x] Re-check `docs/ARCHITECTURAL_NORTH_STAR.md` before implementation.
- [x] Keep this slice backend-contract only; do not implement frontend UI.
- [x] Add `docs/DASHBOARD_DATA_CONTRACT.md` for exact API surfaces a future
  UI can consume.
- [x] Add `docs/specs/24_DASHBOARD_UI_PREPARATION.md`.
- [x] Add `docs/runbooks/DASHBOARD_READINESS.md` with fake demo credential
  examples and route checks.
- [x] Add fake sample response fixtures for analyst, manager/GRC,
  legal/privacy, audit/debug, engineer, and CSI/RGOI views under
  `examples/dashboard_contract/`.
- [x] Add route and response contract tests for CSI/RGOI endpoints alongside
  the existing API contract freeze.
- [x] Ensure fixtures remain fake-data only and do not contain real
  organization, workplace, tenant, user, host, domain, IP, PHI, PII, secrets,
  raw payloads, or token vault mappings.
- [x] Update README, checklist, handoff, limitations, lessons, and validation
  notes.
- [x] Validate with
  `powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
  -BaseTemp .pytest_tmp_dashboard_prep_final_validation`.

## Completed Slice

Dashboard UI Implementation v0.1:

- [x] Re-check `docs/ARCHITECTURAL_NORTH_STAR.md` before implementation.
- [x] Build the UI against `docs/DASHBOARD_DATA_CONTRACT.md`.
- [x] Add same-origin FastAPI route `GET /dashboard`.
- [x] Add dependency-free static assets under
  `src/threatprism/dashboard/static/`.
- [x] Use fake demo credentials only.
- [x] Keep `ALLOW_REAL_ACTIONS=false`.
- [x] Add persona views for analyst, manager/GRC, legal/privacy, audit/debug,
  engineer, and CSI/RGOI.
- [x] Add frontend/unit/contract tests in `tests/test_dashboard_ui.py`.
- [x] Start the local app and use the Browser workflow to verify desktop,
  mobile, and role-specific views.
- [x] Fix optional detail-panel degradation found during Browser verification.
- [x] Run `tools/validate-threatprism.ps1` with
  `-BaseTemp .pytest_tmp_dashboard_ui_final_validation2`.
- [x] Run repo-standards cleanup pass.

## Completed Slice

Production Dashboard Hardening v0.1:

- [x] Re-check `docs/ARCHITECTURAL_NORTH_STAR.md` before implementation.
- [x] Keep this as dashboard hardening only; do not add live production IdP,
  live providers, real data, production deployment, external telemetry, or
  remediation.
- [x] Add dashboard-specific security headers for `GET /dashboard` and
  `/dashboard/assets/*`.
- [x] Add CSP, frame blocking, no-sniff, referrer, permissions, same-origin
  resource, and no-store cache posture.
- [x] Add same-origin dashboard request enforcement.
- [x] Add timeout-bounded dashboard API calls.
- [x] Add keyboard-accessible persona navigation markers and visible focus
  state.
- [x] Add focused tests for headers, same-origin enforcement, timeout markers,
  API protection, fake credentials, and responsive layout markers.
- [x] Re-evaluate dashboard-triggered threat model notes and update
  traceability.
- [x] Validate with
  `powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
  -BaseTemp .pytest_tmp_dashboard_hardening_final`.

## Completed Slice

Curated Generated-Fixture Promotion v0.1:

- [x] Add `fixtures/curated/README.md`.
- [x] Add `fixtures/curated/manifest.json` with explicit license, safety, and
  content review statuses.
- [x] Add `fixtures/curated/curated_soc_case_0001.jsonl`.
- [x] Add `tools/fixture_factory/promotions.py` for manifest, path, and
  fixture safety validation.
- [x] Add `tests/test_curated_fixture_promotion.py`.
- [x] Prove promoted fixtures are schema-valid, sanitized, deterministic, and
  explicitly reviewed.
- [x] Prove `fixtures/generated/` paths are rejected and generated output is
  not auto-scanned.
- [x] Keep raw datasets, auto-downloads, live providers, RAG, memory
  write-back, real data, and remediation out of scope.
- [x] Validate with
  `powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
  -BaseTemp .pytest_tmp_curated_fixture_promotion_final`.

## Completed Slice

Broader Curated Fixture Expansion v0.2:

- [x] Re-check `docs/ARCHITECTURAL_NORTH_STAR.md` before implementation.
- [x] Keep the slice fake-data only with no raw external dataset commits,
  auto-downloads, live providers, RAG, memory write-back, trust mutation, or
  remediation.
- [x] Add a tokenized healthcare-context exposure fixture under
  `fixtures/curated/`.
- [x] Add a sanitized prompt-injection fixture under `fixtures/curated/`.
- [x] Add an evidence-conflict/GRC category-alignment fixture under
  `fixtures/curated/`.
- [x] Record approved license, safety, and content review status for each new
  fixture in `fixtures/curated/manifest.json`.
- [x] Extend curated promotion tests for the full manifest set, scenario
  coverage, duplicate fixture IDs, deterministic serialization, generated
  folder rejection, and leakage prevention.
- [x] Keep `fixtures/generated/` ignored and out of automatic scanning.
- [x] Run full safe validation before calling the slice complete:
  `powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
  -BaseTemp .pytest_tmp_curated_v02_final_docs`.

## Completed Slice

Production Identity Readiness v0.1:

- [x] Re-check `docs/ARCHITECTURAL_NORTH_STAR.md` before implementation.
- [x] Keep this as static readiness only; do not add live OIDC/JWKS calls,
  JWT verification, Entra integration, real credentials, production tenant
  administration, production dashboard deployment, or non-demo data handling.
- [x] Add `API_AUTH_MODE=external_oidc` as the explicit production identity
  readiness mode.
- [x] Keep production-like environments blocked from `API_AUTH_MODE=none` and
  `API_AUTH_MODE=demo_key`.
- [x] Reject unknown auth modes.
- [x] Validate static provider, issuer, audience, JWKS, claim, role, and
  algorithm readiness settings.
- [x] Reject verifier enablement unless local fake-JWKS verifier config is
  complete.
- [x] Keep protected routes fail-closed under `external_oidc`.
- [x] Add focused tests for readiness validation, unsafe config rejection,
  incomplete-verifier rejection, unknown auth mode rejection, and
  protected-route fail-closed behavior.
- [x] Update docs, README, runbook, lesson, checklist, handoff, limitations,
  security notes, threat model traceability, and validation notes.
- [x] Validate with
  `powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
  -BaseTemp .pytest_tmp_production_identity_final2`.

## Completed Slice

Production Token Verifier Design v0.1:

- [x] Re-check `docs/ARCHITECTURAL_NORTH_STAR.md` before implementation
  planning.
- [x] Keep this as design/readiness only; do not add JWT parsing, signature
  verification, JWKS fetch, live OIDC calls, Entra calls, real credentials,
  production tenant administration, production claim-to-role authorization, or
  non-demo data handling.
- [x] Add `docs/PRODUCTION_TOKEN_VERIFIER_DESIGN.md` for the future
  `external_oidc` token acceptance and claim-mapping contract.
- [x] Add `docs/specs/29_PRODUCTION_TOKEN_VERIFIER_DESIGN.md`.
- [x] Add `docs/runbooks/PRODUCTION_TOKEN_VERIFIER_DESIGN_REVIEW.md`.
- [x] Require future verification to check bearer token shape, asymmetric
  signature, issuer, audience, expiration, not-before, issued-at, tenant claim,
  subject claim, role claim, role mapping, and role-view policy before any
  request is authorized.
- [x] Require future tests to prove no network calls occur during standard
  validation and no raw JWT, Authorization header, full claim payload, real
  tenant ID, group ID, credential, or key material appears in logs or audit
  events.
- [x] Update README, checklist, handoff, limitations, decisions, security notes,
  threat model notes, lessons, and validation notes.
- [x] Validate with
  `powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
  -BaseTemp .pytest_tmp_token_verifier_design_final`.

## Completed Slice

Dataset-Backed Demo Seeder v0.1:

- [x] Re-check `docs/ARCHITECTURAL_NORTH_STAR.md` before implementation.
- [x] Add a runtime-owned curated loader (`src/threatprism/demo/seeding.py`) that
  reads `fixtures/curated/manifest.json` directly and never imports `tools/`,
  keeping the dependency direction one-way (tooling may import the app, not the
  reverse).
- [x] Seed only fixtures whose manifest entry includes `demo_review` in
  `allowed_uses` and carries `approved_demo_safe` / `approved_for_tests` review
  status; never auto-scan the generated fixture folder.
- [x] Enforce a path sandbox that rejects absolute, drive, traversal, non-`.jsonl`,
  and escaping fixture paths.
- [x] Replay each fixture through the real `create_case` + `run_triage` intake
  path so the full four-layer guardrail pipeline runs.
- [x] Add a `FixtureSource` Protocol seam for a future dataset-ingest source
  (interface only; no speculative adapter).
- [x] Add an env-gated startup seed hook (`THREATPRISM_DEMO_SEED`), default off,
  refused in production by `validate_runtime()`.
- [x] Add `python -m threatprism.demo.seed_cli` with `--source` and
  `--skip-existing/--no-skip-existing`; idempotent via `source_case_id` match.
- [x] Add focused tests in `tests/test_demo_seeding.py`.
- [x] Record the finding that curated fixtures are post-sanitization snapshots,
  so replay does not re-trigger quarantine/redaction for already-sanitized
  fixtures (see `LIMITATIONS.md`).
- [x] Update spec (`docs/specs/31_DATASET_BACKED_DEMO_SEEDER.md`), README,
  checklist, handoff, limitations, decisions, `.env.example`, mitigations
  traceability, and lessons.

Production Token Verifier Implementation v0.1:

- [x] Re-check `docs/ARCHITECTURAL_NORTH_STAR.md` before implementation.
- [x] Keep this as local fake-JWKS verification only; do not add live JWKS
  fetch, OIDC discovery, Entra calls, real credentials, production tenant
  administration, production dashboard deployment, non-demo data, or
  remediation.
- [x] Add verifier configuration for allowed tenants, role mapping, local JWKS
  JSON, JWKS fetch disablement, clock skew, token size, and claim mapping
  version.
- [x] Verify compact JWT bearer tokens with configured RSA local JWKS keys.
- [x] Reject malformed, oversized, unsafe-algorithm, missing/unknown `kid`, bad
  signature, issuer, audience, time, subject, tenant, role, tenant mismatch,
  unmapped role, and conflicting-role failures.
- [x] Map verified external role/group claims to exactly one ThreatPrism
  effective role.
- [x] Reuse existing role-view policy so requested `?role=` is never authority.
- [x] Add sanitized audit metadata without raw JWTs, raw Authorization headers,
  full claims, raw subject, raw tenant, raw group, credential, or key material.
- [x] Add focused tests in `tests/test_production_token_verifier.py`.
- [x] Update docs, README, checklist, handoff, limitations, decisions, security
  notes, threat model notes, lessons, and validation notes.
- [x] Validate with
  `powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
  -BaseTemp .pytest_tmp_token_verifier_impl_final2`.

## Completed Slice

Option A — Separate Third-Party Dataset Fixture Source (committed `ac361b4`):

This is a parallel contract to the hand-authored curated fixture path. The
existing `CuratedFixtureSource` deliberately rejects third-party licenses, so
reviewed third-party *synthetic* derivatives onboard through a separate
`CuratedDatasetSource` over `fixtures/curated_datasets/` instead of weakening
the known-good curated boundary. The accepted license-review allowlist lives in
code (`DATASET_ALLOWED_LICENSE_REVIEW` in `src/threatprism/demo/seeding.py`), not
in the manifest, so a tampered manifest cannot self-certify a license.

Hard boundary: `tools/fixture_factory/promotions.py` and
`tests/test_curated_fixture_promotion.py` are intentionally untouched and must
stay that way. Synthetic/fake data only, no auto-download, no raw third-party
data committed.

Dataset onboarding status: **3 of 3 source families promoted.**
`synthea_healthcare` (healthcare context, Apache-2.0), `deepset_prompt_injection`
(prompt injection, Apache-2.0), and `otrf_soc_telemetry` (SOC telemetry, **MIT**)
are all promoted into `fixtures/curated_datasets/manifest.json`.

Done (validated GREEN — 134 passed, eval harness dry-run 15/15, demo safety passed):

- [x] Slice 1: `fixtures/curated_datasets/manifest.json` + `README.md` parallel
  contract; `manifest_version` `curated-datasets/0.1`.
- [x] Slice 2: `CuratedDatasetSource` in `src/threatprism/demo/seeding.py`,
  reusing `CuratedFixtureSource._is_demo_seedable` and `._read_seed_cases` and
  layering the code-authoritative `DATASET_ALLOWED_LICENSE_REVIEW` allowlist.
- [x] Slice 3: wired alongside `CuratedFixtureSource()` in `api/app.py` startup
  and `seed_cli.py` (`--source curated|curated_datasets|all`).
- [x] Tests: `tests/test_curated_dataset_seeding.py` (8 tests; mirrors
  `tests/test_demo_seeding.py` with `repo_root=` override + tmp manifests).
- [x] Slice 4: ran the `SAFE_COLUMNS` synthea adapter against
  `external_datasets/synthea_sample_data/csv/patients.csv`; inspected all 12
  outputs (only the 8 `SAFE_COLUMNS`, SSN Stage-1 tokenized, no raw identifiers
  leaked); wrote committed `fixtures/curated_datasets/synthea_healthcare.jsonl`
  (12 lines) + one `manifest.json` entry with
  `license_review_status=approved_third_party_apache2_synthetic`. Updated the
  startup-hook count test (4 -> 16) and the committed-manifest test (empty ->
  loads 12). `docs/DATASET.md` and the dataset `README.md` updated from
  "pending" to "promoted".

- [x] Slice 6: `deepset/prompt-injections` source (Apache-2.0 parquet staged in
  gitignored `external_datasets/`). Built `tools/fixture_factory/adapters/deepset_adapter.py`
  + added an `apply_prompt_firewall=False` source-scoped exception to
  `sanitizers.py` (injection text stays UN-redacted on replay; credential,
  healthcare, and infra sanitization still apply). Promoted 12 fixtures to
  `fixtures/curated_datasets/deepset_prompt_injection.jsonl` (bucket mix:
  **1 quarantine, 5 redact, 6 none/RR-L1**), added the `manifest.json` and
  `data_sources/registry.json` entries. The honest finding: the deterministic
  firewall recognizes only the quarantine+redact rows; the 6 `none` rows are
  real injections it misses (RR-L1) — they reach the inert demo provider but
  never leak into reports/audit. Tests: `tests/test_deepset_injection_corpus.py`
  (5 tests). Updated count tests (startup hook 16 -> 28; committed-manifest
  synthea test scoped to family). Full suite 139 passed, evals 15/15, demo
  safety passed. Authored `docs/specs/32_SEMANTIC_PROMPT_INJECTION_LAYER.md` as
  the forward-looking next defense layer. Throwaway `_inspect.py`/`_promote.py`
  helpers deleted.

Done (validated GREEN — 149 passed, eval harness dry-run 15/15, demo safety passed):

- [x] Slice 5: `LocalDatasetSource` in `src/threatprism/demo/seeding.py` replays
  uncommitted `.jsonl` staging under gitignored `external_datasets/` on the fly
  through the real `create_case` + `run_triage` intake path. OFF by default —
  not the default `--source`, excluded from `--source all`, never in the startup
  seed hook, and refused in `prod`/`production` by `_ensure_source_allowed()` in
  `seed_cli.py`. No manifest/license gate (this is unreviewed local-only data),
  but the four-layer guardrail pipeline still sanitizes it at intake. Added
  `seed_cli --source local` and `--limit N` (limit valid only with `--source
  local`). Nothing committed: `external_datasets/**` stays gitignored and the
  source only reads. Tests: `tests/test_local_dataset_seeding.py` (10 tests).

## Completed Slice

OTRF SOC-Telemetry Onboarding (3rd dataset family) — validated GREEN
(156 passed, eval harness dry-run 15/15, demo safety passed):

- [x] Verified OTRF/Security-Datasets license is **MIT** from the repo `LICENSE`
  file (residual: re-confirm at pinned commit at build time).
- [x] Replaced the unsafe OTRF adapter stub with a fail-closed `SAFE_FIELDS`
  allowlist + streaming JSONL reader (`tools/fixture_factory/adapters/otrf_adapter.py`);
  drops host/Hostname/UserID(SID)/AccountName/Domain/port/`*Guid`/`TargetObject`,
  reduces `Image` to basename, scrubs SIDs + user-profile paths.
- [x] Fixed a bug where the shared domain normalizer mangled process basenames
  (`powershell.exe` -> `example.org`) by attaching the validated basename after
  sanitization.
- [x] Generated + inspected 8 distinct-EventID fixtures; confirmed zero raw
  identifier leakage before promoting
  `fixtures/curated_datasets/otrf_soc_telemetry.jsonl`.
- [x] Added a new code-authoritative license status
  `approved_third_party_mit_lab_telemetry` to `DATASET_ALLOWED_LICENSE_REVIEW`
  and a manifest entry with MIT attribution.
- [x] Added `tests/test_otrf_telemetry_corpus.py` (7 tests: no-leak, projection,
  SID scrub, basename regression, license gate, real-intake seed); updated
  startup-hook count (28 -> 36) and the fixture-factory adapter id test.
- [x] Updated `docs/DATASET.md`, `fixtures/curated_datasets/README.md`, and this
  checklist.

## Next Active Slice

Remaining ordered queue (user decision): **(2) Option A closeout** → **(3)
Semantic-layer enablement plan** targeting **Meta Prompt Guard 2 — 86M**
(multilingual; owner-approved 2026-05-30, Llama Community License accepted; see
`docs/specs/32_SEMANTIC_PROMPT_INJECTION_LAYER.md` §3). Beyond that: Recommended choices should be selected explicitly before
implementation:

- [ ] Live-provider preparation only after re-opening gated threat treatments.
- [ ] Optional external research provider feasibility, such as Exa.ai, only as
  a gated future enhancement; it is not needed for the current build and must
  not add live calls, CSI/RGOI memory write-back, live RAG, automatic fixture
  promotion, trust mutation, or source-of-truth changes.
- [ ] Live JWKS fetch or real IdP integration only after explicitly approving a
  separate live-integration slice with updated threat treatment.
- [ ] Production dashboard deployment, browser matrix certification, and
  accessibility certification only after explicit approval.
- [ ] Additional curated fixture promotion only after manual license, safety,
  and content review for each new fixture.

Future planned data-realism slice:

- [x] Dataset-Backed Demo Seeder v0.1 replays hand-reviewed curated fixtures
  through the real intake path; see
  `docs/specs/31_DATASET_BACKED_DEMO_SEEDER.md`. A future dataset-ingest source
  can implement the `FixtureSource` seam after its own review gate.
- [x] Data Strategy & Synthetic Fixture Factory v0.1.
- [x] Capture the dataset strategy in
  `docs/DATA_STRATEGY_AND_FIXTURE_FACTORY.md`.
- [x] Capture the implementation-ready spec in
  `docs/specs/20_DATA_STRATEGY_AND_FIXTURE_FACTORY.md`.
- [x] When implemented, keep raw external datasets ignored and convert only
  manually reviewed source samples into sanitized ThreatPrism-native fixtures.
- [x] Do not auto-download datasets, run Caldera, add live LLM evaluation, or
  commit raw third-party data without an explicit future prompt.

## Context Handoff

- [x] Avoid pasting long project instructions into new chats.
- [x] Use `START_HERE.md` as the compact startup path.
- [x] Use `tools/generate-compact-handoff.ps1` to print the fresh-chat prompt.
- [x] Treat roughly 75% context used, or less than roughly 25% remaining, as the
  handoff-warning threshold.

## Validation

Use safe local validation first:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

Current known result:

```text
149 passed
eval harness dry-run: 15 passed / 0 failed
```

CI follow-up on 2026-05-24: GitHub Actions failed on Ubuntu because the eval
fixture path traversal guard did not normalize Windows-style backslash paths
before checking the approved fixture/output directories. The local fix
normalizes those candidates before resolution; full safe validation passes with
`-BaseTemp .pytest_tmp_ci_fix_validation`.

If a reused pytest temp directory fails with Windows `WinError 5`, rerun with a
fresh ignored base temp directory.

## Out Of Scope Until Explicitly Requested

- [ ] Real remediation or containment.
- [ ] Live LLM calls.
- [ ] Live SOAR calls.
- [ ] Live cloud or enrichment provider calls.
- [ ] Production credentials.
- [ ] Real workplace, tenant, user, host, domain, IP, or secret data.
- [ ] Production dashboard deployment and live production identity integration.
- [ ] Strict CI gates that fail before the inherited baseline is ready.

## Definition Of Done For The Current Slice

- [x] Local workspace is connected to `mwill20/ThreatPrism_V2`.
- [x] Current baseline is committed and pushed.
- [x] README explains setup, test, and demo flow.
- [x] Guardrail and action-safety test coverage covers failure paths.
- [x] Specs, limitations, and handoff docs agree with the implemented state.
- [x] Validation passes from a clean command.
- [x] Remaining gaps are documented as next-phase work, not hidden as completed.

## Published Baseline

- Initial baseline commit: `2ece6dd Build ThreatPrism V2 baseline`.
- Healthcare safeguard guardrails commit: `f251d28 Implement healthcare safeguard guardrails`.
- Operational metrics prep commit: `3a4dd84 Prep operational metrics read-model slice`.
- Access control audit prep commit: `20ad254 Document access control audit slice`.
- Architectural North Star commit: `31d5c98 Add architectural north star`.
- Lessons curriculum commit: `6aa3755 Add ThreatPrism lessons curriculum`.
- Access control implementation commit: `f05e93d Implement demo access control audit slice`.
- Operational read models implementation commit:
  `fd8564b Implement operational read models and metrics`.
- Evaluation harness implementation commit:
  `d0a798a Implement eval harness and regression defense labs`.
- Dedicated review queue implementation commit:
  `39483f3 Add dedicated operational review queues`.
- Pushed to `origin/main` for `mwill20/ThreatPrism_V2`.
