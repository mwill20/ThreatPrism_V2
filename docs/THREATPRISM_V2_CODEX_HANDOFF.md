# ThreatPrism V2 Codex Handoff

## Read This First

This handoff is the current source of truth for continuing ThreatPrism V2 work in this workspace.

For context-light startup, read `START_HERE.md` first and do not paste this
file into a new chat.

Canonical local path:

```text
C:\Projects\ThreatPrismV2
```

Destination repository:

```text
mwill20/ThreatPrism_V2
```

Product name:

```text
ThreatPrism
```

Do not use a V2 suffix as the product name in user-facing material.

## Current State

The original handoff baseline said this workspace contained documentation and
specs only. That statement is now stale.

Implementation has begun in this workspace. Trust the live files and validation
results over older chat summaries or final responses, including the previous
final response that leaked drafting/debug text.

The current live implementation includes a first backend slice:

- `src/threatprism/api/app.py` with FastAPI routes for health, case intake,
  case listing/detail, triage-report retrieval, and analyst feedback.
- `src/threatprism/cases/` with Pydantic case, triage report, feedback,
  disagreement, evidence, GRC, MITRE, action, audit, operational metrics, and
  read-model schemas plus the case service orchestration.
- `src/threatprism/soar/generic.py` with generic SOAR payload normalization.
- `src/threatprism/guardrails/` with prompt firewall, tokenization,
  healthcare safeguard scanning, role-based rendering helpers, output-policy
  scanning, evidence-grounding checks, and action-safety checks.
- `src/threatprism/auth/` with demo API-key authentication, identity-to-role
  mapping, role-view authorization, and safe authorization audit events.
- `src/threatprism/llm/providers.py` with a deterministic demo provider.
- `src/threatprism/persistence/sqlite.py` with SQLite demo persistence.
- `src/threatprism/reports/render.py` with deterministic report rendering.
- `src/threatprism/evals/` with the local dry-run regression eval harness.
- `src/threatprism/csi/` with read-only CSI/RGOI cognitive schemas,
  retrieval governance, trust scoring, evidence alignment validation, lineage,
  replay, observability, divergence telemetry, and fake demo seed objects.
- `src/threatprism/demo/` with typed fake scenario-pack loading.
- `tools/` with fake-data-only safety checks and local validation wrapper.
- `tools/generate-compact-handoff.ps1` with compact fresh-chat prompt
  generation.
- `tools/fixture_factory/` with local-only synthetic fixture models,
  sanitizers, validators, adapters, and CLI generation.
- `data_sources/registry.json` with review-required, no-download, no-raw-commit
  defaults for candidate source families.
- `external_datasets/` and `fixtures/generated/` with ignored local staging and
  generated fixture output boundaries.
- `fixtures/curated/` with one tracked, hand-reviewed fake SOC fixture plus a
  manifest review gate.
- `Dockerfile`, `docker-compose.yml`, and `.dockerignore` with local demo
  backend packaging.
- `.github/workflows/safe-validation.yml` with lightweight fake-data-only CI.
- `examples/soar_payloads/` with fake demo payloads only.
- `examples/demo_scenarios/` with the fake role-specific demo scenario pack.
- `examples/csi/` with tiny fake CSI/RGOI cognitive object fixture
  descriptions.
- `examples/dashboard_contract/` with fake persona response fixtures for
  dashboard contract review.
- `src/threatprism/dashboard/static/` with the local fake-data-only dashboard
  UI served at `GET /dashboard`.
- Dashboard hardening for `GET /dashboard` and `/dashboard/assets/*` with
  security headers, same-origin request enforcement, timeout-bounded API calls,
  keyboard persona navigation markers, docs, threat-model updates, and tests.
- `tests/evals/` with fake JSONL eval fixtures only.
- `tests/test_api_flow.py` and `tests/test_guardrails.py` covering the current
  API flow and guardrail behavior.
- `tests/test_operational_read_models.py` covering metrics, dedicated review
  queues, filtered read models, detail routes, authorization, and leakage
  prevention.
- `tests/test_demo_scenarios_and_api_contract.py` covering scenario-pack smoke
  workflows and OpenAPI route/response-model contract checks.
- `tests/test_docker_packaging.py` covering Dockerfile, Compose, and Docker
  ignore safety boundaries.
- `tests/test_fixture_factory.py` covering registry metadata, fixture models,
  sanitizer behavior, adapters, CLI behavior, path safety, deterministic
  output, no-network behavior, schema validity, and leakage prevention.
- `tests/test_curated_fixture_promotion.py` covering curated manifest review,
  explicit fixture paths, generated-folder rejection, schema validity,
  deterministic serialization, and leakage prevention.
- `tests/test_csi_rgoi.py` covering tenant isolation, retrieval policy,
  evidence alignment, trust scoring, quarantine exclusion, stale cognition,
  lineage, replay, observability, divergence telemetry, demo auth, and OpenAPI
  routes.
- `tests/test_demo_scenarios_and_api_contract.py` covering demo workflows,
  route contract freeze, CSI/RGOI route contracts, and dashboard contract
  fixture safety.
- `tests/test_dashboard_ui.py` covering dashboard route serving, security
  headers, same-origin asset and request boundaries, fake credential
  boundaries, API protection, keyboard markers, and responsive layout markers.
- `tests/test_ops_safety.py` covering the demo safety checker.
- `docs/DATA_STRATEGY_AND_FIXTURE_FACTORY.md` and
  `docs/specs/20_DATA_STRATEGY_AND_FIXTURE_FACTORY.md` capturing the
  implemented local-only data-realism and synthetic fixture factory slice.
- `docs/CURATED_GENERATED_FIXTURE_PROMOTION.md` and
  `docs/specs/27_CURATED_GENERATED_FIXTURE_PROMOTION.md` capturing the
  reviewed tiny fixture-promotion path.
- `REPO_AUDIT.md`, `CHANGELOG.md`, root `CONTRIBUTING.md`, and focused
  reviewer-readiness docs for usage, evaluation, dataset handling,
  model/provider behavior, deployment boundary, monitoring, and
  troubleshooting.

Validated on 2026-05-25 with:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1 -BaseTemp .pytest_tmp_fixture_factory_validation_done
```

Result:

```text
73 passed
eval harness dry-run: 15 passed / 0 failed
```

Repo Standards Readiness Pass validation on 2026-05-26 with:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1 -BaseTemp .pytest_tmp_repo_standards_final_fresh
```

Result:

```text
73 passed
eval harness dry-run: 15 passed / 0 failed
```

CSI/RGOI Foundation validation on 2026-05-26 with:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1 -BaseTemp .pytest_tmp_csi_final_validation
```

Result:

```text
82 passed
eval harness dry-run: 15 passed / 0 failed
```

Dashboard UI Preparation validation on 2026-05-26 with:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1 -BaseTemp .pytest_tmp_dashboard_prep_final_validation
```

Result:

```text
83 passed
eval harness dry-run: 15 passed / 0 failed
```

Dashboard UI Implementation validation on 2026-05-26 with:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1 -BaseTemp .pytest_tmp_dashboard_ui_final_validation2
```

Result:

```text
87 passed
eval harness dry-run: 15 passed / 0 failed
```

Production Dashboard Hardening validation on 2026-05-26 with:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1 -BaseTemp .pytest_tmp_dashboard_hardening_final
```

Result:

```text
89 passed
eval harness dry-run: 15 passed / 0 failed
```

Curated Generated-Fixture Promotion validation on 2026-05-26 with:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1 -BaseTemp .pytest_tmp_curated_fixture_promotion_final
```

Result:

```text
93 passed
eval harness dry-run: 15 passed / 0 failed
```

CI follow-up on 2026-05-24: GitHub Actions run `26350740346` failed on Ubuntu
at `tests/test_eval_harness.py::test_path_traversal_is_rejected_for_fixtures_and_outputs`.
Root cause was Windows-style backslash traversal being treated as a literal
filename on POSIX before approved-directory validation. The eval runner now
normalizes backslash candidates before resolution. Revalidated locally with:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1 -BaseTemp .pytest_tmp_ci_fix_validation
```

If rerunning the exact command fails with a Windows `WinError 5` while cleaning
the reused `.pytest_tmp_run_new` directory, use a fresh ignored base temp such
as:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_verify
```

The destination repo remains `mwill20/ThreatPrism_V2`. The local workspace at
`C:\Projects\ThreatPrismV2` is a Git checkout; still verify live status before
making git claims.

The original V1 repo `mwill20/threatprism` was reviewed read-only for reuse analysis. It has not been copied into this workspace.

## Privacy Rule

Do not mention any real employer, healthcare organization, or specific workplace in:

- code
- docs
- comments
- commit messages
- README
- demo data
- examples

Frame the product generically as a tool for organizations moving from outsourced MSSP-managed SOC operations to an internal SOC model.

## Governing Docs

Read in this order:

1. `docs/THREATPRISM_V2_CODEX_HANDOFF.md`
2. `docs/ARCHITECTURAL_NORTH_STAR.md`
3. `docs/specs/00_VISION.md`
4. `docs/specs/01_PRODUCT_REQUIREMENTS.md`
5. `docs/specs/02_ARCHITECTURE.md`
6. `docs/specs/04_API_CONTRACT.md`
7. `docs/specs/05_DATA_MODEL.md`
8. `docs/specs/08_AI_GUARDRAILS.md`
9. `docs/specs/09_ACTION_SAFETY_MODEL.md`
10. `docs/specs/10_GRC_HITRUST_ALIGNMENT.md`
11. `docs/specs/V1_REUSE_ANALYSIS.md`
12. `DECISIONS.md`
13. `LIMITATIONS.md`
14. `AGENTS.md`
15. `docs/DATA_STRATEGY_AND_FIXTURE_FACTORY.md` when the task involves
    datasets, synthetic fixtures, or data realism.
16. `docs/CSI_RGOI_ARCHITECTURE.md` and `docs/specs/23_CSI_RGOI_FOUNDATION.md`
    when the task involves governed cognition, RAG, retrieval, memory,
    lineage, or institutional learning.
17. `docs/DASHBOARD_DATA_CONTRACT.md` and
    `docs/specs/24_DASHBOARD_UI_PREPARATION.md` when the task involves
    dashboard contracts, UI readiness, persona response fixtures, or frontend
    planning.

The older root handoff and prompt files were updated for path and repo target, but this current handoff should be treated as the latest continuation brief.

## Key Locked Decisions

- `docs/ARCHITECTURAL_NORTH_STAR.md` is the directional architecture guide for
  new slices, workarounds, and major enhancements.
- Architecture target: CLI + FastAPI service + dashboard-ready backend.
- First backend is case-centric, not V1 run-centric.
- Single-org internal SOC only. Do not build MSSP multi-tenancy.
- Demo persistence: SQLite, designed so PostgreSQL can be added later.
- SOAR integration: provider-agnostic adapter interface.
- Microsoft integration is first-class but must not hardwire the core model.
- AI provider abstraction is required. OpenAI is the default provider; local OpenAI-compatible or Ollama-compatible provider is optional.
- No real remediation or containment in V2.
- Default action setting must be `ALLOW_REAL_ACTIONS=false`.
- HITRUST work is control-category mapping only. Do not claim compliance, certification, or implementation.
- Demo data must be fake and must not require live SOAR credentials.

## Copy/Fork Versus Clean Build Decision

Recommended strategy:

```text
Clean V2 architecture with selective V1 module porting.
```

Do not full-copy V1 as the primary foundation.

Do not do a pure clean-room build that ignores V1.

Reasoning:

- V1 has strong guardrails, provenance tracking, Pydantic schema discipline, deterministic reporting, and ops artifacts.
- V1 also has a large linear CLI `src/main.py`, run-centric SQLite schema, old docs, historical lessons, and an older V2 spec that conflict with the current handoff.
- V2 needs API-first boundaries, async triage jobs, case persistence, SOAR ingestion, analyst feedback, disagreement metrics, and GRC mapping.

## V1 Concepts To Preserve

From `mwill20/threatprism`, preserve or adapt:

- Provenance envelope: `source_file`, `record_index`, `event_id`, `raw_event`.
- Prompt firewall and sanitization patterns from `src/security.py`.
- Output policy scanning from `src/security.py`.
- Deterministic semantic evidence validation from `src/security.py`.
- Pydantic-style structured output contracts from `src/schemas.py`.
- Deterministic report rendering pattern from `src/report.py`.
- Run artifact pattern from `src/ops/`: `run_log.jsonl`, `metrics.json`, `what_broke.md`.
- Selected deterministic AWS/GCP enrichment helpers as later compatibility adapters.
- Relevant tests for prompt firewall, semantic validation, full flow, and source detection.

Do not copy wholesale:

- V1 `src/main.py`
- V1 `src/storage.py`
- V1 `Dockerfile`
- V1 historical docs and lessons
- V1 data folders unless explicitly needed for a compatibility fixture
- V1 old `docs/V2_SPEC.md`

## Security And LLM Boundary

ThreatPrism V2 must treat all case text, logs, payloads, and source artifacts as untrusted.

ThreatPrism V2 must treat all LLM output as untrusted until validated.

For healthcare-oriented work, SOAR payloads are expected to be security-only,
but ThreatPrism must treat inbound payloads as potentially contaminated.
ThreatPrism does not classify every identifier as PHI/ePHI by itself.
Identifiers become PHI/ePHI risk when connected to health context, patient
context, care context, billing context, encounter context, or other data that
can reasonably identify an individual.

Required safe model boundary:

```text
Raw source payload
  -> source payload hash
  -> normalize evidence and provenance
  -> deterministic prompt firewall
  -> input sanitization
  -> sensitive-value tokenization
  -> LLM prompt assembly
  -> provider-agnostic LLM call
  -> strict Pydantic/schema validation
  -> output policy scanner
  -> evidence-grounding checks
  -> action safety scanner
  -> controlled rehydration for authorized views
  -> deterministic report rendering
  -> audit event write
```

## Tokenization And Rehydration

Add tokenization before LLM calls.

Tokenization must:

- replace sensitive values with deterministic case-local tokens
- preserve semantic type, such as user, host, IP, domain, URL, file hash, or secret-like value
- preserve evidence provenance
- store token mappings outside the model prompt path
- avoid sending secrets, full API keys, tenant IDs, private hostnames, and unnecessary user identifiers to the LLM

Controlled rehydration may happen only after:

- schema validation passes
- output policy scanning passes
- evidence-grounding checks pass
- action safety checks pass
- an authorization context exists

Never rehydrate secrets, full API keys, or credential-like tokens.

Prefer masked values for analyst views and tokenized values for management/GRC views unless raw values are required.

## Completed Implementation Slices

The first vertical slice is implemented:

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

Healthcare Safeguard & Evidence Alignment Guardrails v0.1 is also implemented:

```text
Context-aware potential PHI/ePHI, PII, secret, and security telemetry detection
  -> Typed tokenization before persistence and model-visible payload creation
  -> Role-based rendering for AI, analyst, engineer, manager/GRC,
     legal/privacy, and audit/debug views
  -> Compliance-language scanner for HIPAA/HITRUST/audit-ready/control claims
  -> Audit events for tokenization, rehydration approval or denial,
     role-view policy application, guardrail blocks, and report validation
```

Access Control & Audit Integrity v0.1 is implemented:

```text
Demo API key
  -> Caller identity and effective role
  -> Role-view authorization
  -> Role escalation denial
  -> Safe authorization audit event for allow or deny decisions
  -> Role-aware case and report reads
```

Operational Read Models & Metrics API v0.1 is implemented:

```text
Operational Read Models & Metrics API v0.1
  -> Stable GET /metrics aggregate response shape
  -> Dashboard-ready GET /cases/read-model companion envelope route
  -> Dedicated GET /queues/manager-review and GET /queues/healthcare-review
     queue routes
  -> Safe detail routes for evidence, timeline, MITRE, GRC, and audit events
  -> Authorization and role-safe rendering on read/detail routes
  -> Tests proving metrics and read models do not expose raw potential PHI/ePHI,
     secrets, credentials, raw payload bodies, or token vault mappings
```

Evaluation Harness & Regression Defense Labs v0.1 is implemented:

```text
Fake JSONL eval fixtures
  -> Approved tests/evals fixture directory only
  -> Dry-run deterministic checks
  -> Sanitized eval result previews
  -> Approved .eval_runs output directory only
  -> Tests for prompt injection, unsafe actions, schema/evidence failures,
     healthcare leakage, authorization escalation, read-model leakage,
     audit leakage, token-vault exposure, compliance overclaims, oversized
     payloads, malformed JSON, and conflicting evidence
```

Demo Operations & CI Hardening v0.1 is implemented:

```text
Safe validation wrapper
  -> Demo safety checker
  -> Pytest with plugin autoload disabled
  -> Dry-run eval harness
  -> Eval artifact hygiene scan
  -> Fake-data-only GitHub Actions workflow
```

Demo Scenario Pack & API Contract Freeze v0.1 is implemented:

```text
Typed scenario pack
  -> Fake analyst, manager/GRC, legal/privacy, audit/debug, and engineer
     workflows
  -> Fake healthcare safeguard review payload
  -> OpenAPI route and response-model contract assertions
  -> Scenario smoke tests against local in-memory FastAPI
  -> Dashboard work was out of scope in that slice; no live integrations,
     production IdP, or remediation were added
```

Docker Compose & Local Demo Packaging v0.1 is implemented:

```text
Dockerfile
  -> Existing FastAPI backend image
  -> Locked dependency install
  -> Non-root runtime user
  -> Demo-safe environment defaults
docker-compose.yml
  -> Single threatprism-api service
  -> Fake demo API-key auth
  -> Deterministic demo provider
  -> SQLite named volume
  -> Empty live-provider credential variables
```

Data Strategy & Synthetic Fixture Factory v0.1 is implemented:

```text
data_sources/registry.json
  -> review-required source registry with downloads disabled
external_datasets/
  -> ignored local-only reviewed source sample staging
tools/fixture_factory/
  -> local-only adapters, sanitizers, validators, models, and CLI
fixtures/generated/
  -> ignored deterministic sanitized JSONL fixture output
```

Repo Standards Readiness Pass v0.1 is implemented:

```text
REPO_AUDIT.md
  -> audit-first repository standards scorecard and gap list
docs/USAGE.md, docs/EVALUATION.md, docs/DATASET.md, docs/MODEL_CARD.md,
docs/DEPLOYMENT.md, docs/MONITORING.md, docs/TROUBLESHOOTING.md
  -> reviewer-focused entry points
README.md
  -> purpose, audience, status, requirements, doc map, evaluation, license,
     and support summary
```

CSI/RGOI Foundation v0.1 is implemented:

```text
src/threatprism/csi/
  -> read-only cognitive object schemas, retrieval governance, trust scoring,
     evidence alignment, lineage, replay, observability, and divergence
     telemetry
GET /csi/objects, /csi/objects/{object_id}, /csi/lineage/{object_id},
/csi/replay/{object_id}, /csi/observability, /csi/divergence
  -> retrieval-governed cognition APIs
examples/csi/rgoi_cognitive_objects.json
  -> tiny fake fixture description
```

Dashboard UI Preparation v0.1 is implemented:

```text
docs/DASHBOARD_DATA_CONTRACT.md
  -> backend surfaces the local dashboard consumes
docs/runbooks/DASHBOARD_READINESS.md
  -> fake credential, route-check, and hardening workflow for dashboard review
examples/dashboard_contract/
  -> static fake persona response fixtures
tests/test_demo_scenarios_and_api_contract.py
  -> route/response contract checks for CSI/RGOI and dashboard fixtures
```

Dashboard UI Implementation v0.1 is implemented:

```text
GET /dashboard
  -> local fake-data-only dashboard shell served by FastAPI
src/threatprism/dashboard/static/
  -> dependency-free HTML, CSS, and JavaScript
tests/test_dashboard_ui.py
  -> route, asset, fake credential, API protection, and responsive layout
     checks
Browser verification
  -> desktop layout, mobile layout, analyst case workflow, manager/GRC
     navigation, and CSI/RGOI cognitive retrieval view
```

Production Dashboard Hardening v0.1 is implemented:

```text
GET /dashboard and /dashboard/assets/*
  -> CSP, frame blocking, no-sniff, referrer, permissions, same-origin
     resource, and no-store cache headers
src/threatprism/dashboard/static/app.js
  -> same-origin request enforcement and timeout-bounded API calls
src/threatprism/dashboard/static/index.html and styles.css
  -> tab semantics, keyboard persona navigation markers, and focus state
tests/test_dashboard_ui.py
  -> header, same-origin, timeout, keyboard, fake credential, API protection,
     and responsive layout checks
```

## Next Implementation Slice

No new implementation slice is selected yet. Curated Generated-Fixture
Promotion v0.1 is complete; it promotes one tiny tracked fake fixture through
`fixtures/curated/manifest.json`. Generated fixtures remain ignored and are
not auto-scanned.

Optional external research provider work, such as Exa.ai feasibility, is a
deferred future enhancement only. It is not needed for the current build and
must not add live calls, live RAG, CSI/RGOI memory write-back, automatic
fixture promotion, trust mutation, or source-of-truth changes without a
separate approved slice.

Do not implement:

- real remediation actions
- full threat intelligence integrations
- production dashboard deployment, production IdP, external telemetry, or
  tracked browser/accessibility certification
- MSSP multi-tenancy
- live SOAR credential flows
- CSI/RGOI write-back, live RAG, autonomous knowledge approval, trust mutation,
  or suppression publication

## Recommended Initial Module Layout

Use a clean structure rather than copying V1 layout wholesale:

```text
src/threatprism/
  api/
  cases/
  csi/
  guardrails/
  llm/
  reports/
  persistence/
  soar/
  enrichment/
  mitre/
  grc/
  actions/
  ops/
  cli/
tests/
examples/soar_payloads/
docs/specs/
```

Port V1 concepts into the relevant modules.

Example mapping:

- V1 `src/security.py` -> `src/threatprism/guardrails/`
- V1 `src/schemas.py` -> `src/threatprism/cases/schemas.py` and report schema modules
- V1 `src/report.py` -> `src/threatprism/reports/`
- V1 `src/ops/` -> `src/threatprism/ops/`
- V1 source ingest modules -> later compatibility adapters under `src/threatprism/soar/` or `src/threatprism/ingest/`

## Required Demo Payloads

Add later during implementation:

```text
examples/soar_payloads/
  generic_soar_case.json
  sentinel_incident.json
  defender_xdr_alert.json
  logic_apps_webhook_payload.json
  swimlane_case_mock.json
```

All payloads must be fake.

Use reserved domains and documentation IP ranges.

## Core API Routes

Implement first:

```text
GET /health
GET /cases
POST /cases
GET /metrics
GET /cases/read-model
GET /cases/{case_id}
GET /cases/{case_id}/triage-report
GET /cases/{case_id}/evidence
GET /cases/{case_id}/timeline
GET /cases/{case_id}/mitre
GET /cases/{case_id}/grc-controls
GET /cases/{case_id}/audit-events
POST /cases/{case_id}/analyst-feedback
```

Document or stub later:

```text
GET /cases/{case_id}/ioc-enrichment
POST /evals/run
```

## GRC And HITRUST

Use only:

- HIPAA Security Rule safeguard theme
- HITRUST-aligned
- HITRUST-inspired control mapping
- HITRUST-style framework category
- GRC-ready evidence organization
- control category mapping
- evidence-to-control traceability
- evidence alignment

Do not claim:

- HIPAA compliance
- HIPAA certification
- HITRUST compliance
- HITRUST certification
- that ThreatPrism implements HITRUST
- that evidence is audit-ready
- that evidence proves compliance

Map only to control categories:

- access control
- audit logging
- incident response
- risk management
- vendor/third-party risk
- configuration management
- data protection
- vulnerability management
- change management
- security monitoring
- identity and access management

## Current Files Added Or Updated

Spec pack:

```text
docs/specs/00_VISION.md
docs/specs/01_PRODUCT_REQUIREMENTS.md
docs/specs/02_ARCHITECTURE.md
docs/specs/03_SOC_WORKFLOWS.md
docs/specs/04_API_CONTRACT.md
docs/specs/05_DATA_MODEL.md
docs/specs/06_SOAR_INTEGRATION.md
docs/specs/07_MICROSOFT_INTEGRATION.md
docs/specs/08_AI_GUARDRAILS.md
docs/specs/09_ACTION_SAFETY_MODEL.md
docs/specs/10_GRC_HITRUST_ALIGNMENT.md
docs/specs/11_EVALUATION_PLAN.md
docs/specs/12_IMPLEMENTATION_ROADMAP.md
docs/specs/13_ACCEPTANCE_CRITERIA.md
docs/specs/14_DEMO_PLAN.md
docs/specs/15_HEALTHCARE_SAFEGUARD_GUARDRAILS.md
docs/specs/16_OPERATIONAL_READ_MODELS_AND_METRICS.md
docs/specs/17_ACCESS_CONTROL_AND_AUDIT_INTEGRITY.md
docs/specs/19_DEMO_SCENARIO_PACK_AND_API_CONTRACT.md
docs/specs/20_DATA_STRATEGY_AND_FIXTURE_FACTORY.md
docs/specs/22_DOCKER_COMPOSE_LOCAL_DEMO_PACKAGING.md
docs/specs/23_CSI_RGOI_FOUNDATION.md
docs/specs/24_DASHBOARD_UI_PREPARATION.md
docs/specs/25_DASHBOARD_UI_IMPLEMENTATION.md
docs/specs/26_PRODUCTION_DASHBOARD_HARDENING.md
docs/specs/SPEC_REVIEW_SUMMARY.md
docs/specs/V1_REUSE_ANALYSIS.md
```

Root docs:

```text
AGENTS.md
START_HERE.md
DECISIONS.md
LIMITATIONS.md
README.md
REPO_AUDIT.md
CHANGELOG.md
CONTRIBUTING.md
docs/USAGE.md
docs/EVALUATION.md
docs/DATASET.md
docs/MODEL_CARD.md
docs/DEPLOYMENT.md
docs/MONITORING.md
docs/TROUBLESHOOTING.md
docs/OPERATIONAL_READ_MODELS_AND_METRICS.md
docs/EVALUATION_HARNESS_AND_REGRESSION_DEFENSE_LABS.md
docs/DEMO_SCENARIO_PACK_AND_API_CONTRACT.md
docs/DATA_STRATEGY_AND_FIXTURE_FACTORY.md
docs/DOCKER_COMPOSE_LOCAL_DEMO_PACKAGING.md
docs/DASHBOARD_DATA_CONTRACT.md
docs/DASHBOARD_UI_IMPLEMENTATION.md
docs/DASHBOARD_PRODUCTION_HARDENING.md
docs/CSI_RGOI_ARCHITECTURE.md
docs/CSI_RGOI_WORKFLOWS.md
threatprism_v2_codex_handoff_brief.md
threatprism_v2_codex_spec_prompt.md
```

Current handoff:

```text
docs/THREATPRISM_V2_CODEX_HANDOFF.md
```

Current operational implementation additions:

```text
src/threatprism/cases/read_models.py
src/threatprism/evals/schemas.py
src/threatprism/evals/runner.py
src/threatprism/evals/cli.py
src/threatprism/demo/scenarios.py
tests/test_operational_read_models.py
tests/test_eval_harness.py
tests/test_demo_scenarios_and_api_contract.py
tests/test_fixture_factory.py
tests/test_csi_rgoi.py
tests/evals/regression_cases.jsonl
tests/evals/malformed_cases.jsonl
examples/demo_scenarios/demo_scenario_pack.json
examples/demo_scenarios/healthcare_safeguard_review_case.json
examples/csi/rgoi_cognitive_objects.json
examples/dashboard_contract/*.json
tools/check_demo_safety.py
tools/validate-threatprism.ps1
tools/generate-compact-handoff.ps1
tools/generate_compact_handoff.py
tools/fixture_factory/
data_sources/registry.json
external_datasets/README.md
external_datasets/.gitkeep
fixtures/generated/.gitkeep
.claude/commands/compact-handoff.md
Dockerfile
docker-compose.yml
.dockerignore
.github/workflows/safe-validation.yml
Lessons/Lesson10_Operational_Read_Models_And_Metrics.md
Lessons/Lesson11_Evaluation_Harness_And_Regression_Defense_Labs.md
Lessons/Lesson12_Demo_Operations_And_CI_Hardening.md
Lessons/Lesson13_Demo_Scenarios_And_API_Contract.md
Lessons/Lesson14_Docker_Compose_Local_Demo_Packaging.md
Lessons/Lesson15_Threat_Model_Treatment_And_Demo_Hardening.md
Lessons/Lesson16_Data_Strategy_And_Synthetic_Fixture_Factory.md
Lessons/Lesson17_Repo_Standards_Readiness_Pass.md
Lessons/Lesson18_CSI_RGOI_Foundation.md
Lessons/Lesson19_Dashboard_UI_Preparation.md
Lessons/Lesson20_Dashboard_UI_Implementation.md
Lessons/Lesson21_Production_Dashboard_Hardening.md
```

## Next Session Recommended Prompt

Use this:

```text
Read docs/THREATPRISM_V2_CODEX_HANDOFF.md first and treat it as the current source of truth.
If available, read START_HERE.md before the longer handoff docs.
Then read docs/ARCHITECTURAL_NORTH_STAR.md as the directional architecture guide.

Verify the live repo state before making changes. The original docs-only
handoff baseline is stale, and the previous final response leaked
drafting/debug text; trust the files and validation results over that message.

Continue with the next explicitly requested slice using a clean V2 architecture
with selective V1 concept porting.

Do not full-copy V1. Do not implement real remediation. Keep ALLOW_REAL_ACTIONS=false.

Start by inspecting `docs/specs/`, `src/threatprism/`, `tests/`,
`examples/soar_payloads/`, `examples/demo_scenarios/`, `pyproject.toml`,
`requirements.txt`, and
`.env.example`. Run:

powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1

Then continue only from evidence-backed gaps. Preserve the current fake-demo,
analyst-controlled, no-real-remediation boundary. Do not add production
dashboard deployment, live integrations, real data, external telemetry, or
production IdP integration unless the user explicitly changes scope. The
scenario pack, dashboard UI tests, and API contract tests are now the quickest
route/role smoke signals after the full validation wrapper.

If the next request is about datasets or more realistic fixtures, read
`docs/DATA_STRATEGY_AND_FIXTURE_FACTORY.md` and
`docs/specs/20_DATA_STRATEGY_AND_FIXTURE_FACTORY.md` before making changes.
Do not auto-download datasets or commit raw third-party data.

If the reused `.pytest_tmp_run_verify` folder is locked on Windows, rerun with a
fresh ignored base temp such as `.pytest_tmp_run_ops_ci`.
```
