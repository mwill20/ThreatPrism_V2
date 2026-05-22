# ThreatPrism V2 Codex Handoff

## Read This First

This handoff is the current source of truth for continuing ThreatPrism V2 work in this workspace.

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
  disagreement, evidence, GRC, MITRE, action, and audit schemas plus the case
  service orchestration.
- `src/threatprism/soar/generic.py` with generic SOAR payload normalization.
- `src/threatprism/guardrails/` with prompt firewall, tokenization,
  output-policy scanning, evidence-grounding checks, and action-safety checks.
- `src/threatprism/llm/providers.py` with a deterministic demo provider.
- `src/threatprism/persistence/sqlite.py` with SQLite demo persistence.
- `src/threatprism/reports/render.py` with deterministic report rendering.
- `examples/soar_payloads/` with fake demo payloads only.
- `tests/test_api_flow.py` and `tests/test_guardrails.py` covering the current
  API flow and guardrail behavior.

Validated on 2026-05-21 with:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_new
```

Result:

```text
13 passed
```

If rerunning the exact command fails with a Windows `WinError 5` while cleaning
the reused `.pytest_tmp_run_new` directory, use a fresh ignored base temp such
as:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_verify
```

The destination repo remains `mwill20/ThreatPrism_V2`. The local workspace at
`C:\Projects\ThreatPrismV2` may not be initialized as a Git checkout; verify
before making git claims.

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
2. `docs/specs/00_VISION.md`
3. `docs/specs/01_PRODUCT_REQUIREMENTS.md`
4. `docs/specs/02_ARCHITECTURE.md`
5. `docs/specs/04_API_CONTRACT.md`
6. `docs/specs/05_DATA_MODEL.md`
7. `docs/specs/08_AI_GUARDRAILS.md`
8. `docs/specs/09_ACTION_SAFETY_MODEL.md`
9. `docs/specs/10_GRC_HITRUST_ALIGNMENT.md`
10. `docs/specs/V1_REUSE_ANALYSIS.md`
11. `DECISIONS.md`
12. `LIMITATIONS.md`
13. `AGENTS.md`

The older root handoff and prompt files were updated for path and repo target, but this current handoff should be treated as the latest continuation brief.

## Key Locked Decisions

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

## First Implementation Slice

The first vertical slice is now partially implemented. Continue to verify the
live repo before assuming completion, but the current target remains:

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

Do not implement:

- real remediation actions
- full threat intelligence integrations
- a frontend dashboard
- MSSP multi-tenancy
- live SOAR credential flows

## Recommended Initial Module Layout

Use a clean structure rather than copying V1 layout wholesale:

```text
src/threatprism/
  api/
  cases/
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
GET /cases/{case_id}
GET /cases/{case_id}/triage-report
POST /cases/{case_id}/analyst-feedback
```

Document or stub later:

```text
GET /metrics
GET /cases/{case_id}/evidence
GET /cases/{case_id}/timeline
GET /cases/{case_id}/ioc-enrichment
GET /cases/{case_id}/mitre
GET /cases/{case_id}/grc-controls
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
docs/specs/SPEC_REVIEW_SUMMARY.md
docs/specs/V1_REUSE_ANALYSIS.md
```

Root docs:

```text
AGENTS.md
DECISIONS.md
LIMITATIONS.md
threatprism_v2_codex_handoff_brief.md
threatprism_v2_codex_spec_prompt.md
```

Current handoff:

```text
docs/THREATPRISM_V2_CODEX_HANDOFF.md
```

## Next Session Recommended Prompt

Use this:

```text
Read docs/THREATPRISM_V2_CODEX_HANDOFF.md first and treat it as the current source of truth.

Verify the live repo state before making changes. The original docs-only
handoff baseline is stale, and the previous final response leaked
drafting/debug text; trust the files and validation results over that message.

Continue the first implementation slice using a clean V2 architecture with selective V1 module porting.

Do not full-copy V1. Do not implement real remediation. Keep ALLOW_REAL_ACTIONS=false.

Start by inspecting `docs/specs/`, `src/threatprism/`, `tests/`,
`examples/soar_payloads/`, `pyproject.toml`, `requirements.txt`, and
`.env.example`. Run:

$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_new

Then continue only from evidence-backed gaps. Preserve the current fake-demo,
analyst-controlled, no-real-remediation boundary.

If the reused `.pytest_tmp_run_new` folder is locked on Windows, rerun with a
fresh ignored base temp such as `.pytest_tmp_run_verify`.
```
