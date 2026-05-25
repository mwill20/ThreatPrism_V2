# ThreatPrism

ThreatPrism is a demo-safe SOC migration accelerator for organizations moving
from outsourced SOC operations toward an internal SOC model.

The current repository contains the V2 spec pack plus the first backend slice:
generic SOAR case intake, case normalization, guardrails, deterministic demo
triage, SQLite persistence, FastAPI routes, fake SOAR payloads, and initial
tests.

The latest implemented guardrail slice also includes context-aware healthcare
safeguards, typed sensitive-data tokens, role-based rendering helpers, and
compliance-language scanning for healthcare/GRC claims.

The latest backend security slice adds demo API-key authentication,
identity-to-role mapping, role-view authorization, and safe authorization audit
events for role-aware case and report reads.

The latest operational slice adds safe metrics, dashboard-ready case-list read
models, manager-review and healthcare-review queue routes, filters, and
role-aware detail routes for evidence, timeline, MITRE, GRC, and audit events.

The latest regression slice adds a local dry-run evaluation harness with fake
JSONL fixtures, sanitized eval artifacts, path traversal protection, and tests
for prompt injection, unsafe action claims, healthcare leakage, auth
escalation, read-model leakage, audit leakage, and compliance-language
overclaims.

The latest operations slice adds a safe validation wrapper, a fake-data-only CI
workflow, a demo safety scanner, eval artifact hygiene checks, and runbook
updates for repeatable local and CI validation.

The latest demo slice adds a repeatable fake scenario pack for analyst,
manager/GRC, legal/privacy, audit/debug, and engineer workflows, plus OpenAPI
contract tests for the current backend routes.

The latest packaging slice adds Docker Compose local demo packaging for the
existing fake-data FastAPI backend, with deterministic demo defaults and no
live providers.

The latest data-realism slice adds a safe, deterministic synthetic fixture
factory that converts explicit local, manually reviewed source-shape samples
into sanitized ThreatPrism-native JSONL fixtures without downloads, live
providers, raw dataset commits, or baseline test auto-scanning.

## Current Boundaries

- Demo data only.
- No real remediation or containment.
- `ALLOW_REAL_ACTIONS=false` by default.
- No live LLM, SOAR, cloud, or enrichment calls are required for the current
  slice.
- HITRUST output is category/alignment mapping only, not compliance or
  certification.
- V2 uses a clean architecture with selective V1 concept porting. Do not
  full-copy V1 into this repository.

## Project Layout

```text
src/threatprism/
  api/            FastAPI application factory and routes
  auth/           Demo authentication and role-view authorization
  cases/          Case, triage report, feedback, read models, and service orchestration
  evals/          Local dry-run regression evaluation harness
  demo/           Typed fake scenario-pack loading
  guardrails/     Prompt firewall, tokenization, policy, and evidence checks
  llm/            Provider interface and deterministic demo provider
  persistence/    SQLite demo repository
  reports/        Deterministic report rendering
  soar/           SOAR payload normalization
  enrichment/     Demo enrichment stubs
docs/specs/       Product, architecture, API, data, security, and demo specs
examples/         Fake demo SOAR payloads and scenario packs
tests/            API, guardrail, read-model, eval, and safety tests
tools/            Safe local validation and demo safety checks
tools/fixture_factory/
                  Local-only synthetic fixture factory
data_sources/     Review-required source registry
external_datasets/
                  Ignored local-only reviewed source sample staging
fixtures/generated/
                  Ignored generated fixture output
.github/          Fake-data-only CI workflow
Dockerfile        Local demo backend image
docker-compose.yml Local demo backend service
```

## Setup

From PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If you do not use a virtual environment, run the same install command from the
project root.

## Start A New AI Chat

Do not paste long handoff docs into a new chat. Use the compact startup file:

```powershell
Set-Location C:\Projects\ThreatPrismV2
Get-Content .\START_HERE.md
```

Generate a fresh compact handoff prompt:

```powershell
Set-Location C:\Projects\ThreatPrismV2
powershell -ExecutionPolicy Bypass -File .\tools\generate-compact-handoff.ps1
```

Claude Code users can run `/compact-handoff`. Codex users can ask for
`compact handoff` to trigger the global handoff skill.

## Validate

Use the safe local validation wrapper:

```powershell
Set-Location C:\Projects\ThreatPrismV2
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

The wrapper runs:

- Demo safety checks.
- Pytest with plugin autoload disabled and a fresh temp directory.
- The dry-run eval harness against fake fixtures.
- Eval artifact hygiene checks.

Current known result:

```text
73 passed
eval harness dry-run: 15 passed / 0 failed
```

The underlying pytest command remains:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_ops_ci
```

Run only the safety checker:

```powershell
python tools\check_demo_safety.py --include-untracked
```

If Windows locks a reused pytest temp directory, rerun with a fresh ignored
`--basetemp` value.

## Generate Synthetic Fixtures

The fixture factory is local-only and requires explicit reviewed source samples
under `external_datasets/`. It does not download datasets and does not promote
generated fixtures into baseline tests automatically.

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -m tools.fixture_factory.factory --source synthea_sample_data --input external_datasets/synthea_sample --output fixtures/generated/synthea_healthcare.jsonl --limit 10
```

Output is written under `fixtures/generated/`, which is ignored by git except
for the placeholder file. Review generated fixtures manually before promoting
any curated sample into tracked tests or eval fixtures.

Run only the demo scenario and API contract checks:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest tests\test_demo_scenarios_and_api_contract.py -p no:cacheprovider --basetemp .pytest_tmp_run_demo_contract_focus
```

Expected focused result:

```text
4 passed
```

## Run The API

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
$env:API_AUTH_MODE='none'
$env:THREATPRISM_LOCAL_DEV_ACK='true'
$env:ALLOW_REAL_ACTIONS='false'
python -m uvicorn threatprism.api.app:create_app --factory --reload
```

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

## Run With Docker Compose

```powershell
Set-Location C:\Projects\ThreatPrismV2
docker compose up --build
```

The Compose service runs the same backend at `http://127.0.0.1:8000` with
`API_AUTH_MODE=demo_key`, fake demo credentials,
`LLM_PROVIDER=deterministic_demo`, and `ALLOW_REAL_ACTIONS=false`.

Stop the container:

```powershell
docker compose down
```

## Demo SOAR Intake

Submit the fake generic SOAR payload:

```powershell
$payload = Get-Content -Raw .\examples\soar_payloads\generic_soar_case.json | ConvertFrom-Json
$created = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/cases -Body ($payload | ConvertTo-Json -Depth 20) -ContentType 'application/json'
$created
```

Fetch the triage report:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/cases/$($created.case_id)/triage-report"
```

Fetch operational metrics:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/metrics
```

Fetch the dashboard-ready case-list envelope:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/cases/read-model?manager_review_required=false"
```

Read dedicated review queues:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/queues/manager-review"
Invoke-RestMethod "http://127.0.0.1:8000/queues/healthcare-review"
```

Submit analyst feedback:

```powershell
$feedback = @{
  analyst_id = 'analyst_demo_001'
  analyst_determination = 'benign'
  analyst_severity = 'low'
  analyst_confidence = 0.76
  analyst_final_disposition = 'close'
  analyst_notes = 'Synthetic review for local demo.'
  false_positive = $true
  missed_escalation = $true
}

Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/cases/$($created.case_id)/analyst-feedback" -Body ($feedback | ConvertTo-Json -Depth 20) -ContentType 'application/json'
```

## Run The Eval Harness

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -m threatprism.evals.cli --fixtures regression_cases.jsonl
```

Eval artifacts are written under `.eval_runs/<run_id>/` and contain sanitized
previews only.

## Active Checklist

Track current work in `docs/WORKING_CHECKLIST.md`.

Use `docs/ARCHITECTURAL_NORTH_STAR.md` as the directional architecture guide
before starting a new slice, accepting a workaround, or adding a major
enhancement.

## Learning Curriculum

Use `Lessons/00_Index.md` for a hands-on curriculum that teaches the current
backend slices, guardrails, tests, and next implementation direction.

The completed healthcare safeguard slice is documented in
`docs/HEALTHCARE_SAFEGUARD_GUARDRAILS.md` and
`docs/specs/15_HEALTHCARE_SAFEGUARD_GUARDRAILS.md`.

Access Control & Audit Integrity v0.1 is implemented. See
`docs/ACCESS_CONTROL_AND_AUDIT_INTEGRITY.md` and
`docs/specs/17_ACCESS_CONTROL_AND_AUDIT_INTEGRITY.md`.

Operational Read Models & Metrics API v0.1 is implemented. See
`docs/OPERATIONAL_READ_MODELS_AND_METRICS.md` and
`docs/specs/16_OPERATIONAL_READ_MODELS_AND_METRICS.md`.

Evaluation Harness & Regression Defense Labs v0.1 is implemented. See
`docs/EVALUATION_HARNESS_AND_REGRESSION_DEFENSE_LABS.md` and
`docs/specs/11_EVALUATION_PLAN.md`.

Demo Operations & CI Hardening v0.1 is implemented. See
`docs/DEMO_OPERATIONS_AND_CI_HARDENING.md` and
`docs/specs/18_DEMO_OPERATIONS_AND_CI_HARDENING.md`.

Demo Scenario Pack & API Contract Freeze v0.1 is implemented. See
`docs/DEMO_SCENARIO_PACK_AND_API_CONTRACT.md`,
`docs/specs/19_DEMO_SCENARIO_PACK_AND_API_CONTRACT.md`, and
`examples/demo_scenarios/demo_scenario_pack.json`.

Data Strategy & Synthetic Fixture Factory v0.1 is implemented. See
`docs/DATA_STRATEGY_AND_FIXTURE_FACTORY.md`,
`docs/specs/20_DATA_STRATEGY_AND_FIXTURE_FACTORY.md`,
`data_sources/registry.json`, and `tools/fixture_factory/`. Public or
synthetic datasets must be manually reviewed, kept out of git as raw data, and
converted into sanitized ThreatPrism-native fixtures before use.

Docker Compose & Local Demo Packaging v0.1 is implemented. See
`docs/DOCKER_COMPOSE_LOCAL_DEMO_PACKAGING.md`,
`docs/specs/22_DOCKER_COMPOSE_LOCAL_DEMO_PACKAGING.md`, `Dockerfile`, and
`docker-compose.yml`.
