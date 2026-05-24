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
models, manager-review and healthcare-review filters, and role-aware detail
routes for evidence, timeline, MITRE, GRC, and audit events.

The latest regression slice adds a local dry-run evaluation harness with fake
JSONL fixtures, sanitized eval artifacts, path traversal protection, and tests
for prompt injection, unsafe action claims, healthcare leakage, auth
escalation, read-model leakage, audit leakage, and compliance-language
overclaims.

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
  cases/          Case, triage report, feedback, read models, and service orchestration
  guardrails/     Prompt firewall, tokenization, policy, and evidence checks
  llm/            Provider interface and deterministic demo provider
  persistence/    SQLite demo repository
  reports/        Deterministic report rendering
  soar/           SOAR payload normalization
  enrichment/     Demo enrichment stubs
docs/specs/       Product, architecture, API, data, security, and demo specs
examples/         Fake demo SOAR payloads
tests/            API flow and guardrail tests
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

## Validate

Use the known-safe local validation command:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_verify
```

Current known result:

```text
41 passed
```

If Windows locks a reused pytest temp directory, rerun with a fresh ignored
`--basetemp` value.

## Run The API

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
$env:ALLOW_REAL_ACTIONS='false'
python -m uvicorn threatprism.api.app:create_app --factory --reload
```

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
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

The next recommended backend slice is Demo Operations & CI Hardening v0.1.
