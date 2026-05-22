# ThreatPrism

ThreatPrism is a demo-safe SOC migration accelerator for organizations moving
from outsourced SOC operations toward an internal SOC model.

The current repository contains the V2 spec pack plus the first backend slice:
generic SOAR case intake, case normalization, guardrails, deterministic demo
triage, SQLite persistence, FastAPI routes, fake SOAR payloads, and initial
tests.

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
  cases/          Case, triage report, feedback, and service orchestration
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
13 passed
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

## Active Checklist

Track current work in `docs/WORKING_CHECKLIST.md`.

The next planned slice is Healthcare Safeguard & Evidence Alignment Guardrails
v0.1. See `docs/HEALTHCARE_SAFEGUARD_GUARDRAILS.md` and
`docs/specs/15_HEALTHCARE_SAFEGUARD_GUARDRAILS.md`.
