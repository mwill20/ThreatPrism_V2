# Usage

ThreatPrism can be used locally as a FastAPI backend, through focused pytest
checks, through the dry-run eval harness, or through the synthetic fixture
factory. All current workflows are fake-data-only.

## Safe Defaults

Use these defaults unless a future slice explicitly changes scope:

```powershell
$env:THREATPRISM_ENV='demo'
$env:LLM_PROVIDER='deterministic_demo'
$env:ALLOW_REAL_ACTIONS='false'
```

Do not use real case data, live provider credentials, real remediation, real
organization data, or real healthcare records.

## Validate The Repository

```powershell
Set-Location C:\Projects\ThreatPrismV2
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

Expected current result:

```text
73 passed
eval harness dry-run: 15 passed / 0 failed
```

## Start The API

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
$env:THREATPRISM_ENV='demo'
$env:DATABASE_URL='sqlite:///./data/threatprism.db'
$env:API_AUTH_MODE='none'
$env:THREATPRISM_LOCAL_DEV_ACK='true'
$env:LLM_PROVIDER='deterministic_demo'
$env:ALLOW_REAL_ACTIONS='false'
python -m uvicorn threatprism.api.app:create_app --factory --reload
```

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

The response should include `allow_real_actions` set to `false`.

## Submit A Fake SOAR Case

```powershell
$payload = Get-Content -Raw .\examples\soar_payloads\generic_soar_case.json | ConvertFrom-Json
$created = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/cases -Body ($payload | ConvertTo-Json -Depth 20) -ContentType 'application/json'
$created.case_id
```

Fetch the triage report:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/cases/$($created.case_id)/triage-report"
```

Fetch metrics and queues:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/metrics
Invoke-RestMethod http://127.0.0.1:8000/queues/manager-review
Invoke-RestMethod http://127.0.0.1:8000/queues/healthcare-review
```

## Use Demo API-Key Roles

For role-aware views, start the API with demo-key auth:

```powershell
$env:API_AUTH_MODE='demo_key'
```

Then include the fake demo key:

```powershell
Invoke-RestMethod -Headers @{ 'X-ThreatPrism-Demo-Key' = 'demo-analyst-key' } `
  -Uri "http://127.0.0.1:8000/cases/$($created.case_id)/triage-report?role=analyst"
```

Role escalation is denied. A `?role=` parameter is a view request, not
authority.

## Run With Docker Compose

```powershell
Set-Location C:\Projects\ThreatPrismV2
docker compose up --build
```

The backend listens on `http://127.0.0.1:8000` with fake demo credentials,
deterministic demo triage, and `ALLOW_REAL_ACTIONS=false`.

Stop the service:

```powershell
docker compose down
```

## Run The Eval Harness

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -m threatprism.evals.cli --fixtures regression_cases.jsonl --output local
```

Eval artifacts are written under `.eval_runs/` and are ignored by git.

## Generate Synthetic Fixtures

Use only tiny, manually reviewed source-shape samples placed under
`external_datasets/`.

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -m tools.fixture_factory.factory --source synthea_sample_data --input external_datasets/synthea_sample --output fixtures/generated/synthea_healthcare.jsonl --limit 10
```

Generated fixtures remain ignored under `fixtures/generated/` until a future
manual license, safety, and content review approves promotion.
