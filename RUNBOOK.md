# ThreatPrism Local Runbook

This runbook covers the current demo-safe backend slice. It must not be used
with real case data, live provider credentials, or production-impacting actions.

## Preconditions

- Work from `C:\Projects\ThreatPrismV2`.
- Start new AI chats from `START_HERE.md` instead of pasting long handoff docs.
- Use fake payloads from `examples/soar_payloads/`.
- Keep `ALLOW_REAL_ACTIONS=false`.
- Do not run live LLM, SOAR, cloud, or enrichment calls unless explicitly
  requested and intentionally configured.

## Install Dependencies

```powershell
Set-Location C:\Projects\ThreatPrismV2
python -m pip install -r requirements.txt
```

## Generate A Compact Handoff Prompt

Use this before starting a fresh chat or when context is approaching 75% used:

```powershell
Set-Location C:\Projects\ThreatPrismV2
powershell -ExecutionPolicy Bypass -File .\tools\generate-compact-handoff.ps1
```

Claude Code users can run `/compact-handoff`. Codex users can ask for
`compact handoff`.

## Run Safe Validation

Use the wrapper for local validation:

```powershell
Set-Location C:\Projects\ThreatPrismV2
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

The wrapper sets fake-only environment defaults, clears live provider
credential variables for the validation process, runs the demo safety checker,
runs pytest with plugin autoload disabled, runs the dry-run eval harness, and
checks eval artifacts for forbidden raw values.

Expected current result:

```text
63 passed
```

## Run Tests Directly

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_ops_ci
```

Expected current result:

```text
63 passed
```

If a reused temp directory is locked on Windows, use a new ignored
`--basetemp` directory.

## Run Demo Scenario And Contract Checks

Use this focused check when changing routes, response models, demo payloads, or
role-view behavior:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest tests\test_demo_scenarios_and_api_contract.py -p no:cacheprovider --basetemp .pytest_tmp_run_demo_contract_focus
```

Expected focused result:

```text
4 passed
```

The scenario definitions live at:

```text
examples/demo_scenarios/demo_scenario_pack.json
```

They cover analyst, manager/GRC, legal/privacy, audit/debug, and engineer
workflows using fake payloads and fake demo credentials only.

## Start The API

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
$env:THREATPRISM_ENV='demo'
$env:DATABASE_URL='sqlite:///./data/threatprism.db'
$env:LLM_PROVIDER='deterministic_demo'
$env:ALLOW_REAL_ACTIONS='false'
python -m uvicorn threatprism.api.app:create_app --factory --reload
```

Confirm the API is healthy:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

The response should show `allow_real_actions` as `false`.

## Run The Demo Flow

Create a case from the fake generic SOAR payload:

```powershell
$payload = Get-Content -Raw .\examples\soar_payloads\generic_soar_case.json | ConvertFrom-Json
$created = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/cases -Body ($payload | ConvertTo-Json -Depth 20) -ContentType 'application/json'
$created.case_id
```

Fetch the normalized case:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/cases/$($created.case_id)"
```

Fetch the triage report:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/cases/$($created.case_id)/triage-report"
```

Fetch metrics and review queues:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/metrics
Invoke-RestMethod http://127.0.0.1:8000/queues/manager-review
Invoke-RestMethod http://127.0.0.1:8000/queues/healthcare-review
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
python -m threatprism.evals.cli --fixtures regression_cases.jsonl --output local
python tools\check_demo_safety.py --scan-eval-artifacts
```

Eval outputs are generated under `.eval_runs/` and are ignored by git. Do not
move generated eval artifacts into tracked docs or test fixtures.

## Troubleshooting

- If imports fail while running Uvicorn, confirm `$env:PYTHONPATH='src'`.
- If tests fail while cleaning `.pytest_tmp_run_verify`, rerun with a fresh
  `--basetemp` value.
- If reports mention real action execution, treat that as a blocker. The action
  safety scanner must fail closed.
- If demo payloads contain real workplace or user data, stop and replace them
  with reserved domains, documentation IP ranges, and synthetic identifiers.

## Stop Criteria

Stop and document a blocker if any next step requires:

- Real remediation.
- Live external credentials.
- Real case or workplace data.
- HITRUST compliance or certification claims.
- Full-copying V1 into this repository.
