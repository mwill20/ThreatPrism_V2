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
271 passed (3 skipped: opt-in live Prompt Guard 2 tests)
eval harness dry-run: 15 passed / 0 failed
```

## Run Tests Directly

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_ops_ci
```

Expected current result:

```text
271 passed (3 skipped)
```

If a reused temp directory is locked on Windows, use a new ignored
`--basetemp` directory.

## Run Demo Scenario And Contract Checks

Use this focused check when changing routes, response models, demo payloads, or
role-view behavior. It also checks CSI/RGOI route contracts and dashboard
contract fixtures:

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

Dashboard readiness contract fixtures live at:

```text
examples/dashboard_contract/
```

For dashboard contract review, use:

```text
docs/runbooks/DASHBOARD_READINESS.md
```

## Review Production Token Verifier Design

The production token verifier design is documentation-only. It does not enable
JWT parsing, JWKS fetch, live IdP calls, or production claim-to-role
authorization.

Read:

```text
docs/PRODUCTION_IDENTITY_READINESS.md
docs/PRODUCTION_TOKEN_VERIFIER_DESIGN.md
docs/runbooks/PRODUCTION_TOKEN_VERIFIER_DESIGN_REVIEW.md
```

Use fake OIDC example values only. Protected routes must still fail closed
under `API_AUTH_MODE=external_oidc` until a future implementation slice lands.

## Start The Dashboard

The local dashboard is served by the FastAPI backend and uses fake demo
credentials only:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
$env:THREATPRISM_ENV='demo'
$env:API_AUTH_MODE='demo_key'
$env:DEMO_API_KEYS='demo-analyst-key:demo_analyst:analyst,demo-engineer-key:demo_engineer:engineer,demo-manager-key:demo_manager:manager_grc,demo-legal-key:demo_legal:legal_privacy,demo-audit-key:demo_audit:audit_debug,demo-admin-key:demo_admin:admin'
$env:THREATPRISM_AUTH_REQUIRED='true'
$env:LLM_PROVIDER='deterministic_demo'
$env:ALLOW_REAL_ACTIONS='false'
$env:DATABASE_URL='sqlite:///:memory:'
python -m uvicorn threatprism.api.app:create_app --factory --host 127.0.0.1 --port 8765
```

Open:

```text
http://127.0.0.1:8765/dashboard
```

Expected dashboard posture:

- `ALLOW_REAL_ACTIONS=false` is displayed.
- Persona tabs work by mouse and keyboard.
- Dashboard responses include CSP, no-sniff, frame-deny, no-referrer,
  permissions, same-origin resource, and no-store headers.
- Dashboard requests stay same-origin and use fake demo credentials only.

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

Confirm the API is healthy:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

The response should show `allow_real_actions` as `false`.

## Start With Docker Compose

Use this when you want repeatable local backend startup without setting a
Python virtual environment manually:

```powershell
Set-Location C:\Projects\ThreatPrismV2
docker compose up --build
```

The service runs at `http://127.0.0.1:8000` with fake demo API-key
authentication, deterministic demo triage, empty live-provider credential
variables, and `ALLOW_REAL_ACTIONS=false`.

Stop the service:

```powershell
docker compose down
```

Reset the demo SQLite volume:

```powershell
docker compose down -v
```

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

Query read-only CSI/RGOI cognition:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/csi/objects?tenant_id=tenant_demo_alpha&query=identity"
Invoke-RestMethod "http://127.0.0.1:8000/csi/lineage/cog_reason_alpha_human_001?tenant_id=tenant_demo_alpha"
Invoke-RestMethod "http://127.0.0.1:8000/csi/replay/cog_reason_alpha_human_001?tenant_id=tenant_demo_alpha"
Invoke-RestMethod "http://127.0.0.1:8000/csi/observability?tenant_id=tenant_demo_alpha"
Invoke-RestMethod "http://127.0.0.1:8000/csi/divergence?tenant_id=tenant_demo_alpha"
```

CSI/RGOI routes are retrieval-only. They do not write memory, mutate trust,
approve knowledge, publish suppressions, run live RAG, or execute remediation.

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

## Generate Synthetic Fixtures

Use this only with tiny source-shape samples that were manually reviewed and
placed under `external_datasets/`. The factory is local-only and does not
download data.

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -m tools.fixture_factory.factory --source synthea_sample_data --input external_datasets/synthea_sample --output fixtures/generated/synthea_healthcare.jsonl --limit 10
```

Factory guardrails:

- Input paths must stay under `external_datasets/`.
- Output paths must stay under `fixtures/generated/`.
- Existing output files require `--force`.
- Generated JSONL is ignored by git and must be manually reviewed before any
  curated sample is promoted into tracked tests or eval fixtures.
- Tracked curated fixtures live under `fixtures/curated/` and require a
  manifest entry with approved license, safety, and content review status.

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
