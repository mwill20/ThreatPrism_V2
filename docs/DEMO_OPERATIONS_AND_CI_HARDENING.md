# Demo Operations And CI Hardening

Demo Operations & CI Hardening v0.1 is implemented.

This slice makes ThreatPrism easier to run, validate, and review without
opening live-provider or production-impacting paths.

## Implemented Files

```text
tools/check_demo_safety.py
tools/validate-threatprism.ps1
.github/workflows/safe-validation.yml
tests/test_ops_safety.py
```

## Local Validation

Use the safe wrapper from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

The wrapper sets:

```text
PYTHONPATH=src
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
THREATPRISM_ENV=test
API_AUTH_MODE=none
THREATPRISM_AUTH_REQUIRED=true
THREATPRISM_LOCAL_DEV_ACK=true
LLM_PROVIDER=deterministic_demo
ALLOW_REAL_ACTIONS=false
```

It also clears live-provider credential variables for the validation process.

The wrapper runs:

1. `python tools/check_demo_safety.py --include-untracked`
2. Advisory-only `python -m pip_audit -r requirements.txt` when `pip-audit`
   is installed locally.
3. `python -m pytest -p no:cacheprovider --basetemp <fresh temp>`
4. `python -m threatprism.evals.cli --fixtures regression_cases.jsonl --output ops_ci`
5. `python tools/check_demo_safety.py --scan-eval-artifacts`

## CI

The lightweight GitHub Actions workflow runs the same fake-only validation
shape:

```text
.github/workflows/safe-validation.yml
```

The workflow installs local requirements, runs the demo safety checker, runs
pytest, runs the dry-run eval harness, and scans eval artifacts.

It does not require live credentials and does not call live LLM, SOAR, cloud,
enrichment, or remediation providers.

## Safety Checks

`tools/check_demo_safety.py` fails closed when it detects:

- `ALLOW_REAL_ACTIONS=true` in the validation environment.
- Live-provider credential environment variables set during validation.
- Production-like environment paired with disabled or demo auth.
- Disabled auth without explicit local-development acknowledgement.
- Missing exact dependency pins or missing `requirements-lock.txt`.
- `.env.example` defaults that require live credentials or real actions.
- Missing required ignored artifact patterns.
- Tracked eval outputs, pytest temp folders, local databases, bytecode, or
  runtime data artifacts.
- Live-looking API keys or private key material in scanned repository files.
- Forbidden raw fixture values, raw payload markers, or token-vault mapping
  markers in generated eval artifacts.

## Boundaries

This slice does not add:

- Live LLM calls.
- Live SOAR calls.
- Cloud or enrichment calls.
- Production credentials.
- Production identity provider integration.
- Dashboard UI.
- Real healthcare data.
- Real remediation.

## Validation

Current validation on 2026-05-24 with:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1 -BaseTemp .pytest_tmp_run_threat_treatment_final2
```

Original slice validation result:

```text
63 passed
```

The eval harness also reported:

```text
"total": 15
"passed": 15
"failed": 0
```

## Next Slice

Demo Scenario Pack & API Contract Freeze v0.1 is now implemented.

It stays fake-data-only and backend-only, with scenario-pack smoke tests and
OpenAPI contract checks for the current route surface.
