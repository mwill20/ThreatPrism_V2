# 18 Demo Operations And CI Hardening

## Status

Implemented on 2026-05-24.

Validation:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1 -BaseTemp .pytest_tmp_run_threat_treatment_final2
```

Result:

```text
63 passed
```

Eval harness result:

```text
15 passed, 0 failed
```

## Goal

Make local validation, demo operation, and CI repeatable, fake-data-only, and
safe by default.

## Implemented Scope

- Safe PowerShell validation wrapper around the known-good pytest command.
- Demo safety scanner for environment, `.env.example`, gitignore, tracked
  artifacts, secret-looking content, runtime guard behavior, and eval artifact
  hygiene.
- Lightweight GitHub Actions workflow that runs fake-data-only tests and the
  eval harness.
- Tests proving the safety checker detects live-looking secrets, real-action
  validation environments, and unsafe eval artifacts.
- Runbook and documentation updates for API startup, SOAR intake, metrics,
  review queues, and eval execution.

## CI Contract

CI must:

- Set `ALLOW_REAL_ACTIONS=false`.
- Set `LLM_PROVIDER=deterministic_demo`.
- Avoid live provider credentials.
- Run `tools/check_demo_safety.py`.
- Run pytest with plugin autoload disabled.
- Run `python -m threatprism.evals.cli --fixtures regression_cases.jsonl`.
- Scan generated eval artifacts.

CI must not:

- Require live LLM credentials.
- Require live SOAR credentials.
- Call live cloud or enrichment providers.
- Execute remediation.
- Upload generated `.eval_runs/` artifacts unless a future redaction/export
  policy explicitly allows it.

## Acceptance Criteria

- Local validation can be run with one PowerShell command.
- Pytest uses a fresh ignored base temp and disables plugin autoload.
- Eval harness runs in deterministic dry-run mode.
- Safety checks fail if real actions are enabled.
- Safety checks fail if live provider credentials are present during
  validation.
- Safety checks fail if production-like settings use disabled or demo auth.
- Safety checks fail if generated runtime artifacts are tracked.
- Safety checks fail if eval artifacts contain forbidden raw sensitive values,
  raw payload markers, or token-vault mapping markers.
- CI runs without repository secrets.
- Docs, README, runbook, lessons, checklist, handoff, decisions, and
  limitations reflect the implemented state.

## Out Of Scope

- Live LLM, SOAR, cloud, or enrichment calls.
- Production credentials.
- Production IdP.
- Dashboard UI.
- Real healthcare or security data.
- Real remediation.
