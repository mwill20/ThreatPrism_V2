# Evaluation Harness And Regression Defense Labs

Evaluation Harness & Regression Defense Labs v0.1 is implemented.

This slice adds a local dry-run regression harness that proves ThreatPrism
fails safely against known bad or ambiguous inputs before live LLMs, live SOAR,
cloud calls, dashboard work, production persistence, or real remediation are
added.

## Implemented Files

```text
src/threatprism/evals/schemas.py
src/threatprism/evals/runner.py
src/threatprism/evals/cli.py
tests/evals/regression_cases.jsonl
tests/evals/malformed_cases.jsonl
tests/test_eval_harness.py
```

## Eval Categories

The fake fixture suite covers:

- Prompt injection.
- Hallucinated claims.
- Unsafe action claims.
- Schema violations.
- Unsupported evidence citations.
- Healthcare safeguard leakage.
- Authorization escalation.
- Cross-role data leakage.
- Metrics/read-model leakage.
- Audit-event leakage.
- Token-vault mapping exposure.
- Compliance-language overclaiming.
- Benign/suspicious ambiguity.
- Oversized payload handling.
- Malformed JSON handling.
- Conflicting evidence handling.

## Safety Rules

The harness:

- Uses deterministic local checks only.
- Reads fixtures only from `tests/evals/`.
- Writes artifacts only under `.eval_runs/`.
- Rejects path traversal.
- Stores sanitized previews, not raw payload bodies.
- Avoids raw potential PHI/ePHI, secrets, credentials, authorization headers,
  and token vault mappings in eval artifacts.
- Keeps `ALLOW_REAL_ACTIONS=false`.

The harness does not prove live-LLM safety, HIPAA compliance, HITRUST
certification, audit readiness, or production readiness. It is a regression
safety gate for the current deterministic and controlled fake-provider failure
modes.

## Run Locally

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -m threatprism.evals.cli --fixtures regression_cases.jsonl
```

The command writes sanitized eval artifacts to `.eval_runs/<run_id>/`.

## Validation

Validated on 2026-05-24 with:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_eval_harness_final4
```

Result:

```text
41 passed
```

## Next Slice

The next recommended slice is Demo Operations & CI Hardening v0.1.

Reason: the backend, guardrails, access control, read models, and eval harness
are now locally validated. The next confidence step is repeatable developer
operations: safe CI, run scripts, artifact hygiene, and demo/runbook hardening
without adding live integrations or dashboard UI.
