# Evaluation

ThreatPrism currently uses deterministic local validation, pytest coverage, and
a fake-data dry-run eval harness. This is regression evidence for the current
demo-safe backend, not a live-LLM safety proof or production-readiness claim.

## Evaluation Questions

1. Does the backend accept fake SOAR payloads and produce structured case and
   triage outputs?
2. Do prompt-injection, evidence, healthcare, authorization, and action-safety
   guardrails fail closed where expected?
3. Do role-aware reads avoid leaking raw potential PHI/ePHI, secrets,
   credentials, raw payload bodies, and token vault mappings?
4. Does the eval harness reject unsafe paths and produce sanitized artifacts?
5. Does the fixture factory generate deterministic, sanitized, schema-valid
   ThreatPrism-native fixtures without network calls?
6. Does CSI/RGOI enforce read-only retrieval governance, tenant isolation,
   evidence alignment, trust scoring, stale cognition controls, and
   AI-vs-human divergence telemetry?
7. Do dashboard-prep fixtures and API contract tests preserve the documented
   backend surfaces without adding frontend UI or unsafe data?

## Current Validation Command

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

The wrapper:

- clears live-provider credential variables for the validation process
- sets fake-only defaults
- runs `tools/check_demo_safety.py`
- runs pytest with plugin autoload disabled
- runs the dry-run eval harness
- scans eval artifacts for forbidden raw values

## Current Recorded Result

Validated during the Dashboard UI Preparation pass with:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1 -BaseTemp .pytest_tmp_dashboard_prep_final_validation
```

Result:

```text
83 passed
eval harness dry-run: 15 passed / 0 failed
```

## Coverage Summary

| Area | Evidence |
|---|---|
| API flow | `tests/test_api_flow.py` |
| Access control | `tests/test_access_control.py` |
| Guardrails | `tests/test_guardrails.py`, `tests/test_guardrail_failures.py` |
| Healthcare safeguards | `tests/test_healthcare_guardrails.py`, `tests/test_phi_detector_coverage.py` |
| Read models and metrics | `tests/test_operational_read_models.py` |
| Eval harness | `tests/test_eval_harness.py`, `tests/evals/*.jsonl` |
| Demo safety | `tests/test_ops_safety.py`, `tools/check_demo_safety.py` |
| Demo scenarios and API contract | `tests/test_demo_scenarios_and_api_contract.py` |
| Docker packaging | `tests/test_docker_packaging.py` |
| Fixture factory | `tests/test_fixture_factory.py` |
| CSI/RGOI governed cognition | `tests/test_csi_rgoi.py` |
| Dashboard contract fixtures | `examples/dashboard_contract/*.json`, `tests/test_demo_scenarios_and_api_contract.py` |

## Known Evaluation Limits

- No live LLM calls are evaluated.
- No live SOAR, cloud, enrichment, or remediation providers are evaluated.
- No real PHI, PII, secrets, workplace data, or production telemetry is used.
- No performance, latency, or load-test benchmark has been measured.
- No external penetration test, production security review, or deployment
  reliability test has been performed.
