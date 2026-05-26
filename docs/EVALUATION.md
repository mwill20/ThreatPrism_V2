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
8. Does the local dashboard serve same-origin assets, use fake demo
   credentials, preserve API protection, reference the documented contract, and
   remain responsive across desktop and mobile breakpoints?
9. Do dashboard hardening checks enforce security headers, same-origin request
   targets, timeout-bounded API calls, and keyboard persona navigation markers?
10. Does curated fixture promotion require explicit manifest review, reject
    generated-folder paths, preserve scenario coverage, and keep promoted
    fixtures schema-valid and sanitized?
11. Does production identity readiness reject unsafe auth modes, require static
    OIDC-shaped config, reject incomplete verifier enablement, and keep
    protected routes fail-closed when verification is disabled?
12. Does the local production token verifier preserve no-network validation,
    fail-closed semantics, verified-claims-only authorization, role-view
    policy enforcement, and sanitized audit requirements?

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

Validated during the Production Token Verifier Implementation pass with:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1 -BaseTemp .pytest_tmp_token_verifier_impl_final2
```

Result:

```text
112 passed
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
| Curated fixture promotion | `fixtures/curated/*.jsonl`, `tests/test_curated_fixture_promotion.py` |
| CSI/RGOI governed cognition | `tests/test_csi_rgoi.py` |
| Dashboard contract fixtures | `examples/dashboard_contract/*.json`, `tests/test_demo_scenarios_and_api_contract.py` |
| Dashboard UI and hardening | `src/threatprism/dashboard/static/`, `tests/test_dashboard_ui.py` |
| Production identity readiness | `src/threatprism/auth/production.py`, `tests/test_production_identity_readiness.py` |
| Production token verifier | `src/threatprism/auth/production.py`, `tests/test_production_token_verifier.py`, `docs/PRODUCTION_TOKEN_VERIFIER_IMPLEMENTATION.md` |

## Known Evaluation Limits

- No live LLM calls are evaluated.
- No live SOAR, cloud, enrichment, or remediation providers are evaluated.
- No live production IdP, OIDC discovery, or JWKS fetch is evaluated. Local
  fake-JWKS token verification is evaluated.
- No real PHI, PII, secrets, workplace data, or production telemetry is used.
- No performance, latency, or load-test benchmark has been measured.
- No external penetration test, production security review, or deployment
  reliability test has been performed.
