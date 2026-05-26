# Production Token Verifier Local Validation Runbook

Use this runbook to validate the local no-network token verifier.

## Safety Rules

- Use fake local keys only.
- Keep `ALLOW_REAL_ACTIONS=false`.
- Keep `PRODUCTION_IDENTITY_JWKS_FETCH_ENABLED=false`.
- Do not use real issuer URLs, tenant IDs, audiences, groups, users,
  credentials, private keys, workplace data, or production telemetry.
- Do not call live OIDC discovery, JWKS, Entra, Graph, cloud, SOAR, LLM, or
  enrichment endpoints.

## Focused Tests

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest tests\test_production_identity_readiness.py tests\test_production_token_verifier.py -p no:cacheprovider --basetemp .pytest_tmp_token_verifier_focus
```

Expected focused behavior:

- Static `external_oidc` readiness still passes with verifier disabled.
- Verifier enablement fails closed unless local fake JWKS, tenant allowlist,
  role mapping, and no-network settings are complete.
- Valid fake signed tokens can authorize protected routes.
- Invalid tokens fail closed.
- Audit events contain hashes and reason codes, not raw token material.
- Network sockets are not used by the verifier.

## Full Validation

```powershell
Set-Location C:\Projects\ThreatPrismV2
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

The standard wrapper must remain fake-data-only and offline. Live IdP smoke
tests are not part of this repository baseline.
