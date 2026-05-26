# Production Identity Readiness Runbook

Use this runbook to review the static production identity readiness boundary.
It is not a production deployment procedure.

For the verifier contract and local implementation, read
`docs/PRODUCTION_TOKEN_VERIFIER_DESIGN.md` and
`docs/PRODUCTION_TOKEN_VERIFIER_IMPLEMENTATION.md`. The runtime still fails
closed under `external_oidc` unless local fake-JWKS verification is explicitly
enabled and complete.

## Safety Rules

- Use fake example values only.
- Keep `ALLOW_REAL_ACTIONS=false`.
- Do not use real issuer URLs, tenant IDs, audiences, users, groups, roles,
  secrets, or credentials.
- Do not expect protected API routes to authorize requests under
  `external_oidc` unless local no-network verification is enabled with fake
  JWKS config.

## Static Readiness Smoke Test

From the repository root:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
$env:THREATPRISM_ENV='production'
$env:API_AUTH_MODE='external_oidc'
$env:PRODUCTION_IDENTITY_PROVIDER='entra_oidc'
$env:PRODUCTION_IDENTITY_ISSUER='https://idp.example.com/tenant/v2.0'
$env:PRODUCTION_IDENTITY_AUDIENCE='api://threatprism-demo'
$env:PRODUCTION_IDENTITY_JWKS_URI='https://idp.example.com/tenant/discovery/v2.0/keys'
$env:PRODUCTION_IDENTITY_SUBJECT_CLAIM='sub'
$env:PRODUCTION_IDENTITY_ROLES_CLAIM='roles'
$env:PRODUCTION_IDENTITY_TENANT_CLAIM='tid'
$env:PRODUCTION_IDENTITY_REQUIRED_ROLES='analyst,engineer,manager_grc,legal_privacy,audit_debug,admin'
$env:PRODUCTION_IDENTITY_ALLOWED_ALGORITHMS='RS256'
$env:PRODUCTION_IDENTITY_LIVE_VERIFICATION_ENABLED='false'
$env:ALLOW_REAL_ACTIONS='false'
$env:DATABASE_URL='sqlite:///:memory:'
python -c "from threatprism.config import Settings; s=Settings.from_env(); s.validate_runtime(); print(s.production_identity_readiness().ready_for_token_verifier)"
```

Expected output:

```text
True
```

## Fail-Closed API Check

Starting the API with fake readiness values and verifier disabled is allowed
for configuration shape review, but protected API routes must still deny
requests:

```powershell
python -m uvicorn threatprism.api.app:create_app --factory --host 127.0.0.1 --port 8766
```

In another terminal:

```powershell
Invoke-RestMethod -Headers @{ Authorization = 'Bearer fake-demo-token' } -Uri http://127.0.0.1:8766/metrics
```

Expected behavior:

```text
HTTP 403 Production token is not authorized for this request.
```

This is correct when local verification is disabled. Use
`docs/runbooks/PRODUCTION_TOKEN_VERIFIER_LOCAL_VALIDATION.md` for the focused
verifier test workflow.

## Standard Validation

Run the full safe validation wrapper before considering this slice complete:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```
