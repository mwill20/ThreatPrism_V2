# Production Identity Readiness Runbook

Use this runbook to review the static production identity readiness boundary.
It is not a production deployment procedure.

For the future verifier contract, read
`docs/PRODUCTION_TOKEN_VERIFIER_DESIGN.md` and
`docs/runbooks/PRODUCTION_TOKEN_VERIFIER_DESIGN_REVIEW.md`. Those files are
design-only; the current runtime still fails closed under `external_oidc`.

## Safety Rules

- Use fake example values only.
- Keep `ALLOW_REAL_ACTIONS=false`.
- Do not use real issuer URLs, tenant IDs, audiences, users, groups, roles,
  secrets, or credentials.
- Do not expect protected API routes to authorize requests under
  `external_oidc`; live token verification is not implemented.

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

Starting the API with the fake readiness values is allowed for configuration
shape review, but protected API routes must still deny requests:

```powershell
python -m uvicorn threatprism.api.app:create_app --factory --host 127.0.0.1 --port 8766
```

In another terminal:

```powershell
Invoke-RestMethod -Headers @{ Authorization = 'Bearer fake-demo-token' } -Uri http://127.0.0.1:8766/metrics
```

Expected behavior:

```text
HTTP 403 Unsupported API auth mode.
```

This is correct until a future approved production token-verifier slice exists.

## Standard Validation

Run the full safe validation wrapper before considering this slice complete:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```
