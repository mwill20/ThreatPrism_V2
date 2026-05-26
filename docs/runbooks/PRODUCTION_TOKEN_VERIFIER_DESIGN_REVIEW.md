# Production Token Verifier Design Review Runbook

Use this runbook to review the approved production token verifier design. The
local no-network implementation now exists; use
`docs/runbooks/PRODUCTION_TOKEN_VERIFIER_LOCAL_VALIDATION.md` for focused
runtime validation.

This is not a live IdP setup guide.

## Safety Rules

- Use fake example values only.
- Keep `ALLOW_REAL_ACTIONS=false`.
- Do not use real issuer URLs, tenant IDs, audiences, groups, users, secrets,
  credentials, workplace data, or production telemetry.
- Do not call live OIDC discovery, JWKS, Entra, Graph, or cloud endpoints.
- Do not expect `API_AUTH_MODE=external_oidc` to authorize protected requests
  unless local verification is explicitly enabled with fake local JWKS config.

## Review Inputs

Read these files:

```text
docs/PRODUCTION_IDENTITY_READINESS.md
docs/PRODUCTION_TOKEN_VERIFIER_DESIGN.md
docs/specs/28_PRODUCTION_IDENTITY_READINESS.md
docs/specs/29_PRODUCTION_TOKEN_VERIFIER_DESIGN.md
docs/threat-models/stride-threat-model.md
docs/threat-models/mitigations-traceability.md
docs/specs/21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md
SECURITY.md
LIMITATIONS.md
```

## Design Checklist

Confirm the design keeps these properties:

- Protected requests remain fail-closed until code exists and tests pass.
- The verifier never trusts unverified claims.
- Allowed algorithms are asymmetric only.
- `alg=none` and missing `kid` fail closed.
- Issuer and audience are pinned from configuration.
- Tenant and role claims are required.
- External roles map to one ThreatPrism effective role.
- `?role=` remains a view request, not authority.
- Audit events use hashes and reason codes, not raw tokens or full claims.
- Standard validation remains no-network.
- Live JWKS fetch, if added later, is opt-in and separately gated.

## Static Readiness Check

The current runtime can still validate static readiness with fake values:

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

## Fail-Closed Confirmation

With local verification disabled, protected routes still deny requests under
`external_oidc`:

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

This is correct when the verifier is disabled. To validate the implemented
local verifier, use the local validation runbook.

## Future Implementation Gate

Before implementation begins, create or update a spec that names:

- local fake key and fake JWKS fixtures.
- verifier config settings.
- claim mapping config format.
- production principal shape.
- audit reason-code vocabulary.
- focused tests for every failure mode in
  `docs/PRODUCTION_TOKEN_VERIFIER_DESIGN.md`.

## Standard Validation

Run safe validation after any design or future implementation change:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```
