# Production Identity Readiness

Production Identity Readiness v0.1 adds a provider-agnostic readiness boundary
for future production authentication. It does not implement live token
verification, OAuth flows, Entra integration, break-glass access, production
tenant administration, or non-demo data handling.

The goal is to make production identity harder to misconfigure before a real
identity provider slice exists.

## Implemented Scope

- Adds `API_AUTH_MODE=external_oidc` as the only production-compatible auth
  mode name.
- Keeps `API_AUTH_MODE=none` and `API_AUTH_MODE=demo_key` rejected when
  `THREATPRISM_ENV` is `prod` or `production`.
- Adds static production identity readiness settings to `Settings`.
- Validates that production identity readiness uses:
  - an allowed provider value: `oidc` or `entra_oidc`
  - HTTPS issuer URL
  - HTTPS JWKS URL
  - non-empty audience
  - simple subject, role, and tenant claim names
  - all current ThreatPrism role views
  - approved asymmetric token algorithms only
- Rejects `PRODUCTION_IDENTITY_LIVE_VERIFICATION_ENABLED=true` because live
  verifier behavior is not implemented in this slice.
- Leaves protected API routes fail-closed under `external_oidc` until a future
  explicit token-verifier slice adds trusted principal extraction.

## Runtime Behavior

`Settings.validate_runtime()` now recognizes three auth modes:

| Auth Mode | Current Use |
|---|---|
| `none` | Explicit local development only. Requires local-dev acknowledgement unless auth is disabled for tests. |
| `demo_key` | Fake demo credentials only. Requires explicit `DEMO_API_KEYS`. Rejected in production-like environments. |
| `external_oidc` | Static production identity readiness only. Requires readiness config. Protected requests fail closed until live verification is implemented. |

Unknown auth modes are rejected during startup.

When `external_oidc` is configured correctly, application startup is allowed so
operators and tests can prove the configuration shape. Protected routes still
return `403 Unsupported API auth mode.` because no live token verifier exists.
That fail-closed behavior is intentional.

## Environment Variables

```text
API_AUTH_MODE=external_oidc
PRODUCTION_IDENTITY_PROVIDER=entra_oidc
PRODUCTION_IDENTITY_ISSUER=https://idp.example.com/tenant/v2.0
PRODUCTION_IDENTITY_AUDIENCE=api://threatprism-demo
PRODUCTION_IDENTITY_JWKS_URI=https://idp.example.com/tenant/discovery/v2.0/keys
PRODUCTION_IDENTITY_SUBJECT_CLAIM=sub
PRODUCTION_IDENTITY_ROLES_CLAIM=roles
PRODUCTION_IDENTITY_TENANT_CLAIM=tid
PRODUCTION_IDENTITY_REQUIRED_ROLES=analyst,engineer,manager_grc,legal_privacy,audit_debug,admin
PRODUCTION_IDENTITY_ALLOWED_ALGORITHMS=RS256
PRODUCTION_IDENTITY_LIVE_VERIFICATION_ENABLED=false
```

These are shape examples only. Do not use real tenant IDs, real issuer values,
real audiences, real credentials, or real workplace data in this repository.

## Out Of Scope

- No live OAuth/OIDC calls.
- No JWKS download.
- No JWT parsing or signature verification.
- No Entra app registration.
- No production IdP routing or callbacks.
- No break-glass workflow.
- No production RBAC/ABAC claim mapping.
- No non-demo case data.
- No real credentials.
- No real tenant, organization, workplace, user, host, domain, IP, PHI, PII, or
  secret data.

## Validation

Focused test coverage lives in
`tests/test_production_identity_readiness.py` and `tests/test_ops_safety.py`.

Use the standard safe validation wrapper before calling the slice complete:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```
