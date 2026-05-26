# Production Identity Readiness

Production Identity Readiness v0.1 adds a provider-agnostic readiness boundary
for future production authentication. A follow-on local token-verifier slice
now implements fake local JWKS-backed bearer-token verification. This readiness
doc still does not describe live OAuth flows, Entra integration, break-glass
access, production tenant administration, or non-demo data handling.

The goal is to make production identity harder to misconfigure before a real
identity provider slice exists.

The follow-on `docs/PRODUCTION_TOKEN_VERIFIER_IMPLEMENTATION.md` document
describes the local no-network verifier. Protected routes still fail closed
under `external_oidc` unless that verifier is explicitly enabled with complete
local fake-JWKS configuration.

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
- Rejects `PRODUCTION_IDENTITY_LIVE_VERIFICATION_ENABLED=true` unless the
  local verifier has complete fake JWKS, tenant allowlist, role mapping, token
  size, clock skew, and no-network configuration.
- Leaves protected API routes fail-closed under `external_oidc` whenever the
  local verifier is disabled or misconfigured.

## Runtime Behavior

`Settings.validate_runtime()` now recognizes three auth modes:

| Auth Mode | Current Use |
|---|---|
| `none` | Explicit local development only. Requires local-dev acknowledgement unless auth is disabled for tests. |
| `demo_key` | Fake demo credentials only. Requires explicit `DEMO_API_KEYS`. Rejected in production-like environments. |
| `external_oidc` | Production identity readiness plus optional local no-network token verification. Protected requests fail closed unless local verification is explicitly enabled and complete. |

Unknown auth modes are rejected during startup.

When `external_oidc` is configured correctly with verifier disabled,
application startup is allowed so operators and tests can prove the static
configuration shape. Protected routes fail closed. When the local verifier is
enabled with complete fake-JWKS configuration, protected routes authorize only
after signature, issuer, audience, time, tenant, role-mapping, and role-view
policy checks pass.

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
PRODUCTION_IDENTITY_ALLOWED_TENANTS=
PRODUCTION_IDENTITY_ROLE_MAPPING=
PRODUCTION_IDENTITY_JWKS_JSON=
PRODUCTION_IDENTITY_JWKS_FETCH_ENABLED=false
PRODUCTION_IDENTITY_CLOCK_SKEW_SECONDS=60
PRODUCTION_IDENTITY_MAX_TOKEN_BYTES=8192
PRODUCTION_IDENTITY_CLAIM_MAPPING_VERSION=local-demo-v1
```

These are shape examples only. Do not use real tenant IDs, real issuer values,
real audiences, real credentials, or real workplace data in this repository.

## Out Of Scope

- No live OAuth/OIDC calls.
- No JWKS download or live discovery.
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
