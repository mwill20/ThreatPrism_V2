# 30 Production Token Verifier Implementation

## Slice Name

Production Token Verifier Implementation v0.1

## Goal

Implement the approved `external_oidc` verifier contract using local fake keys
and no-network validation, while preserving ThreatPrism's fake-data and
analyst-controlled boundaries.

## In Scope

- Local JWKS JSON parsing from configuration.
- Compact JWT bearer-token parsing.
- RSA signature verification for `RS256`, `RS384`, and `RS512`.
- Issuer, audience, expiration, issued-at, optional not-before, subject,
  tenant, and role claim validation.
- External role/group to ThreatPrism role mapping.
- Production principal creation from verified claims only.
- Integration with existing role-view authorization policy.
- Sanitized audit metadata with deterministic HMAC-SHA256 aliases for allow
  and deny decisions.
- Focused tests for verifier success, fail-closed behavior, audit safety, and
  no-network behavior.

## Out Of Scope

- Live JWKS fetch.
- OIDC discovery.
- OAuth redirect flows.
- Entra app registration, Graph calls, or production tenant administration.
- Real issuer URLs, tenant IDs, group IDs, users, credentials, private keys,
  workplace data, production telemetry, or non-demo case data.
- Production dashboard deployment.
- Real remediation.

## Acceptance Criteria

- `API_AUTH_MODE=external_oidc` remains fail-closed unless local verifier
  configuration is complete and verification is explicitly enabled.
- Startup rejects live verifier enablement without local JWKS JSON, tenant
  allowlist, role mapping, safe token size, safe clock skew, and JWKS fetch
  disabled.
- Verified tokens can authorize protected API routes through the existing
  role-view policy.
- Invalid tokens fail closed with stable `401` or `403` behavior.
- Audit events never include raw JWTs, raw Authorization headers, full claim
  payloads, raw subject, raw tenant, raw external group, credentials, or JWKS
  key material.
- Standard validation remains offline and fake-data-only.

## Primary Files

- `src/threatprism/auth/production.py`
- `src/threatprism/auth/demo.py`
- `src/threatprism/config.py`
- `src/threatprism/api/app.py`
- `tests/test_production_token_verifier.py`
- `tests/test_production_identity_readiness.py`
- `tools/check_demo_safety.py`
- `docs/PRODUCTION_TOKEN_VERIFIER_IMPLEMENTATION.md`

## Validation

Use:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```
