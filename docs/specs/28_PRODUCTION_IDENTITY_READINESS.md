# 28 Production Identity Readiness

## Slice Name

Production Identity Readiness v0.1

## Goal

Add a safe, testable production identity readiness boundary without adding live
identity-provider behavior. This slice prepared ThreatPrism for the local
production token-verifier implementation while preserving the fake-data and
fail-closed posture.

## Problem

Before this slice, ThreatPrism rejected `none` and `demo_key` in production-like
environments, but it did not define the production-compatible auth mode or the
static configuration shape that a future identity verifier will need.

That left two risks:

- Operators could not distinguish "production auth intentionally not ready"
  from an arbitrary unsupported `API_AUTH_MODE`.
- Future production identity work had no tested static contract for issuer,
  audience, JWKS, role claims, tenant claims, and approved algorithms.

## In Scope

- Add `external_oidc` as the explicit production identity readiness auth mode.
- Add static readiness fields to runtime settings.
- Reject unknown auth modes.
- Keep production environments blocked from `none` and `demo_key`.
- Validate fake/demo-safe OIDC-style configuration shape.
- Reject token verification enablement unless local fake-JWKS verifier
  configuration is complete.
- Prove protected routes fail closed under `external_oidc` when verification is
  disabled or misconfigured.
- Update docs, runbooks, threat model notes, checklist, lessons, and
  limitations.

## Out Of Scope

- Live OIDC/JWKS calls.
- JWT verification.
- Entra app registration or Graph calls.
- Real tenant IDs, issuer URLs, audiences, credentials, or organization data.
- Production RBAC/ABAC claim authorization.
- Break-glass governance.
- Production deployment.
- Real case data.

## Acceptance Criteria

- `Settings.validate_runtime()` recognizes only `none`, `demo_key`, and
  `external_oidc`.
- `prod` and `production` still reject `none` and `demo_key`.
- `external_oidc` requires static provider, issuer, audience, JWKS URI, claims,
  role coverage, and safe asymmetric algorithms.
- `PRODUCTION_IDENTITY_LIVE_VERIFICATION_ENABLED=true` is rejected unless the
  local verifier has fake JWKS JSON, tenant allowlist, role mapping, safe token
  size, safe clock skew, and JWKS fetch disabled.
- `external_oidc` app startup logs whether local verification is enabled or
  protected requests fail closed.
- Protected routes fail closed until local fake-JWKS verification is enabled.
- `.env.example` documents empty, fake-safe production identity placeholders.
- The safe validation wrapper passes.

## Primary Files

- `src/threatprism/auth/production.py`
- `src/threatprism/config.py`
- `src/threatprism/api/app.py`
- `tests/test_production_identity_readiness.py`
- `tests/test_ops_safety.py`
- `docs/PRODUCTION_IDENTITY_READINESS.md`
- `docs/runbooks/PRODUCTION_IDENTITY_READINESS.md`

## Security Properties

- No network calls are added.
- Local token validation is fake-JWKS and no-network only.
- No real provider values are required.
- Local token verification cannot be enabled accidentally or with live JWKS
  fetch.
- Production-like startup cannot fall back to disabled or demo API-key auth.
- Request authorization remains fail-closed until a trusted local verifier
  produces a verified principal.

## Follow-On Design

Production Token Verifier Design v0.1 and Implementation v0.1 are captured in
`docs/specs/29_PRODUCTION_TOKEN_VERIFIER_DESIGN.md`,
`docs/specs/30_PRODUCTION_TOKEN_VERIFIER_IMPLEMENTATION.md`,
`docs/PRODUCTION_TOKEN_VERIFIER_DESIGN.md`, and
`docs/PRODUCTION_TOKEN_VERIFIER_IMPLEMENTATION.md`.
