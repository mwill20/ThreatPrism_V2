# 28 Production Identity Readiness

## Slice Name

Production Identity Readiness v0.1

## Goal

Add a safe, testable production identity readiness boundary without adding live
identity-provider behavior. This slice prepares ThreatPrism for a future
production token-verifier implementation while preserving the current fake-data
and fail-closed posture.

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
- Reject live token verification enablement until a future approved slice.
- Prove protected routes fail closed under `external_oidc`.
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
- `PRODUCTION_IDENTITY_LIVE_VERIFICATION_ENABLED=true` is rejected.
- `external_oidc` app startup logs that protected requests fail closed.
- Protected routes return `403 Unsupported API auth mode.` until a future live
  verifier slice is implemented.
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
- No token validation is simulated as real.
- No real provider values are required.
- Live token verification cannot be enabled accidentally.
- Production-like startup cannot fall back to disabled or demo API-key auth.
- Request authorization remains fail-closed until a future trusted principal
  extraction path exists.

## Follow-On Design

Production Token Verifier Design v0.1 is captured in
`docs/specs/29_PRODUCTION_TOKEN_VERIFIER_DESIGN.md` and
`docs/PRODUCTION_TOKEN_VERIFIER_DESIGN.md`. That follow-on slice defines the
future verifier contract but does not change the runtime fail-closed behavior.
