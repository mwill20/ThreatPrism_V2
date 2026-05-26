# Lesson 24: Production Token Verifier Design

## Goal

Understand how ThreatPrism should move from static production identity
readiness to future live token verification without accidentally treating
unverified claims as authority.

## Why This Lesson Matters

`API_AUTH_MODE=external_oidc` currently validates configuration shape and then
fails closed on protected routes. That is intentional. The next production
identity step needs a verifier design before code exists, because token
verification can create serious security bugs if claims are trusted too early
or logged too freely.

## Primary Files

- `docs/PRODUCTION_IDENTITY_READINESS.md`
- `docs/PRODUCTION_TOKEN_VERIFIER_DESIGN.md`
- `docs/specs/29_PRODUCTION_TOKEN_VERIFIER_DESIGN.md`
- `docs/runbooks/PRODUCTION_TOKEN_VERIFIER_DESIGN_REVIEW.md`
- `src/threatprism/auth/production.py`
- `src/threatprism/auth/demo.py`
- `src/threatprism/config.py`
- `tests/test_production_identity_readiness.py`

## Current Runtime Boundary

The current runtime does not verify tokens.

```text
API_AUTH_MODE=external_oidc
  -> static readiness checks
  -> protected routes fail closed
```

This prevents an operator from mistaking fake demo auth or incomplete OIDC
settings for production authentication.

## Future Verifier Pipeline

The future implementation must follow this order:

```text
Authorization header
  -> extract one bearer token
  -> reject malformed or oversized token
  -> inspect protected header only
  -> enforce algorithm allowlist and kid
  -> verify signature against configured JWKS cache
  -> enforce issuer, audience, exp, nbf, iat
  -> require subject, tenant, and role claims
  -> map external role to ThreatPrism effective role
  -> apply role-view policy
  -> emit sanitized audit event
```

The key rule: no claim is trusted until after signature, issuer, audience, and
time validation pass.

## Audit Rule

Audit events may record reason codes, hashes, mapped roles, and decision
metadata. They must not record raw JWTs, raw Authorization headers, full claim
payloads, real tenant IDs, real group IDs, or JWKS key material.

## Design Boundary

This lesson covers the design only. It does not add:

- JWT parsing.
- JWKS fetch.
- Entra integration.
- OAuth flows.
- production tenant administration.
- non-demo data handling.

## Hands-On Review

Run the static readiness check from the runbook with fake values only:

```powershell
Set-Location C:\Projects\ThreatPrismV2
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

Then read `docs/runbooks/PRODUCTION_TOKEN_VERIFIER_DESIGN_REVIEW.md` and
confirm that `external_oidc` still fails closed for protected routes.

## Interview Talk Track

"ThreatPrism separates production identity readiness from production token
verification. The current system validates that an OIDC-shaped configuration is
well-formed, but it deliberately refuses protected requests because no trusted
verifier exists yet. The future verifier design requires signature validation,
issuer and audience checks, tenant and role claim enforcement, deterministic
role mapping, and sanitized audit events before any role-safe API view can be
served."

## Quick Reference

- Static readiness exists now.
- Live token verification does not.
- Unverified claims are never authority.
- `?role=` is always a view request.
- Standard validation must stay offline.
- Real IdP values must not be committed.
