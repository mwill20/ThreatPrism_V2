# 29 Production Token Verifier Design

## Slice Name

Production Token Verifier Design v0.1

## Goal

Define the future live production token-verifier architecture without
implementing token parsing, signature verification, JWKS fetching, provider
calls, production identity administration, or trusted production
claim-to-role authorization.

## Problem

Production Identity Readiness v0.1 proved that ThreatPrism can reject unsafe
auth modes, validate static OIDC-shaped configuration, and fail closed under
`API_AUTH_MODE=external_oidc`.

The next risk is architectural ambiguity. A future token verifier could
accidentally trust unverified claims, fetch unbounded JWKS data, leak raw JWTs
into audit events, hardwire one provider into core authorization, or let a
requested role view become authority.

This design slice creates the implementation contract before code is added.

## In Scope

- Document the future token acceptance pipeline.
- Define claim-to-role mapping rules.
- Define fail-closed error semantics.
- Define JWKS cache and future fetch boundaries.
- Define sanitized audit telemetry requirements.
- Define no-network validation requirements.
- Define future test coverage.
- Update README, checklist, handoff, limitations, decisions, security notes,
  threat model notes, lessons, and validation notes.

## Out Of Scope

- JWT parsing or signature verification.
- JWKS download or live discovery.
- OAuth redirect flows.
- Entra app registration, Microsoft Graph, or production tenant setup.
- Real issuer URLs, tenant IDs, groups, users, credentials, or organization
  data.
- Production RBAC/ABAC implementation.
- Break-glass access.
- Production dashboard deployment.
- Non-demo case data.

## Design Requirements

Future live verification may accept a protected request only after it:

1. Extracts exactly one bearer token.
2. Rejects missing, malformed, oversized, or non-bearer credentials.
3. Reads only the protected header before signature verification.
4. Enforces an asymmetric algorithm allowlist.
5. Resolves `kid` through a configured local JWKS cache.
6. Verifies the signature.
7. Enforces issuer, audience, expiration, not-before, issued-at, and clock
   skew.
8. Requires subject, tenant, and role claims.
9. Maps external roles or groups to one ThreatPrism effective role.
10. Applies the existing role-view policy.
11. Emits sanitized audit events without raw JWTs, raw Authorization headers,
    raw real tenant IDs, raw group IDs, full claim payloads, or key material.

## Acceptance Criteria

- `docs/PRODUCTION_TOKEN_VERIFIER_DESIGN.md` exists and clearly states that no
  live token verifier is implemented.
- A runbook exists for reviewing the design and future implementation gates
  without live IdP calls.
- The threat model and treatment register identify live token verification as
  the next gated production identity treatment, not as completed runtime auth.
- README, checklist, handoff, limitations, decisions, and lessons point to the
  design.
- Standard safe validation passes with no live provider calls.

## Future Implementation Acceptance Criteria

When the future implementation slice is approved, it must add tests for:

- missing, malformed, oversized, and bad-signature tokens.
- `alg=none`, unsupported algorithms, missing `kid`, and unknown `kid`.
- wrong issuer, wrong audience, expired token, future `nbf`, and unreasonable
  `iat`.
- missing subject, tenant, and role claims.
- unmapped roles, conflicting roles, tenant mismatch, and role-view escalation.
- no raw token, raw Authorization header, full claim payload, JWKS key material,
  or real tenant/group identifiers in logs or audit events.
- no network calls during standard validation.

## Primary Files

- `docs/PRODUCTION_TOKEN_VERIFIER_DESIGN.md`
- `docs/runbooks/PRODUCTION_TOKEN_VERIFIER_DESIGN_REVIEW.md`
- `docs/PRODUCTION_IDENTITY_READINESS.md`
- `docs/specs/28_PRODUCTION_IDENTITY_READINESS.md`
- `src/threatprism/auth/production.py`
- `src/threatprism/auth/demo.py`
- `src/threatprism/config.py`

## Security Properties

- No live identity provider calls are added.
- No JWT verification is simulated as production behavior.
- `external_oidc` protected routes remain fail-closed.
- Provider-specific behavior stays behind a provider profile instead of core
  authorization logic.
- Entra-compatible OIDC remains first-class but not hardwired.
- Standard validation remains fake-data-only and offline.
