# Production Token Verifier Design

Production Token Verifier Design v0.1 defines the future live-token
verification architecture for `API_AUTH_MODE=external_oidc`.

This is a design and readiness slice only. It does not parse JWTs at runtime,
download JWKS keys, call an identity provider, integrate with Entra ID, or
authorize production users.

## Purpose

The previous Production Identity Readiness slice added static OIDC-shaped
configuration checks and fail-closed protected routes. This design turns that
readiness boundary into a precise implementation contract for a future token
verifier slice.

The design keeps ThreatPrism provider-agnostic while making Entra-compatible
OIDC a first-class profile.

## Security Boundary

`external_oidc` must remain fail-closed until a trusted verifier is
implemented and tested.

Future live verification may accept a request only after every check below
passes:

1. Extract exactly one `Authorization: Bearer <token>` credential.
2. Reject missing, malformed, oversized, or non-bearer credentials.
3. Decode only the JWT protected header before verification.
4. Reject `alg=none`, unsupported algorithms, missing `kid`, duplicate header
   fields, or unexpected token type markers.
5. Resolve the public key from a configured JWKS cache by `kid`.
6. Verify the signature with the configured asymmetric algorithm allowlist.
7. Enforce configured issuer, audience, expiration, not-before, issued-at, and
   clock-skew bounds.
8. Require configured subject, role, and tenant claims.
9. Map external roles or groups to a single ThreatPrism effective role.
10. Enforce tenant guardrails and role-view policy.
11. Emit sanitized audit telemetry.
12. Continue into existing role-safe read paths only after authorization
    succeeds.

The verifier must never treat unverified claims as authoritative.

## Non-Goals

- No OAuth redirect flow.
- No refresh-token, session-cookie, or browser SSO flow.
- No Entra app registration or Microsoft Graph calls.
- No live JWKS download during standard validation.
- No production tenant administration.
- No break-glass workflow.
- No SCIM or user provisioning.
- No real issuer URLs, tenant IDs, audiences, groups, users, or credentials in
  this repository.
- No production dashboard deployment.
- No non-demo case data.

## Future Configuration Model

The existing readiness settings remain the base:

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

Future verifier-specific settings should be added only when the implementation
slice lands:

```text
PRODUCTION_IDENTITY_ALLOWED_TENANTS=tenant_demo_alpha
PRODUCTION_IDENTITY_ROLE_MAPPING=analysts:analyst,engineers:engineer,grc_reviewers:manager_grc
PRODUCTION_IDENTITY_CLOCK_SKEW_SECONDS=60
PRODUCTION_IDENTITY_MAX_TOKEN_BYTES=8192
PRODUCTION_IDENTITY_JWKS_CACHE_TTL_SECONDS=300
PRODUCTION_IDENTITY_JWKS_FETCH_ENABLED=false
```

The repository must use fake examples only. Real tenant IDs, group IDs,
domains, audiences, users, and credentials must stay out of code, docs, tests,
examples, and commit messages.

## JWKS And Key Handling

The first implementation should verify tokens against local fake JWKS fixtures
only. Live JWKS fetch should remain disabled in safe validation and CI.

If live JWKS fetch is later approved, it must be explicitly opt-in and must
enforce:

- HTTPS-only JWKS URI.
- Issuer and audience pinned from settings, never discovered dynamically into
  trust.
- Small response body limit.
- Short request timeout.
- No credential forwarding.
- No redirects to non-HTTPS.
- No private IP, loopback, localhost, or link-local JWKS targets except a
  dedicated local test mode.
- Cache expiry and `kid` miss behavior that fails closed.
- Safe logging that never stores raw tokens, raw Authorization headers, or full
  claim sets.

## Claim Mapping

The verifier should create a production principal object similar in purpose to
the current demo principal, but it must be sourced from verified claims only.

Required normalized fields:

| Field | Source |
|---|---|
| `subject_hash` | HMAC or salted hash of the verified subject claim |
| `issuer` | verified `iss` |
| `audience` | configured audience match result |
| `tenant_id` | configured tenant claim |
| `effective_role` | mapped ThreatPrism role |
| `auth_mode` | `external_oidc` |
| `claim_mapping_version` | deterministic mapping version string |

External claims must map to one effective role from:

```text
analyst, engineer, manager_grc, legal_privacy, audit_debug, admin
```

Unmapped roles, conflicting roles, missing roles, or role escalation attempts
must fail closed. If deterministic priority is ever allowed, the priority order
must be explicit in configuration, documented, and tested.

The `ai` view remains an internal view role, not an external user role.

## Authorization Integration

Future production authorization must reuse the same role-view policy semantics
as demo authorization:

- The request may ask for a role view.
- The verified principal supplies the effective role.
- The effective role decides which views are allowed.
- The request parameter never becomes authority.

Failure semantics should be stable:

| Condition | Response |
|---|---|
| missing bearer token | `401` |
| malformed or oversized token | `401` |
| bad signature | `401` |
| unsupported algorithm or `kid` miss | `401` |
| issuer, audience, expiration, not-before, or issued-at failure | `401` |
| missing subject, tenant, or role claim | `403` |
| unmapped role or conflicting role | `403` |
| tenant mismatch | `403` |
| role-view escalation | `403` |
| verifier not configured | startup failure or protected-route fail-closed |

## Audit Telemetry

Production token verification must audit allow and deny decisions without
leaking sensitive token material.

Allowed audit metadata:

- verifier decision.
- reason code.
- auth mode.
- provider profile.
- issuer match boolean or configured issuer alias.
- audience match boolean.
- subject hash.
- tenant claim hash or configured tenant alias.
- mapped effective role.
- requested role view.
- `kid` hash.
- algorithm.
- claim mapping version.
- request metadata hash.

Forbidden audit metadata:

- raw JWT.
- raw Authorization header.
- raw subject.
- raw tenant ID when it is real.
- raw group IDs or role IDs when they are real.
- full claim payload.
- JWKS key material.
- credentials or secrets.

## No-Network Validation Rule

The future implementation must keep the standard validation wrapper offline.
Unit and contract tests should use local fake keys and fake JWKS documents.
Any live IdP smoke test must be a separate manual runbook step outside
`tools/validate-threatprism.ps1` and must require explicit user approval.

## Future Test Plan

The token verifier implementation slice should add focused tests for:

- missing token.
- malformed bearer header.
- oversized token.
- `alg=none`.
- symmetric algorithm when only asymmetric algorithms are allowed.
- missing `kid`.
- unknown `kid`.
- bad signature.
- expired token.
- future `nbf`.
- unreasonable `iat`.
- wrong issuer.
- wrong audience.
- missing subject claim.
- missing tenant claim.
- missing role claim.
- unmapped role.
- conflicting roles.
- tenant mismatch.
- role-view escalation.
- no raw token or claim leakage in audit events and logs.
- JWKS fetch disabled during safe validation.
- local fake JWKS cache hit and cache miss behavior.

## Future Implementation Order

1. Add verifier config models and fake key fixtures.
2. Add local JWKS verifier service with no network path.
3. Add verified production principal and claim-to-role mapper.
4. Integrate production authorization with existing role-view policy.
5. Add sanitized audit events.
6. Add focused tests and contract checks.
7. Only after that, consider opt-in live JWKS fetch with separate threat-model
   treatment and runbook updates.

## Current Status

This design is ready for implementation planning, but no live verifier is
implemented. `API_AUTH_MODE=external_oidc` must continue to deny protected
routes until a future approved implementation slice lands.
