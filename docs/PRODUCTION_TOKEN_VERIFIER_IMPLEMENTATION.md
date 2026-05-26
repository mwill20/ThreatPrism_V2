# Production Token Verifier Implementation

Production Token Verifier Implementation v0.1 adds the first trusted
`external_oidc` runtime verifier for ThreatPrism.

This implementation is intentionally local and no-network. It verifies bearer
tokens against a configured fake local JWKS document only. It does not fetch
JWKS keys, call OIDC discovery, call Entra ID, use Microsoft Graph, administer
tenants, process real credentials, or authorize real users.

## Implemented Scope

- `API_AUTH_MODE=external_oidc` can authorize protected routes only when
  `PRODUCTION_IDENTITY_LIVE_VERIFICATION_ENABLED=true` and the local verifier
  configuration is complete.
- The verifier accepts compact JWT bearer tokens only.
- It reads the protected header before signature validation and rejects
  malformed tokens, oversized tokens, `alg=none`, unsupported algorithms,
  missing `kid`, unknown `kid`, duplicate `kid`, and unexpected token types.
- It verifies RSA signatures for `RS256`, `RS384`, and `RS512` using the
  configured local JWKS JSON.
- It enforces issuer, audience, expiration, issued-at, optional not-before,
  subject claim, tenant claim, and role claim checks.
- It maps verified external role/group claim values to exactly one ThreatPrism
  effective role.
- It reuses the existing role-view policy so `?role=` remains a view request,
  not authority.
- It emits sanitized authorization audit metadata with deterministic
  HMAC-SHA256 claim aliases and reason codes, not raw JWTs, raw Authorization
  headers, full claim payloads, raw subject values, raw tenant IDs, raw group
  IDs, or JWKS key material.

## New Configuration

The verifier extends the static readiness settings with local verifier fields:

```text
PRODUCTION_IDENTITY_LIVE_VERIFICATION_ENABLED=true
PRODUCTION_IDENTITY_ALLOWED_TENANTS=tenant_demo_alpha
PRODUCTION_IDENTITY_ROLE_MAPPING=demo_analysts:analyst,demo_managers:manager_grc
PRODUCTION_IDENTITY_JWKS_JSON={"keys":[...fake local public keys...]}
PRODUCTION_IDENTITY_JWKS_FETCH_ENABLED=false
PRODUCTION_IDENTITY_CLOCK_SKEW_SECONDS=60
PRODUCTION_IDENTITY_MAX_TOKEN_BYTES=8192
PRODUCTION_IDENTITY_CLAIM_MAPPING_VERSION=local-demo-v1
```

Keep these values fake in this repository. Do not commit real issuer URLs,
tenant IDs, group IDs, users, credentials, private keys, workplace data, or
production telemetry.

## Runtime Boundary

This slice changes the `external_oidc` boundary from “always fail closed” to:

| State | Behavior |
|---|---|
| Verifier disabled | Protected routes fail closed under `external_oidc`. |
| Verifier enabled without complete local config | Startup fails closed. |
| Verifier enabled with local fake JWKS config | Protected routes authorize only after signature, claim, tenant, role mapping, and role-view checks pass. |

`PRODUCTION_IDENTITY_JWKS_FETCH_ENABLED=true` remains rejected. Live JWKS fetch
and real IdP integration require a separate approved slice.

## Tests

Focused coverage lives in:

- `tests/test_production_identity_readiness.py`
- `tests/test_production_token_verifier.py`
- `tests/test_ops_safety.py`

The tests cover missing/malformed/oversized tokens, unsafe algorithms, missing
or unknown `kid`, bad signatures, issuer/audience/time failures, missing
subject/tenant/role claims, tenant mismatch, unmapped roles, conflicting roles,
role-view escalation, sanitized audit events, and no-network behavior.

## Still Out Of Scope

- Live JWKS fetch.
- OIDC discovery.
- OAuth redirect or browser SSO flow.
- Entra ID or Microsoft Graph calls.
- Production tenant administration.
- Real credentials or real tenant data.
- Break-glass governance.
- Production dashboard deployment.
- Non-demo case data.
