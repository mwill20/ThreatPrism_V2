# Lesson 25: Production Token Verifier Implementation

## Goal

Understand the local no-network `external_oidc` verifier and how it turns
verified token claims into a ThreatPrism role without trusting unverified JWT
data.

## What Exists

- `src/threatprism/auth/production.py` parses compact JWTs, validates local
  JWKS-backed RSA signatures, checks issuer/audience/time claims, enforces
  tenant and role claims, and maps external groups to one ThreatPrism role.
- `src/threatprism/auth/demo.py` reuses the same role-view policy for verified
  production principals as it uses for demo principals.
- `src/threatprism/config.py` rejects incomplete verifier configuration and
  keeps JWKS fetch disabled.
- `tests/test_production_token_verifier.py` proves success and fail-closed
  behavior with fake in-memory keys only.

## Safety Boundary

This is not live IdP integration. The implementation uses fake local JWKS JSON
and no network calls. Live JWKS fetch, OIDC discovery, Entra calls, real
credentials, real tenant data, and production dashboard deployment remain
future gated work.

## Review Questions

- Does the verifier reject before trusting claims?
- Is the public key selected only by `kid` from configured local JWKS JSON?
- Are issuer, audience, expiration, issued-at, tenant, and role claims checked?
- Does role mapping produce exactly one ThreatPrism effective role?
- Does `?role=` stay a request for a view rather than authority?
- Do audit events use HMAC-SHA256 aliases and avoid raw tokens, full claims,
  tenant IDs, group IDs, and key material?

## Focused Command

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest tests\test_production_identity_readiness.py tests\test_production_token_verifier.py -p no:cacheprovider --basetemp .pytest_tmp_token_verifier_focus
```
