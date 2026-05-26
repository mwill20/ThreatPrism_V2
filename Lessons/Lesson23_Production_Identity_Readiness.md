# Lesson 23: Production Identity Readiness

## Goal

Understand how ThreatPrism now represents production identity readiness without
pretending to implement live identity-provider authentication.

## Key Idea

Production identity readiness is a startup and configuration contract, not an
authorization implementation. `API_AUTH_MODE=external_oidc` proves that the
operator has supplied a provider, issuer, audience, JWKS URL, claim names,
role coverage, and safe algorithms. It does not verify tokens.

Protected API routes still fail closed under `external_oidc`.

## Files To Read

- `src/threatprism/auth/production.py`
- `src/threatprism/config.py`
- `src/threatprism/api/app.py`
- `tests/test_production_identity_readiness.py`
- `docs/PRODUCTION_IDENTITY_READINESS.md`
- `docs/runbooks/PRODUCTION_IDENTITY_READINESS.md`

## Walkthrough

1. `PRODUCTION_IDENTITY_AUTH_MODE` defines the only production-compatible auth
   mode name: `external_oidc`.
2. `evaluate_production_identity_readiness()` checks static configuration only.
   It accepts safe fake OIDC-shaped values and rejects missing provider
   details, non-HTTPS issuer/JWKS URLs, missing role views, unsafe algorithms,
   and live verifier enablement.
3. `Settings.validate_runtime()` rejects unknown auth modes, rejects `none` and
   `demo_key` in production-like environments, and requires readiness checks
   when `external_oidc` is configured.
4. `create_app()` logs that production identity readiness is configured but
   protected requests fail closed.
5. `authorize_role_view()` still rejects unsupported runtime auth modes for
   protected requests because trusted token-to-principal mapping is not built
   yet.

## Hands-On Check

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest tests\test_production_identity_readiness.py -p no:cacheprovider --basetemp .pytest_tmp_lesson23
```

Expected focused result:

```text
7 passed
```

## Interview Talk Track

ThreatPrism does not treat demo API keys as production auth. The production
identity readiness slice adds a named `external_oidc` mode and verifies that
the static OIDC-style configuration is complete, HTTPS-based, role-aware, and
limited to safe asymmetric algorithms. It also rejects any attempt to enable
live verification in this slice. That prevents accidental overclaiming: the
system can prove readiness shape, while protected routes still deny requests
until a real token verifier is explicitly implemented and tested.
