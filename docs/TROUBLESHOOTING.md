# Troubleshooting

## Imports Fail With `No module named 'threatprism'`

ThreatPrism uses a `src/` layout. Run commands from the repository root and set
`PYTHONPATH` when invoking modules directly:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
```

Pytest reads `pythonpath = ["src"]` from `pyproject.toml` when run from the
repository root.

## Pytest Fails While Cleaning A Temp Directory

Windows can lock pytest temp directories. Use a fresh ignored base temp:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_fresh
```

## Validation Fails Because Live Provider Variables Are Set

The validation wrapper clears known live-provider credential variables for its
own process. If the demo safety checker still fails, inspect your shell
environment and `.env` files. Do not run validation with real credentials or
real action settings.

## API Refuses To Start In Production Mode

This is intentional. `THREATPRISM_ENV=prod` or `production` cannot use
`API_AUTH_MODE=none` or `API_AUTH_MODE=demo_key`. Use
`API_AUTH_MODE=external_oidc` only for static production identity readiness.
Live production token verification is not implemented yet.

## Demo Auth Fails Closed

`API_AUTH_MODE=demo_key` requires `DEMO_API_KEYS`. `API_AUTH_MODE=none` requires
`THREATPRISM_LOCAL_DEV_ACK=true` for local fake-data development.

## Fixture Factory Rejects Paths

Inputs must resolve under `external_datasets/` and outputs must resolve under
`fixtures/generated/`. Existing outputs require `--force`. The factory rejects
path traversal, absolute escapes, unsafe extensions, and implicit overwrites.

## Stop And Document A Blocker

Stop if the next step requires:

- real remediation
- live provider credentials
- real case data
- real PHI or PII
- real organization or workplace data
- live production authentication claims
- HIPAA or HITRUST compliance claims
