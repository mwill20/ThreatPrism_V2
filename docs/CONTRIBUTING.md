# Contributing

ThreatPrism is still a fake-data POC. Contributions must preserve the current
security boundary before adding feature scope.

## Validation

Use the safe local wrapper first:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

This runs the demo-safety checks, exact-pin checks, pytest, and the fake eval
harness. The dependency audit is advisory-only for the POC and is skipped when
`pip-audit` is not installed.

## Dependency Updates

- Direct dependencies in `requirements.txt` must use exact `==` pins.
- `requirements-lock.txt` records the transitive versions used for local
  validation and reproducible installs.
- Do not add live LLM, cloud, SOAR, enrichment, or remediation dependencies
  without an explicit implementation prompt.
- Prefer small, widely used dependencies. If a control can be implemented
  clearly with the standard library for POC scope, do that first.
- After changing dependencies, refresh the lock file from a reviewed local
  environment and run safe validation.

Suggested review flow:

```powershell
python -m pip install -r requirements.txt
python -m pip freeze
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

If `pip-audit` is installed locally, the validation wrapper runs it against
`requirements.txt`. Advisories are not CI-blocking yet; document any finding in
the owning slice before shared or production deployment.

## Data Rules

- Use fake demo data only.
- Do not commit real organizations, workplaces, users, hosts, domains, IPs,
  tenant IDs, credentials, PHI, PII, or secrets.
- Keep `ALLOW_REAL_ACTIONS=false`.
- Treat inbound SOAR payloads, report text, and eval fixtures as untrusted.
