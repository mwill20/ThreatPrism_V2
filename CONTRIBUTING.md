# Contributing

ThreatPrism is currently a demo-safe proof-of-concept. Contributions must keep
the fake-data, no-live-provider, and no-real-remediation boundaries intact.

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for the full contribution
rules, validation flow, dependency policy, and data-handling requirements.

Minimum local check before opening a change:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

Do not include real organization data, workplace data, credentials, PHI, PII,
tenant identifiers, private hostnames, real domains, real IPs, or live-provider
output in code, docs, tests, examples, or commit messages.
