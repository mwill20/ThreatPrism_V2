# Dashboard Readiness Runbook

This runbook supports local dashboard review. Use fake demo data and fake demo
credentials only.

## Preconditions

- Work from `C:\Projects\ThreatPrismV2`.
- Keep `ALLOW_REAL_ACTIONS=false`.
- Do not use live LLM, SOAR, cloud, enrichment, RAG, or live production IdP
  providers/token verification.
- Do not use real organization, workplace, tenant, user, host, domain, IP,
  PHI, PII, or secret data.

## Start The Local API

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
$env:THREATPRISM_ENV='demo'
$env:API_AUTH_MODE='demo_key'
$env:DEMO_API_KEYS='demo-analyst-key:demo_analyst:analyst,demo-engineer-key:demo_engineer:engineer,demo-manager-key:demo_manager:manager_grc,demo-legal-key:demo_legal:legal_privacy,demo-audit-key:demo_audit:audit_debug'
$env:LLM_PROVIDER='deterministic_demo'
$env:ALLOW_REAL_ACTIONS='false'
python -m uvicorn threatprism.api.app:create_app --factory --reload
```

> **Analyst co-pilot (Evolution 3):** on the **Analyst** or **Engineer** persona the
> case-detail panel shows an "Analyst co-pilot" card — **Assign to me** / **Release**
> and a **feedback form** — plus a **"My cases only"** toggle. Controls are hidden for
> non-assignable personas (manager/legal/audit), which the API would also deny.
>
> **Use a file-backed DB (the default above), not `DATABASE_URL=sqlite:///:memory:`.**
> The dashboard fires several parallel detail requests per case; `:memory:` shares one
> SQLite connection across threads and returns intermittent 500s (see the hardening
> backlog in `docs/WORKING_CHECKLIST.md`). File-backed mode is unaffected.

## Fake Credential Map

| Persona | Demo Key |
|---|---|
| Analyst | `demo-analyst-key` |
| Manager/GRC | `demo-manager-key` |
| Legal/Privacy | `demo-legal-key` |
| Audit/Debug | `demo-audit-key` |
| Engineer | `demo-engineer-key` |

## Backend Checks For Future UI Work

Health:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Metrics:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/metrics -Headers @{ 'X-ThreatPrism-Demo-Key' = 'demo-manager-key' }
```

Case read model:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/cases/read-model?limit=25" -Headers @{ 'X-ThreatPrism-Demo-Key' = 'demo-analyst-key' }
```

Review queues:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/queues/manager-review -Headers @{ 'X-ThreatPrism-Demo-Key' = 'demo-manager-key' }
Invoke-RestMethod http://127.0.0.1:8000/queues/healthcare-review -Headers @{ 'X-ThreatPrism-Demo-Key' = 'demo-legal-key' }
```

CSI/RGOI retrieval:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/csi/objects?tenant_id=tenant_demo_alpha&query=identity" -Headers @{ 'X-ThreatPrism-Demo-Key' = 'demo-analyst-key' }
Invoke-RestMethod "http://127.0.0.1:8000/csi/lineage/cog_reason_alpha_human_001?tenant_id=tenant_demo_alpha" -Headers @{ 'X-ThreatPrism-Demo-Key' = 'demo-engineer-key' }
Invoke-RestMethod "http://127.0.0.1:8000/csi/observability?tenant_id=tenant_demo_alpha&purpose=audit_reconstruction" -Headers @{ 'X-ThreatPrism-Demo-Key' = 'demo-audit-key' }
```

## Fixture Review

Static fake sample responses live in:

```text
examples/dashboard_contract/
```

These fixtures are for dashboard contract review. They are not generated test
fixtures, live API captures, or production data.

## Hardening Checks

The local dashboard route should return dashboard-specific hardening headers:

- `Content-Security-Policy`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy`
- `Cross-Origin-Resource-Policy`
- `Cache-Control: no-store`

Dashboard JavaScript should use same-origin API paths, fake demo credentials,
and timeout-bounded requests only.

## Validation

Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

Expected current behavior:

- demo safety check passes
- pytest passes
- eval dry-run passes with `15 passed / 0 failed`

## Stop Criteria

Stop and update the threat model before any work requires:

- live providers
- live production IdP/token verification
- real data
- remediation
- CSI/RGOI write-back
- RAG corpus expansion
- production dashboard deployment
- external telemetry or third-party frontend assets
