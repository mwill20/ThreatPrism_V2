# Dashboard UI Implementation

ThreatPrism now includes a local demo dashboard served by the FastAPI backend.
It is a fake-data-only operator surface for exercising the existing dashboard
contract, not a production frontend.

## Route

```text
GET /dashboard
```

Static assets are served from:

```text
GET /dashboard/assets/styles.css
GET /dashboard/assets/app.js
```

## Personas

The dashboard includes persona tabs for:

- analyst
- manager/GRC
- legal/privacy
- audit/debug
- engineer
- CSI/RGOI

Each persona uses the fake demo credential documented in
`docs/DASHBOARD_DATA_CONTRACT.md` and consumes the same role-safe API routes
that are covered by contract tests.

## Safety Boundary

- Uses same-origin API calls only.
- Uses fake demo credentials only.
- Displays `ALLOW_REAL_ACTIONS=false` from `GET /health`.
- Does not call live providers.
- Does not execute remediation.
- Does not use real organization, workplace, tenant, user, host, domain, IP,
  PHI, PII, credential, or secret data.
- Does not mutate CSI/RGOI knowledge, trust, suppressions, or evidence.

## Local Verification

Start the backend with fake demo settings, then open `/dashboard`:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
$env:THREATPRISM_ENV='demo'
$env:API_AUTH_MODE='demo_key'
$env:DEMO_API_KEYS='demo-analyst-key:demo_analyst:analyst,demo-engineer-key:demo_engineer:engineer,demo-manager-key:demo_manager:manager_grc,demo-legal-key:demo_legal:legal_privacy,demo-audit-key:demo_audit:audit_debug,demo-admin-key:demo_admin:admin'
$env:THREATPRISM_AUTH_REQUIRED='true'
$env:LLM_PROVIDER='deterministic_demo'
$env:ALLOW_REAL_ACTIONS='false'
$env:DATABASE_URL='sqlite:///:memory:'
python -m uvicorn threatprism.api.app:create_app --factory --host 127.0.0.1 --port 8765
```

Then visit:

```text
http://127.0.0.1:8765/dashboard
```

Use `Load demo case` to create a fake case through the existing `/cases`
endpoint.
