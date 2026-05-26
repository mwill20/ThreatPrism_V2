# Spec 25: Dashboard UI Implementation

## Status

Implemented as a local, fake-data-only FastAPI-served dashboard UI.

## Goal

Provide a usable dashboard surface for analysts, manager/GRC, legal/privacy,
audit/debug, engineers, and CSI/RGOI review while consuming the existing
role-safe backend API contract.

## In Scope

- Same-origin static dashboard route at `GET /dashboard`.
- Static assets under `src/threatprism/dashboard/static/`.
- Fake demo credential use only.
- Role-specific persona navigation.
- Metrics, case list, case detail, review signals, and CSI/RGOI panels.
- Responsive layout verified through the Browser workflow.
- Tests for route serving, same-origin assets, fake credential boundaries,
  protected API behavior, contract route references, and responsive layout
  markers.

## Out Of Scope

- Live LLM, SOAR, cloud, enrichment, RAG, memory write-back, or remediation.
- Production IdP integration.
- Real organization, workplace, tenant, user, host, domain, IP, PHI, PII, or
  secret data.
- Frontend package managers, external component libraries, external fonts,
  analytics, telemetry beacons, or third-party assets.
- Production dashboard deployment, SSO, RBAC beyond current demo API-key
  enforcement, accessibility certification, load testing, or browser matrix
  testing.

## Implementation Notes

The dashboard is intentionally dependency-light. FastAPI serves static
HTML/CSS/JavaScript from the existing backend process:

```text
GET /dashboard
GET /dashboard/assets/styles.css
GET /dashboard/assets/app.js
```

The UI calls only same-origin API routes already listed in
`docs/DASHBOARD_DATA_CONTRACT.md`. It sends fake demo credentials through
`X-ThreatPrism-Demo-Key` and displays `ALLOW_REAL_ACTIONS=false` from
`GET /health`.

Optional detail panels degrade to empty records when a downstream route is not
ready, so case selection remains usable even when a specific evidence, MITRE,
GRC, audit, or timeline panel is unavailable.

## Acceptance Criteria

- `GET /dashboard` serves the UI shell.
- Dashboard assets are same-origin and contain no live-provider URLs.
- Fake demo credentials are the only credential examples.
- API routes remain protected in `API_AUTH_MODE=demo_key`.
- The UI references the documented dashboard API surfaces.
- Browser verification covers desktop layout, mobile layout, and role-specific
  persona views.
- Standard safe validation passes.
