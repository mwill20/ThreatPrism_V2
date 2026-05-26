# Spec 26: Production Dashboard Hardening

## Status

Implemented as production-style hardening for the local, fake-data-only
dashboard. This is not a production deployment slice.

## Goal

Reduce the browser and static-asset risk of the existing ThreatPrism dashboard
while preserving the current demo-safe boundary.

## In Scope

- Dashboard-specific security headers for `GET /dashboard` and
  `/dashboard/assets/*`.
- Content Security Policy that allows same-origin script, style, image, and API
  access only.
- Clickjacking, referrer, MIME-sniffing, browser permission, and cross-origin
  isolation headers.
- Same-origin request enforcement in dashboard JavaScript.
- Request timeout handling for dashboard API calls.
- Keyboard-accessible persona tab navigation.
- Accessibility-focused status and focus-state improvements.
- Focused tests for headers, same-origin behavior, timeouts, keyboard markers,
  and fake credential boundaries.
- Threat-model, traceability, limitations, checklist, handoff, README, runbook,
  evaluation, and lesson updates.

## Out Of Scope

- Production IdP, SSO, OAuth, OIDC, Entra ID, or enterprise RBAC.
- Live LLM, SOAR, cloud, enrichment, RAG, or external telemetry providers.
- Real organization, workplace, tenant, user, host, domain, IP, PHI, PII, or
  secret data.
- Real remediation or containment.
- Frontend package managers, component libraries, external fonts, analytics,
  telemetry beacons, or third-party assets.
- CDN deployment, reverse proxy configuration, TLS termination, browser matrix
  certification, or accessibility certification.

## Acceptance Criteria

- Dashboard responses include hardening headers.
- Dashboard code rejects non-same-origin request targets.
- Dashboard API calls are timeout-bounded.
- Persona controls expose tab semantics and keyboard navigation markers.
- API routes remain protected in `API_AUTH_MODE=demo_key`.
- No live-provider URLs, external assets, real credentials, raw payloads, token
  vault mappings, or real-action claims are introduced.
- Browser verification covers desktop, mobile, keyboard persona navigation, and
  role-specific views.
- Standard safe validation passes.
