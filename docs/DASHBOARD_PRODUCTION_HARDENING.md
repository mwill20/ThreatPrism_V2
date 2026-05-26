# Dashboard Production Hardening

ThreatPrism includes production-style hardening for the local dashboard surface.
This does not make the dashboard production-ready. It keeps the existing
fake-data-only FastAPI-served UI safer to inspect and demo.

## Hardened Route Surface

The following routes receive dashboard-specific hardening headers:

```text
GET /dashboard
GET /dashboard/assets/app.js
GET /dashboard/assets/styles.css
```

The header set includes:

| Header | Purpose |
|---|---|
| `Content-Security-Policy` | Allows only same-origin scripts, styles, images, and API requests. |
| `X-Frame-Options: DENY` | Blocks clickjacking through framing. |
| `Referrer-Policy: no-referrer` | Prevents referrer leakage. |
| `X-Content-Type-Options: nosniff` | Prevents MIME sniffing. |
| `Permissions-Policy` | Disables unnecessary browser capabilities. |
| `Cross-Origin-Opener-Policy` | Keeps the dashboard in a same-origin browsing context. |
| `Cross-Origin-Resource-Policy` | Limits dashboard resources to same-origin use. |
| `Cache-Control: no-store` | Avoids retaining demo case data in browser caches. |

## Browser-Side Controls

The dashboard JavaScript:

- builds request URLs from same-origin paths only
- rejects non-same-origin request targets
- bounds API calls with an 8-second timeout
- uses fake demo credentials only
- keeps CSI/RGOI retrieval read-only
- escapes rendered API content before inserting it into the page

## Accessibility Hardening

Persona navigation now exposes tab semantics, selected-state attributes,
keyboard movement markers, visible focus states, and live status regions.

This is not an accessibility certification. It is a local hardening baseline
that keeps the dashboard usable while broader browser and accessibility testing
remain future work.

## Still Required Before Production

- live production token verification and identity provider integration
- TLS and reverse proxy configuration
- secrets management
- production persistence and audit integrity
- durable queue/backpressure
- centralized monitoring
- browser matrix testing
- accessibility audit
- external security review

Do not use real data or live providers with the dashboard in this repository
state.
