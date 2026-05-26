# Deployment

ThreatPrism is currently deployable only as a local demo backend. It is not
production-ready.

## Current Deployment Status

| Target | Status | Notes |
|---|---|---|
| Local Python/FastAPI | Supported | Run with Uvicorn from the repository root. |
| Docker Compose local demo | Supported | Single backend service with fake demo credentials. |
| Local dashboard | Supported | Served at `GET /dashboard` with fake demo credentials and dashboard hardening headers. |
| Production identity readiness | Static-only scaffold | `API_AUTH_MODE=external_oidc` validates OIDC-shaped config but does not verify tokens. |
| Production token verifier | Design only | Future verifier contract exists, but no JWT verification, JWKS fetch, or production claim mapping is implemented. |
| Production container deployment | Not implemented | Requires production auth, secrets, TLS, monitoring, and hardening. |
| Cloud deployment | Not implemented | No Azure, AWS, GCP, or managed deployment profile exists. |
| Production dashboard deployment | Not implemented | Requires production identity, browser matrix testing, accessibility review, and deployment posture. |

## Local Docker Compose

```powershell
Set-Location C:\Projects\ThreatPrismV2
docker compose up --build
```

The service intentionally uses:

- `API_AUTH_MODE=demo_key`
- fake demo keys
- `LLM_PROVIDER=deterministic_demo`
- `ALLOW_REAL_ACTIONS=false`
- empty live-provider credential variables
- SQLite demo persistence in a named Docker volume

The dashboard is available from the same backend process at `/dashboard`. The
local dashboard route and assets include CSP, frame blocking, no-sniff,
referrer, permission, same-origin resource, and no-store cache headers. These
headers are local production-style hardening only; they are not a substitute
for TLS, production identity, or reverse-proxy deployment controls.

## Production Gaps

Before any production-style deployment, ThreatPrism needs:

- live production token verification and production identity provider
  integration
- implementation of the token verifier design with fake-key tests,
  no-network validation, claim-to-role mapping, and sanitized audit telemetry
- TLS termination and network access controls
- secrets management
- database hardening and backup strategy
- durable queue or worker model
- distributed rate limiting and backpressure
- deployment monitoring and alerting
- security scanning gates
- incident response process for ThreatPrism itself
- external security review

Do not deploy ThreatPrism with non-demo data until these gaps are addressed.
