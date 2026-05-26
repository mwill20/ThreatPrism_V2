# Deployment

ThreatPrism is currently deployable only as a local demo backend. It is not
production-ready.

## Current Deployment Status

| Target | Status | Notes |
|---|---|---|
| Local Python/FastAPI | Supported | Run with Uvicorn from the repository root. |
| Docker Compose local demo | Supported | Single backend service with fake demo credentials. |
| Production container deployment | Not implemented | Requires production auth, secrets, TLS, monitoring, and hardening. |
| Cloud deployment | Not implemented | No Azure, AWS, GCP, or managed deployment profile exists. |
| Dashboard UI | Not implemented | Frontend work requires explicit approval. |

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

## Production Gaps

Before any production-style deployment, ThreatPrism needs:

- production identity provider integration
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
