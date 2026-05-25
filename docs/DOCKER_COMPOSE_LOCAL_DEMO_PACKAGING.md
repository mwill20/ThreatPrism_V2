# Docker Compose And Local Demo Packaging

Docker Compose & Local Demo Packaging v0.1 is implemented.

This slice packages the existing fake-data backend for repeatable local startup
without changing the runtime security boundary. It does not add dashboard UI,
live LLM calls, live SOAR calls, production IdP integration, PostgreSQL, Redis,
or real remediation.

## Implemented Files

```text
Dockerfile
docker-compose.yml
.dockerignore
tests/test_docker_packaging.py
```

## Package Boundary

The local image runs only the existing FastAPI backend:

```text
python -m uvicorn threatprism.api.app:create_app --factory --host 0.0.0.0 --port 8000
```

The container defaults preserve the current demo posture:

- `THREATPRISM_ENV=demo`.
- `API_AUTH_MODE=demo_key`.
- Fake demo API keys only.
- `LLM_PROVIDER=deterministic_demo`.
- `ALLOW_REAL_ACTIONS=false`.
- Empty live-provider credential variables.
- SQLite demo persistence under `/app/data/threatprism.db`.

## Run With Docker Compose

```powershell
Set-Location C:\Projects\ThreatPrismV2
docker compose up --build
```

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Stop the demo:

```powershell
docker compose down
```

Remove the demo SQLite volume when you want a fresh local container state:

```powershell
docker compose down -v
```

## Safety Boundary

- Do not pass real provider credentials into Compose.
- Do not mount `.env` into the image.
- Do not run with `ALLOW_REAL_ACTIONS=true`.
- Do not use real organization, workplace, tenant, user, host, domain, IP,
  secret, PHI, or ePHI data.
- Keep PostgreSQL, Redis, workers, production IdP, and live integrations out of
  scope until explicitly requested.
