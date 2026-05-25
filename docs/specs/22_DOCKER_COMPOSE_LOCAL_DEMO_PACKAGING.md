# 22 Docker Compose And Local Demo Packaging

## Slice Name

Docker Compose & Local Demo Packaging v0.1

Status: implemented for current fake-data backend scope.

## Goal

Make the current ThreatPrism backend repeatable to start locally from Docker
Compose while preserving the demo-safe runtime contract.

This slice packages the existing FastAPI service. It does not introduce a new
runtime architecture.

## Scope

In scope:

- A `Dockerfile` for the FastAPI backend.
- A `docker-compose.yml` with one `threatprism-api` service.
- A `.dockerignore` that excludes generated artifacts, local databases, git
  metadata, and `.env` files.
- A named Docker volume for demo SQLite persistence.
- Compose defaults for fake demo credentials and deterministic demo provider.
- A health check for `/health`.
- Tests that enforce the packaging boundary.
- Documentation and checklist updates.

Out of scope:

- Dashboard UI.
- PostgreSQL.
- Redis or external queue workers.
- Production IdP integration.
- Live LLM, SOAR, cloud, or enrichment calls.
- Real remediation or containment.
- Non-demo data.

## Runtime Defaults

The image and Compose service must use:

```text
THREATPRISM_ENV=demo
DATABASE_URL=sqlite:////app/data/threatprism.db
API_AUTH_MODE=demo_key
THREATPRISM_AUTH_REQUIRED=true
THREATPRISM_LOCAL_DEV_ACK=false
LLM_PROVIDER=deterministic_demo
ALLOW_REAL_ACTIONS=false
```

Compose must set live-provider credential variables to empty strings so host
environment credentials are not passed through by accident.

## Acceptance Criteria

- `docker compose config` renders successfully.
- `tests/test_docker_packaging.py` proves the Dockerfile, Compose file, and
  Docker ignore file preserve fake-data-only defaults.
- `tools/validate-threatprism.ps1` passes after the packaging files are added.
- Documentation explains how to start and stop the local demo package.
- The handoff and working checklist identify this slice as complete and do not
  select a live-provider or dashboard slice by default.

## Future Work

Future packaging work may add optional profiles for PostgreSQL, Redis, workers,
or production-style deployment only after explicit user approval and updated
threat-model treatment. Those profiles must not replace the fake-data local
demo default.
