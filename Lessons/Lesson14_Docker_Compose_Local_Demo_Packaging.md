# Lesson 14: Docker Compose Local Demo Packaging

## Goal

Understand how ThreatPrism is packaged for repeatable local backend startup
without crossing into live-provider, production IdP, dashboard, or remediation
scope.

## Primary Files

```text
Dockerfile
docker-compose.yml
.dockerignore
tests/test_docker_packaging.py
docs/DOCKER_COMPOSE_LOCAL_DEMO_PACKAGING.md
docs/specs/22_DOCKER_COMPOSE_LOCAL_DEMO_PACKAGING.md
```

## What The Slice Adds

Docker Compose & Local Demo Packaging v0.1 adds:

- A container image for the existing FastAPI backend.
- A one-service Compose file for local demo startup.
- Demo-safe environment defaults.
- SQLite demo persistence through a named Docker volume.
- A health check for `/health`.
- Tests that guard against accidental live-provider or generated-artifact
  packaging drift.

It does not add dashboard UI, PostgreSQL, Redis, production identity, live
providers, or real remediation.

## Run The Local Package

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
docker compose up --build
```

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Stop:

```powershell
docker compose down
```

Reset demo container state:

```powershell
docker compose down -v
```

## Review Questions

- Does Compose use `API_AUTH_MODE=demo_key` with fake keys?
- Are live-provider credential variables empty?
- Does `ALLOW_REAL_ACTIONS` stay `false`?
- Does `.dockerignore` exclude `.env`, generated eval artifacts, pytest temp
  folders, local databases, and ignored dataset staging folders?
- Does the package avoid PostgreSQL, Redis, dashboard UI, live integrations,
  and remediation by default?

## Quick Reference

- Local image: `threatprism:local-demo`.
- Local service: `threatprism-api`.
- API URL: `http://127.0.0.1:8000`.
- Persistent demo volume: `threatprism-data`.
- Focused tests: `tests/test_docker_packaging.py`.
