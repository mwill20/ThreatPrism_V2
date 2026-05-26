# Changelog

All notable repository-level changes should be recorded here.

## Unreleased

- Added Curated Generated-Fixture Promotion v0.1 with a tracked fake SOC
  fixture, manifest review gate, path-safe promotion loader, tests, and docs
  while keeping `fixtures/generated/` ignored and out of automatic scans.
- Documented Exa.ai or equivalent public-web research providers as optional
  future enhancement candidates only, outside the current CSI/RGOI, validation,
  demo, RAG, memory write-back, fixture-promotion, and source-of-truth paths.
- Added production-style hardening for the local dashboard: CSP/framing/
  referrer/permission headers, same-origin request enforcement, API request
  timeouts, keyboard persona navigation, tests, docs, and threat-model updates.
- Added local fake-data-only dashboard UI at `GET /dashboard`, same-origin
  static assets, dashboard UI tests, and Browser verification notes.
- Added CSI/RGOI read-only governed cognition foundation with schemas,
  retrieval governance, trust scoring, evidence alignment, lineage, replay,
  observability, divergence telemetry, fake fixtures, docs, and tests.
- Added dashboard UI preparation docs, fake persona response fixtures,
  dashboard-readiness runbook, and CSI route contract tests without building a
  frontend dashboard.
- Added repository standards readiness audit and reviewer-focused docs.
- Documented usage, evaluation, dataset, model/provider, deployment,
  monitoring, and troubleshooting entry points.
- Clarified license status, support path, and demo-only production boundaries.

## Current Baseline

- Implemented fake-data FastAPI backend with case intake, triage reports,
  guardrails, role-aware reads, operational metrics, eval harness, demo
  scenario pack, Docker Compose local packaging, and synthetic fixture factory.
- Current safe validation baseline is tracked in README.md, RUNBOOK.md,
  START_HERE.md, LIMITATIONS.md, and docs/WORKING_CHECKLIST.md.
