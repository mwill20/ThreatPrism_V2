# Changelog

All notable repository-level changes should be recorded here.

## Unreleased

- Opened the real-LLM gates (owner-authorized 2026-06-01): live Anthropic triage,
  OpenAI independent analyst, and the local Prompt Guard 2 semantic firewall. Spec
  21 threat-treatment register updated — re-opened L1/RR-L1, L5/OT-L3, L7/OT-L7
  with current-mitigation evidence; added new trust-boundary threats OT-L10
  (analyst data egress), OT-L11a/b/c (triage egress, local-model supply chain,
  detector-not-gate); logged residual-risk acceptances with owner-signature
  placeholders and a pre-flight checklist. Added `tests/test_analyst_egress.py`
  guarding that the OpenAI analyst prompt carries only Stage-1 tokens, never raw
  PHI/secrets. Tools/function-calling, memory write-back, multi-tenancy,
  fine-tuning, non-demo data, and real PHI remain Avoid/Gated. Baseline
  `271 -> 272 passed`.
- Unified secret-pattern detection into a single shared catalog
  (`src/threatprism/guardrails/secret_catalog.py`, spec 34 §3). The product
  detectors (`healthcare.py` `SECRET_RULES`, `tokenization.py` `secret_like`,
  `policy.py`) and the standalone dev-workflow hook (`tools/hooks/_common.py`,
  loaded by file path) now derive every secret-shaped regex from one source, so
  product and dev-workflow secret detection stay in sync under one quarterly
  refresh. Healthcare/tokenization detection is byte-for-byte unchanged; policy
  and the hook broadened only in the safe direction. Added
  `tests/test_secret_catalog.py` and Lesson 35. Baseline `267 -> 271 passed`.
- Fixed an in-memory SQLite concurrency bug: the shared `:memory:` connection
  returned HTTP 500 under FastAPI threadpool concurrency (the dashboard's
  parallel per-case detail fetches). Added a `threading.Lock` and a
  `_transaction()` context manager serializing access to the shared connection;
  file-backed mode keeps connection-per-op. Added a barrier-synchronized
  concurrency regression test and Lesson 34. Baseline `266 -> 267 passed`.
- Added Production Token Verifier Design v0.1 with the future `external_oidc`
  verifier contract, claim-to-role mapping rules, JWKS/cache boundaries,
  fail-closed semantics, sanitized audit requirements, no-network validation
  rules, docs, runbook, lesson, and threat-model notes.
- Added Production Identity Readiness v0.1 with static `external_oidc`
  configuration validation, unknown-auth-mode rejection, live-verifier
  rejection, fail-closed protected-route behavior, docs, runbook, and tests.
- Expanded the curated fixture set to four tiny hand-reviewed fake fixtures
  covering SOC, healthcare-context exposure, sanitized prompt-injection, and
  evidence-conflict/GRC review, with stronger manifest and scenario tests.
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
