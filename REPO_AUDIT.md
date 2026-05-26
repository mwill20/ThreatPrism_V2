# Repository Audit

## Summary

ThreatPrism is a security-focused, AI-assisted SOC migration accelerator. The
repository is strong on architecture, guardrails, validation, fake-data safety,
implementation traceability, and now a hardened local same-origin dashboard
surface. The remaining readiness gaps are mostly reviewer-facing: license
status is not yet selected, production deployment remains out of scope, and
permanent visual demo assets are still not tracked.

Mode used: repo-standards Documentation Fix, audit-first.

## Scorecard

| Area | Status | Priority | Notes |
|---|---|---|---|
| Purpose and audience | PASS | High | README and North Star describe the SOC migration use case and demo-safe scope. |
| Installation and quickstart | PASS | High | README and docs/INSTALLATION.md include PowerShell setup, validation, API, and Docker commands. |
| Usage examples | PASS | High | README, RUNBOOK.md, and docs/USAGE.md cover API, dashboard, eval, scenario, and fixture workflows. |
| Architecture documentation | PASS | High | docs/ARCHITECTURE.md, docs/ARCHITECTURAL_NORTH_STAR.md, and specs cover system design and trust boundaries. |
| Dependencies and environment | PASS | High | requirements.txt uses exact pins; .env.example uses fake or empty values; requirements-lock.txt exists. |
| Evaluation and results | PASS | High | docs/EVALUATION.md and validation wrapper document the current fake-data regression evidence. |
| Dataset documentation | PASS | Medium | docs/DATASET.md clarifies that public datasets are reviewed source material only, not runtime dependencies. |
| Model documentation | PASS | Medium | docs/MODEL_CARD.md documents the deterministic demo provider and absence of live model use. |
| Security documentation | PASS | High | SECURITY.md and docs/threat-models/ cover guardrails, reporting, and threat model treatment. |
| Deployment documentation | PARTIAL | Medium | docs/DEPLOYMENT.md covers local demo, dashboard, and Docker Compose only; production deployment remains out of scope. |
| Monitoring/maintenance | PARTIAL | Medium | docs/MONITORING.md covers current logs, audit events, and future production monitoring gaps. |
| Limitations and trade-offs | PASS | High | LIMITATIONS.md is explicit about demo-only, no-remediation, no-live-provider, and dataset boundaries. |
| License and usage rights | FAIL | High | No LICENSE file exists. README now says usage rights are unclear until a license is selected. |
| Support/contact | PASS | Medium | README points to issues for non-security support and SECURITY.md for vulnerability handling. |
| Visual demo/assets | PARTIAL | Medium | A hardened local dashboard is available at `GET /dashboard`, but no permanent screenshot, GIF, or rendered architecture asset is tracked. |
| Examples | PASS | Medium | Fake SOAR payloads, demo scenarios, eval fixtures, and fixture-factory examples exist. |
| CI/tests | PASS | High | Fake-data-only GitHub Actions workflow and safe local validation wrapper are present. |

## Strengths

- Clear source-of-truth files: START_HERE.md, AGENTS.md, docs/THREATPRISM_V2_CODEX_HANDOFF.md, and docs/WORKING_CHECKLIST.md.
- Strong fake-data-only safety posture with explicit no-live-provider and no-real-remediation boundaries.
- Layered guardrails for prompt injection, healthcare-adjacent contamination, sensitive-data tokenization, evidence grounding, and compliance-language overclaiming.
- Role-aware demo authentication and authorization are covered by tests.
- Eval harness, scenario pack, Docker packaging, fixture factory, hardened local dashboard, and local validation wrapper make the project reproducible without live credentials.
- Threat model and treatment register are unusually mature for a demo-stage repository.

## Gaps Found

1. No `LICENSE` file exists, so usage rights are unclear.
2. Standard reviewer entry points for usage, evaluation, deployment, monitoring, dataset handling, model/provider behavior, and troubleshooting were either missing or distributed across longer docs.
3. `docs/INSTALLATION.md` had stale validation counts from an earlier slice.
4. No permanent visual screenshot or rendered diagram asset is tracked. Text
   diagrams exist and the local dashboard can be inspected at `/dashboard`,
   but screenshot/GIF assets are not committed.
5. Production-readiness boundaries needed a central deployment and monitoring summary.

## Changes Applied In This Pass

- Added this audit file.
- Added focused standalone docs:
  - `docs/USAGE.md`
  - `docs/EVALUATION.md`
  - `docs/DATASET.md`
  - `docs/MODEL_CARD.md`
  - `docs/DEPLOYMENT.md`
  - `docs/MONITORING.md`
  - `docs/TROUBLESHOOTING.md`
- Added root-level reviewer files:
  - `CONTRIBUTING.md`
  - `CHANGELOG.md`
- Updated README links, reviewer status, requirements, evaluation, license, and support sections.
- Updated installation validation counts and current direct pytest guidance.
- Updated working checklist, handoff, limitations, and lesson index for this readiness pass.
- Validated with `powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1 -BaseTemp .pytest_tmp_repo_standards_final_fresh`.

## Dashboard UI Follow-Up Pass

Dashboard UI Implementation v0.1 added a local fake-data-only dashboard served
from the existing FastAPI backend:

- `GET /dashboard`
- `src/threatprism/dashboard/static/`
- `docs/DASHBOARD_UI_IMPLEMENTATION.md`
- `docs/specs/25_DASHBOARD_UI_IMPLEMENTATION.md`
- `tests/test_dashboard_ui.py`

Repo-standards review notes for this follow-up:

- README, RUNBOOK, docs/USAGE, limitations, handoff, checklist, evaluation,
  and lessons now point to the dashboard route and implementation docs.
- The dashboard uses same-origin API calls and fake demo credentials only.
- The dashboard is not documented as production-ready.
- The main remaining dashboard readiness gap is a permanent screenshot or
  short demo recording asset, which should be added only when the user wants
  tracked visual assets.
- The license gap remains open.

Validated after the dashboard UI slice with:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1 -BaseTemp .pytest_tmp_dashboard_ui_final_validation2
```

Result:

```text
87 passed
eval harness dry-run: 15 passed / 0 failed
```

## Production Dashboard Hardening Follow-Up

Production Dashboard Hardening v0.1 added production-style controls to the
local fake-data dashboard without adding production IdP, live providers, real
data, external telemetry, frontend dependencies, or remediation:

- dashboard-specific CSP, frame blocking, no-sniff, referrer, permissions,
  same-origin resource, and no-store cache headers
- browser-side same-origin request enforcement
- timeout-bounded dashboard API calls
- keyboard persona navigation markers and visible focus state
- focused regression tests in `tests/test_dashboard_ui.py`
- threat-model and traceability updates for the now-implemented dashboard
  surface

Validated after the dashboard hardening slice with:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1 -BaseTemp .pytest_tmp_dashboard_hardening_final
```

Result:

```text
89 passed
eval harness dry-run: 15 passed / 0 failed
```

## Validation Performed

Successful result:

```text
73 passed
eval harness dry-run: 15 passed / 0 failed
```

An earlier run using the reused `.pytest_tmp_repo_standards_final` directory hit
the known Windows pytest temp cleanup failure (`WinError 5`) while deleting a
locked file. The fresh base temp rerun passed.

## Remaining Recommended Fixes

1. Select and add a real `LICENSE` file before presenting the repository as reusable open source.
2. Add a static architecture diagram image, dashboard screenshot, or short demo
   recording if tracked visual evidence becomes desirable.
3. Keep validation counts current after each slice.
4. Do not promote generated fixtures until the user manually reviews license, safety, and content.
5. Keep production deployment, live provider, RAG, memory/write-back, production IdP, non-demo data, and remediation work gated behind explicit future approval.
