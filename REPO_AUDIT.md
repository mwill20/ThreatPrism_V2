# Repository Audit

**Date:** 2026-06-03 · **Mode:** Closeout Review (report + doc-currency pass)

**Project type:** Security tool (SOC triage co-pilot) + AI/ML-assisted (LLM triage,
gate open) + lightly agentic (human-in-the-loop co-pilot; no autonomous tools) +
educational (Lessons 1–41). Stage: demo / POC with synthetic data only.

## Summary (closeout)

The repository is publication-strong on every axis but one: layered guardrails, a mature
three-lens threat model with treatment register, fake-data-only safety enforced in CI,
exact dependency pins with a lock file, a 41-lesson curriculum, **rendered (SVG + PNG)
architecture + threat-model diagrams**, a tamper-evident integrity subsystem (failure
log + audit mirror + verify CLI), the real-LLM gate opened and live-verified, all three
runtime evolutions demonstrated, and a governed (demo-only, human-gated) RGOI write-back
loop — with retrieval-into-triage deliberately built-but-not-wired and that disconnection
enforced by a test. Validation is single-sourced at **314 passed / 3 skipped**, eval
15/15, demo safety passing.

**As of 2026-06-03 the license blocker is resolved** — the project is licensed under
**Apache-2.0** (`LICENSE`). All scorecard rows are now PASS or PARTIAL-by-design
(production deployment/monitoring intentionally gated). No publication blockers remain.

## Scorecard

| Area | Status | Priority | Notes |
|------|--------|----------|-------|
| Purpose and audience | PASS | High | README purpose/audience/status; START_HERE + North Star reinforce. |
| Installation and quickstart | PASS | High | README + docs/INSTALLATION.md: PowerShell setup, validation, API, Docker. |
| Usage examples | PASS | High | README, RUNBOOK.md, docs/USAGE.md: API, dashboard, eval, scenario, fixtures, co-pilot, verify-logs. |
| Architecture documentation | PASS | High | docs/ARCHITECTURE.md (rendered Mermaid + ASCII + components) + two threat-model diagrams (trust-boundary DFD + OWASP-LLM overlay) in system-context.md; rendered SVG/PNG in `assets/diagrams/`; North Star + specs. |
| Dependencies and environment | PASS | High | requirements.txt exact pins; requirements-lock.txt; requirements-llm.txt (gated); .env.example placeholders only. |
| Evaluation and results | PASS | High | docs/EVALUATION.md + docs/VALIDATION_BASELINE.md (single source: 314 passed / 3 skipped, eval 15/15); live findings in LIVE_BACKTEST_FINDINGS.md. |
| Dataset documentation | PASS | Medium | docs/DATASET.md: third-party datasets are reviewed source material, not runtime deps. |
| Model documentation | PASS | Medium | docs/MODEL_CARD.md refreshed 2026-06-03: documents the default demo provider, the open real-LLM gate (Claude triage + OpenAI analyst + Prompt Guard 2 under `--live`), live-eval performed, and the demo-only RGOI write-back. |
| Security documentation | PASS | High | SECURITY.md + three-lens threat model + mitigations-traceability + treatment register + new rendered threat-model DFD. |
| Deployment documentation | PARTIAL | Medium | docs/DEPLOYMENT.md covers local/Docker only; production deployment intentionally out of scope. |
| Monitoring/maintenance | PARTIAL | Medium | docs/MONITORING.md + new tamper-evident logs & verify CLI; production monitoring still gated. |
| Limitations and trade-offs | PASS | High | LIMITATIONS.md explicit on demo-only / no-remediation / gated scope. |
| License and usage rights | PASS | High | **Apache-2.0** (`LICENSE`, added 2026-06-03); README License section + Project Status updated. Permissive + patent grant. |
| Support/contact | PASS | Medium | README → issues; SECURITY.md for vulnerabilities. |
| Visual demo/assets | PASS | Medium | Committed rendered images (SVG + PNG) in `assets/diagrams/` (architecture, threat-model DFD, applied overlay), embedded in README; local dashboard at `/dashboard`. A dashboard screenshot/GIF remains optional polish. |
| Examples | PASS | Medium | examples/ (soar_payloads, demo_scenarios, csi, dashboard_contract); curated fixtures; eval fixtures. |
| CI/tests | PASS | High | .github/workflows/safe-validation.yml (Ubuntu, py3.12, fake-data env); 305 collected tests; demo-safety gate. |

## Strengths

- **Safety posture:** fake-data-only (RFC 5737 IPs, `.test` domains), `ALLOW_REAL_ACTIONS=false`, demo-safety scanner gating CI and every commit.
- **Guardrails:** four-layer pipeline (prompt firewall → healthcare → output policy → evidence) + a semantic firewall (detector, default-off, live-verified 4/6 RR-L1).
- **Two-stage tokenization:** permanent Stage-1 (PHI/PII/secrets) vs. rehydratable Stage-2 (telemetry) — a genuinely well-reasoned privacy boundary.
- **Real-LLM seam:** gate opened + live-verified; spend governance (per-run cap, metering, hashed-only call audits); independent OpenAI analyst with an egress guard.
- **Three runtime evolutions** all demonstrated (Evolutions 2 and 3 live).
- **Tamper-evident integrity subsystem:** hash-chained `FailureLog` + case audit-trail mirror + operator `verify_logs` CLI (closes much of OT-1/OT-8).
- **Threat modeling** unusually mature for demo stage: STRIDE + MITRE ATLAS/OWASP-LLM + LINDDUN, traceability matrix, owner-signed treatment register, now a rendered DFD.
- **Reproducibility & docs:** single-source validation baseline, lessons 1–41 (incl. a capstone), durable handoff files.

## Missing Files

- `CITATION.cff` — Optional. The repo has portfolio/educational intent; a citation file would aid reuse/citeability.
- `assets/` screenshot or GIF — Optional polish. Rendered Mermaid + ASCII diagrams already exceed the minimum visual requirement.

## Weak / Partial Areas

- **Deployment / Monitoring** are PARTIAL by design — production deployment, IdP, and production monitoring are explicitly gated, which is honest and correct for this stage (not a defect).
- (Resolved this pass) docs/MODEL_CARD.md was stale re: the open real-LLM gate; refreshed 2026-06-03.

## Reproducibility Gaps

- None material. `pip install -r requirements.txt` + `tools/validate-threatprism.ps1` reproduces the baseline; the Windows pytest-temp `WinError 5` workaround (fresh `-BaseTemp`) is documented.

## Security and Licensing Gaps

- **Licensed Apache-2.0** (`LICENSE`, 2026-06-03) — license gap closed. No secrets committed — verified by the demo-safety scanner (`--include-untracked`) and placeholder-only `.env.example`.

## Minor Hygiene

- Stray `pytest-cache-files-*` directories sit at the repo root (untracked, not committed). A `.gitignore` entry would keep the working tree clean.

## Priority Fix Order (closeout)

No blockers remain. Optional polish only:

1. *(Optional)* Add `CITATION.cff` for portfolio citeability.
2. *(Optional)* Track a dashboard screenshot/GIF; gitignore the `pytest-cache-files-*` dirs.

All prior gaps are resolved: **Apache-2.0 license added**, MODEL_CARD refreshed, diagrams
rendered to committed images, baseline single-sourced and current.

## Validation Reference

Canonical baseline is single-sourced in
[docs/VALIDATION_BASELINE.md](docs/VALIDATION_BASELINE.md): **314 passed / 3 skipped**,
eval harness dry-run **15 passed / 0 failed**, demo safety passed (closeout run
2026-06-03). CI: `.github/workflows/safe-validation.yml` (Ubuntu, Python 3.12, fake-data
env, no live keys).

## Closeout Verdict

**Publication-ready (demo/POC scope).** The project is internally consistent, fully
documented (41 lessons, complete spec/threat-model/runbook set), reproducible offline,
demo-safe, green (314/3, eval 15/15), and **Apache-2.0 licensed**. No publication
blockers remain — optional polish (CITATION.cff, a screenshot) aside. Production
capabilities (live deployment, RAG-into-triage, write-back persistence, multi-tenancy,
real data) remain intentionally gated with documented re-open triggers.

---

## Audit History (superseded — see current audit above)

The sections below are dated records from earlier readiness passes; their validation
counts (73 / 87 / 89 passed) reflect those points in time and are superseded by the
current baseline above.

### Dashboard UI Follow-Up Pass

Dashboard UI Implementation v0.1 added a local fake-data-only dashboard served from the
existing FastAPI backend (`GET /dashboard`, `src/threatprism/dashboard/static/`,
`docs/DASHBOARD_UI_IMPLEMENTATION.md`, `docs/specs/25_DASHBOARD_UI_IMPLEMENTATION.md`,
`tests/test_dashboard_ui.py`). Same-origin API calls, fake demo credentials only, not
documented as production-ready. Result at the time: `87 passed`, eval 15/15.

### Production Dashboard Hardening Follow-Up

Production Dashboard Hardening v0.1 added dashboard-specific CSP, frame blocking,
no-sniff/referrer/permissions headers, same-origin request enforcement, timeout-bounded
fetches, keyboard persona navigation, and regression tests — without production IdP,
live providers, real data, external telemetry, or remediation. Result at the time:
`89 passed`, eval 15/15.
