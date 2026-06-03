# Repository Audit

**Date:** 2026-06-03 · **Mode:** Audit Only (report; no file changes beyond this report)

**Project type:** Security tool (SOC triage co-pilot) + AI/ML-assisted (LLM triage,
gate now open) + lightly agentic (human-in-the-loop co-pilot; no autonomous tools) +
educational (Lessons 1–40). Stage: demo / POC with synthetic data only.

## Summary

The repository is publication-strong on nearly every axis: layered guardrails, a mature
three-lens threat model with treatment register, fake-data-only safety enforced in CI,
exact dependency pins with a lock file, an extensive lesson curriculum, rendered
architecture + threat-model diagrams, and a tamper-evident integrity subsystem. Since
the prior audit, the real-LLM gate has been opened and live-verified, all three runtime
evolutions have been demonstrated, and the validation baseline is single-sourced.

**The one High-priority blocker remains: no `LICENSE` file** — usage rights are unclear
until the owner selects one. One doc-accuracy follow-up (model card vs. now-open real-LLM
gate) and a couple of optional polish items round out the gaps.

## Scorecard

| Area | Status | Priority | Notes |
|------|--------|----------|-------|
| Purpose and audience | PASS | High | README purpose/audience/status; START_HERE + North Star reinforce. |
| Installation and quickstart | PASS | High | README + docs/INSTALLATION.md: PowerShell setup, validation, API, Docker. |
| Usage examples | PASS | High | README, RUNBOOK.md, docs/USAGE.md: API, dashboard, eval, scenario, fixtures, co-pilot, verify-logs. |
| Architecture documentation | PASS | High | docs/ARCHITECTURE.md now has a rendered **Mermaid** diagram + ASCII + component layers; North Star + specs. |
| Dependencies and environment | PASS | High | requirements.txt exact pins; requirements-lock.txt; requirements-llm.txt (gated); .env.example placeholders only. |
| Evaluation and results | PASS | High | docs/EVALUATION.md + docs/VALIDATION_BASELINE.md (single source: 302 passed / 3 skipped, eval 15/15); live findings in LIVE_BACKTEST_FINDINGS.md. |
| Dataset documentation | PASS | Medium | docs/DATASET.md: third-party datasets are reviewed source material, not runtime deps. |
| Model documentation | PARTIAL | Medium | docs/MODEL_CARD.md exists but predates the open real-LLM gate — should reflect that real Claude/OpenAI now run under `--live`. |
| Security documentation | PASS | High | SECURITY.md + three-lens threat model + mitigations-traceability + treatment register + new rendered threat-model DFD. |
| Deployment documentation | PARTIAL | Medium | docs/DEPLOYMENT.md covers local/Docker only; production deployment intentionally out of scope. |
| Monitoring/maintenance | PARTIAL | Medium | docs/MONITORING.md + new tamper-evident logs & verify CLI; production monitoring still gated. |
| Limitations and trade-offs | PASS | High | LIMITATIONS.md explicit on demo-only / no-remediation / gated scope. |
| License and usage rights | FAIL | High | **No LICENSE file.** README flags usage rights as unclear. The one real blocker. |
| Support/contact | PASS | Medium | README → issues; SECURITY.md for vulnerabilities. |
| Visual demo/assets | PASS | Medium | Rendered Mermaid architecture + threat-model diagrams + ASCII; local dashboard at `/dashboard`. Tracked screenshot/GIF still optional. |
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
- **Reproducibility & docs:** single-source validation baseline, lessons 1–40 incl. a capstone, durable handoff files.

## Missing Files

- `LICENSE` — **High.** Absent; usage rights unclear (owner must choose).
- `CITATION.cff` — Optional. The repo has portfolio/educational intent; a citation file would aid reuse/citeability.
- `assets/` screenshot or GIF — Optional polish. Rendered Mermaid + ASCII diagrams already exceed the minimum visual requirement.

## Weak / Partial Areas

- **docs/MODEL_CARD.md** likely still describes only the deterministic demo provider; the real-LLM gate is now open and live-run, so the card should note real Claude/OpenAI usage under `--live` (and that the default remains the demo provider).
- **Deployment / Monitoring** are PARTIAL by design — production deployment, IdP, and production monitoring are explicitly gated, which is honest and correct for this stage (not a defect).

## Reproducibility Gaps

- None material. `pip install -r requirements.txt` + `tools/validate-threatprism.ps1` reproduces the baseline; the Windows pytest-temp `WinError 5` workaround (fresh `-BaseTemp`) is documented.

## Security and Licensing Gaps

- **LICENSE absent** (the one High gap). No secrets committed — verified by the demo-safety scanner (`--include-untracked`) and placeholder-only `.env.example`.

## Minor Hygiene

- Stray `pytest-cache-files-*` directories sit at the repo root (untracked, not committed). A `.gitignore` entry would keep the working tree clean.

## Priority Fix Order

1. **Add a `LICENSE`** (requires the owner's choice) — the only blocker to presenting the repo as reusable/publishable.
2. **Refresh `docs/MODEL_CARD.md`** to reflect the now-open real-LLM gate (real providers under `--live`; demo default).
3. *(Optional)* Add `CITATION.cff` for portfolio citeability.
4. *(Optional)* Track a dashboard screenshot/GIF; gitignore the `pytest-cache-files-*` dirs.

## Validation Reference

Canonical baseline is single-sourced in
[docs/VALIDATION_BASELINE.md](docs/VALIDATION_BASELINE.md): **302 passed / 3 skipped**,
eval harness dry-run **15 passed / 0 failed**, demo safety passed. CI:
`.github/workflows/safe-validation.yml` (Ubuntu, Python 3.12, fake-data env, no live keys).

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
