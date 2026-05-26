# Lesson 17: Repo Standards Readiness Pass

## Goal

Understand how ThreatPrism presents itself to a reviewer: what the project is,
how to run it, what evidence supports it, and what remains explicitly out of
scope.

## Why This Matters

Security and AI projects are often judged as much by reproducibility and
boundary clarity as by code. ThreatPrism must make it easy for a reviewer to
answer:

- What does this project do?
- How do I run it safely?
- What data, model, and provider assumptions does it make?
- What has actually been validated?
- What claims are intentionally not made?

## Primary Files

- `REPO_AUDIT.md`
- `README.md`
- `CHANGELOG.md`
- `CONTRIBUTING.md`
- `docs/USAGE.md`
- `docs/EVALUATION.md`
- `docs/DATASET.md`
- `docs/MODEL_CARD.md`
- `docs/DEPLOYMENT.md`
- `docs/MONITORING.md`
- `docs/TROUBLESHOOTING.md`
- `LIMITATIONS.md`
- `docs/WORKING_CHECKLIST.md`

## Key Concepts

### Audit-First Documentation

The readiness pass starts with `REPO_AUDIT.md`. That file records strengths,
gaps, a scorecard, and remaining risks before claiming the repository is
reviewer-ready.

### Evidence-Based Claims

ThreatPrism documents the validation wrapper and current deterministic
fake-data results, but it does not claim production readiness, live LLM safety,
HIPAA compliance, HITRUST certification, or audit readiness.

### License Clarity

No license has been selected yet. The README and audit intentionally keep usage
rights marked unresolved instead of inventing a license.

### Demo-Only Boundaries

The readiness docs repeat the same operational contract:

- fake data only
- no live providers
- no real remediation
- no real organization or workplace data
- no real PHI or PII
- `ALLOW_REAL_ACTIONS=false`

## Hands-On Check

Run the safe validation wrapper:

```powershell
Set-Location C:\Projects\ThreatPrismV2
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

Then open:

```powershell
Get-Content .\REPO_AUDIT.md
Get-Content .\docs\EVALUATION.md
Get-Content .\docs\DEPLOYMENT.md
```

## Interview Talk Track

ThreatPrism is intentionally documented as a demo-safe, production-style
foundation rather than a production deployment. The repo standards pass makes
reviewer assumptions explicit: setup, validation, data boundaries, model
behavior, deployment gaps, monitoring gaps, license status, and support path
are all visible from first-level documentation.

## Quick Reference

| Question | File |
|---|---|
| What is the project? | `README.md` |
| How do I run it? | `docs/USAGE.md`, `RUNBOOK.md` |
| What was evaluated? | `docs/EVALUATION.md` |
| What data is used? | `docs/DATASET.md` |
| What model is used? | `docs/MODEL_CARD.md` |
| Can it be deployed? | `docs/DEPLOYMENT.md` |
| What is not implemented? | `LIMITATIONS.md` |
| What remains risky? | `REPO_AUDIT.md` |
