# Spec Review Summary

## Scope

This original review covered the ThreatPrism V2 spec pack only. Since then,
implementation has begun in the live workspace. Treat this file as a spec review
record plus current implementation status, not as evidence that the repository
is still docs-only.

Current live implementation includes:

- FastAPI core routes.
- Case, triage report, analyst feedback, disagreement, evidence, MITRE, GRC,
  action, and audit schemas.
- Generic SOAR payload normalization.
- Prompt firewall, tokenization, output policy scanning, evidence-grounding
  checks, and action-safety checks.
- Deterministic demo provider.
- SQLite demo persistence.
- Deterministic report rendering.
- Fake demo SOAR payloads.
- API, guardrail, guardrail-failure, enrichment-stub, and SOAR adapter tests.

## What Was Improved

- Added API security boundary guidance to separate localhost demo mode from production-style case data exposure.
- Added future authorization role expectations for analyst, manager, engineer, and admin users.
- Expanded the API contract for dashboard-ready routes:
  - `GET /metrics`
  - `GET /cases/{case_id}/evidence`
  - `GET /cases/{case_id}/timeline`
  - `GET /cases/{case_id}/ioc-enrichment`
  - `GET /cases/{case_id}/mitre`
  - `GET /cases/{case_id}/grc-controls`
  - `POST /evals/run`
- Added source payload traceability fields:
  - `source_payload_hash`
  - `source_metadata`
  - `case_source_payloads`
- Clarified that raw source payloads must not be returned by default.
- Added `API_AUTH_MODE` and `API_TOKEN` configuration placeholders.
- Added acceptance criteria for metrics, detail routes, dry-run evals, and API authentication boundaries.
- Recorded the canonical local workspace path as `C:\Projects\ThreatPrismV2`.

## Remaining Open Decisions

- How much additional V1 behavior should be selectively ported into the clean
  V2 architecture.
- Whether the first async triage implementation should use in-process FastAPI background tasks or a separate worker.
- How much of the V1 CLI should be preserved directly versus wrapped around the new case model.
- Exact API authentication mechanism for non-demo use.
- Whether raw redacted payload snapshots should be stored in demo mode or only payload hashes and normalization warnings.

## Risks And Blockers

- This workspace is not currently a Git repository, so implementation history, branching, and commits are not available yet.
- The destination repository `mwill20/ThreatPrism_V2` exists, but the local
  workspace still needs to be initialized or synced as that checkout.
- Full production authentication, authorization, deployment hardening, and RBAC are intentionally out of scope for the first build slice but must not be ignored before real data is used.
- V2 must preserve useful V1 behavior without letting old README assumptions override the handoff brief.

## Recommended First Implementation Slice

Continue hardening the first vertical slice:

```text
Generic SOAR webhook payload
  -> Normalize into ThreatPrism Case
  -> Start async triage job
  -> Generate structured triage report
  -> Add MITRE + IOC + GRC mappings, even if stubbed
  -> Return/report status via API
  -> Analyst submits feedback
  -> ThreatPrism records disagreement metrics
```

Implementation prerequisites:

1. Initialize or sync this workspace with `mwill20/ThreatPrism_V2`.
2. Commit and push the current validated baseline.
3. Keep selective V1 concept porting; do not full-copy V1.
4. Continue with fake demo payloads only.
5. Keep real actions blocked with `ALLOW_REAL_ACTIONS=false`.
6. Continue adding focused failure-path tests beyond the current guardrail,
   unsupported evidence ID, and unsafe action claim coverage.
