# Monitoring And Maintenance

ThreatPrism currently has demo-safe audit events and validation artifacts, but
it does not yet have production monitoring.

## Current Signals

| Signal | Location | Purpose |
|---|---|---|
| Authorization audit events | Case audit trail | Record allow and deny decisions. |
| Tokenization audit events | Case audit trail | Track sensitive-data detection and tokenization. |
| Role-view audit events | Case audit trail | Track role-view access decisions. |
| Eval artifacts | `.eval_runs/` | Sanitized dry-run eval results, ignored by git. |
| CSI/RGOI observability | `GET /csi/observability` | Visible cognitive object counts, stale cognition, AI non-authority, competing interpretation groups, and active controls. |
| CSI/RGOI divergence telemetry | `GET /csi/divergence` | AI-vs-human disagreement records for governed cognition. |
| Pytest output | local validation | Regression results for the current fake-data test suite. |
| Demo safety scanner | `tools/check_demo_safety.py` | Detect unsafe environment, artifact, and secret-looking repo states. |

## Local Maintenance Workflow

Run the safe validation wrapper after each slice:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

For pattern maintenance, follow:

```text
docs/runbooks/PATTERN_REFRESH.md
```

The first pattern refresh review is scheduled in `docs/WORKING_CHECKLIST.md`.

## Production Monitoring Gaps

Not yet implemented:

- service health metrics beyond `GET /health`
- request latency and error-rate tracking
- persistent audit export
- SIEM integration
- dashboard or BI monitoring
- alerting
- backup and restore monitoring
- model/provider drift monitoring for live LLMs
- production incident response runbook

These are future production-readiness items, not current demo guarantees.
