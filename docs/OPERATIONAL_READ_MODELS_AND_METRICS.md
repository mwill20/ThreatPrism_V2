# Operational Read Models And Metrics

Operational Read Models & Metrics API v0.1 is implemented.

This slice exposes safe backend read surfaces for future dashboard, manager,
GRC, legal/privacy, audit/debug, analyst, and engineer workflows without
building a frontend or adding live integrations.

## Implemented Routes

```text
GET /metrics
GET /cases/read-model
GET /cases/{case_id}/evidence
GET /cases/{case_id}/timeline
GET /cases/{case_id}/mitre
GET /cases/{case_id}/grc-controls
GET /cases/{case_id}/audit-events
```

The existing `GET /cases` list route is preserved for compatibility. The
dashboard-ready envelope route is `GET /cases/read-model`.

## Metrics Coverage

`GET /metrics` returns aggregate demo-safe metrics for:

- Case volume.
- Counts by source and status.
- Triage status counts.
- Determination, severity, and disposition counts.
- Guardrail block counts.
- Healthcare safeguard review counts.
- Potential sensitive data exposure counts.
- Secret exposure counts.
- Rehydration denial counts.
- Role-view policy application counts.
- Authorization allow and deny counts.
- Analyst feedback counts.
- Disagreement counts.
- Manager review required counts.
- Average time to acknowledge.
- Average time to close.
- GRC mapping counts.
- Evidence-linked GRC mapping counts.

## Read-Model Filtering

`GET /cases/read-model` supports:

```text
source
status
triage_status
severity
determination
manager_review_required
healthcare_review_required
guardrail_blocked
authorization_denied
created_after
created_before
limit
cursor
role
```

The response shape is:

```json
{
  "items": [],
  "next_cursor": null,
  "total": 0,
  "filters": {},
  "role_view": null
}
```

## Security Boundary

Read models and metrics must not expose:

- Raw potential PHI/ePHI.
- Secrets.
- Full credentials.
- Raw payload bodies.
- Token vault mappings.

When `API_AUTH_MODE=demo_key`, role-aware read routes require fake demo
credentials and deny role escalation. `?role=` is treated as a requested view,
not authority.

## GRC Boundary

GRC detail responses cite evidence IDs and keep the existing language note:

```text
HITRUST-aligned category mapping only; this is not a compliance determination.
```

ThreatPrism still does not claim HIPAA compliance, HIPAA certification, HITRUST
compliance, HITRUST certification, control satisfaction, audit readiness, or
that evidence proves compliance.

## Validation

Validated on 2026-05-23 with:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_metrics2
```

Result:

```text
34 passed
```

## Next Slice

The next recommended slice is Evaluation Harness & Defense Labs v0.1.

Reason: ThreatPrism now has intake, guardrails, access control, metrics, and
safe read models. Before adding live providers, dashboard UI, Docker/CI, or
production-style integrations, the project needs repeatable dry-run evals that
prove prompt-injection, evidence-grounding, schema, action-safety,
healthcare-safeguard, authorization, and leakage controls continue to hold.
