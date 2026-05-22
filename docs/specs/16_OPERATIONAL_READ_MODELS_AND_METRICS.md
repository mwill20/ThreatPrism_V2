# 16 Operational Read Models And Metrics

## Slice Name

Operational Read Models & Metrics API v0.1

## Goal

Expose safe, dashboard-ready backend responses for analysts, engineers,
managers, GRC reviewers, legal/privacy reviewers, and audit/debug workflows
without building a frontend dashboard or adding live integrations.

This slice turns the current case, report, feedback, disagreement, audit, and
guardrail data into stable read models that can support SOC operations and
future dashboard work.

## Why This Slice Is Next

ThreatPrism now has:

- Generic SOAR case intake.
- Deterministic triage and report rendering.
- Analyst feedback and disagreement tracking.
- Healthcare safeguard guardrails.
- Role-based rendering helpers.
- GRC evidence-linking and compliance-language blocking.

The next practical gap is visibility: managers, analysts, engineers, and GRC
reviewers need aggregate metrics and role-safe case views before ThreatPrism
adds a frontend dashboard, live SOAR callbacks, live LLMs, or production
integrations.

Update after architect review: this slice remains prepped and important, but
Access Control & Audit Integrity v0.1 should run first. Role-safe read models
should be backed by enforceable identity-to-role authorization before the API
surface expands.

## In Scope

### Metrics API

Implement a stable `GET /metrics` response shape for demo-safe aggregate data.

Metrics should include:

- Case volume totals.
- Case counts by source.
- Case counts by status.
- Triage counts by status.
- Determination, severity, and disposition counts.
- Guardrail block counts.
- Healthcare safeguard exposure counts.
- Secret exposure counts.
- Role-view rehydration denial counts.
- Analyst feedback counts.
- Determination, severity, and disposition disagreement counts.
- Manager review required counts.
- Average time to acknowledge.
- Average time to close.
- GRC mapping counts.
- Evidence-linked mapping counts.

### Case List Read Model

Make `GET /cases` dashboard-ready.

The implementation may either preserve the existing list response for backward
compatibility and add a new envelope route, or update tests and docs together if
the existing response changes.

Recommended stable envelope:

```json
{
  "items": [],
  "next_cursor": null,
  "total": 0,
  "filters": {}
}
```

Recommended filters:

- `source`
- `status`
- `triage_status`
- `severity`
- `determination`
- `manager_review_required`
- `healthcare_review_required`
- `guardrail_blocked`
- `created_after`
- `created_before`
- `limit`
- `cursor`

### Manager Review Queue

Expose a dashboard-ready way to retrieve cases that require manager review.

Preferred implementation:

```text
GET /cases?manager_review_required=true
```

Optional implementation if clearer:

```text
GET /review-queues/manager
```

Returned items must not expose raw potential PHI/ePHI or secrets.

### Healthcare Review Queue

Expose cases where healthcare safeguard metadata indicates possible regulated
data exposure.

Preferred implementation:

```text
GET /cases?healthcare_review_required=true
```

Returned items should include exposure metadata, token counts, detector
categories, and review flags, not raw sensitive values.

### Detail Read Routes

Add safe, evidence-linked detail routes:

```text
GET /cases/{case_id}/evidence
GET /cases/{case_id}/timeline
GET /cases/{case_id}/mitre
GET /cases/{case_id}/grc-controls
GET /cases/{case_id}/audit-events
```

Each route should support role-safe rendering, for example:

```text
GET /cases/{case_id}/evidence?role=manager_grc
```

If an endpoint supports `role`, it must apply the same role-view policy used by
case and report views.

### Audit And Guardrail Read Models

Expose enough audit metadata to explain what happened without exposing raw
sensitive values.

Audit/detail responses may include:

- `audit_event_id`
- `event_type`
- `actor`
- `summary`
- `created_at`
- safe metadata summaries

Audit/detail responses must not include raw potential PHI/ePHI, secrets, raw
credentials, or token vault mappings.

## Out Of Scope

- Frontend dashboard.
- Real SOAR callbacks.
- Live LLM calls.
- Live threat intelligence enrichment calls.
- Real remediation or containment.
- Production authentication or authorization.
- Break-glass raw sensitive value access.
- Long-term data warehouse or BI export.

## Security Rules

- Metrics must never expose raw case text, raw evidence excerpts, raw potential
  PHI/ePHI, secrets, or token vault mappings.
- Role-view rendering must be applied consistently for role-aware detail
  routes.
- Manager/GRC, legal/privacy, and audit/debug views must remain tokenized or
  masked by default.
- Analyst and engineer views may preserve security telemetry needed for SOC
  response, but must not rehydrate potential PHI/ePHI or secrets.
- All routes must stay demo-safe and fake-data-only.
- `ALLOW_REAL_ACTIONS=false` remains the default and must not be loosened.

## Response Shape Examples

### `GET /metrics`

```json
{
  "window": {
    "start": null,
    "end": null
  },
  "case_counts": {
    "total": 3,
    "by_source": {
      "generic_soar": 3
    },
    "by_status": {
      "triage_completed": 2,
      "needs_analyst_review": 1
    }
  },
  "triage": {
    "queued": 0,
    "running": 0,
    "completed": 2,
    "failed": 0,
    "blocked_by_guardrail": 1,
    "needs_review": 0
  },
  "guardrails": {
    "blocked_cases": 1,
    "healthcare_review_required": 1,
    "secret_exposure_detected": 1,
    "rehydration_denied_events": 2
  },
  "disagreement": {
    "feedback_count": 1,
    "determination_mismatch_count": 1,
    "severity_mismatch_count": 1,
    "disposition_mismatch_count": 1,
    "manager_review_required_count": 1
  },
  "timing": {
    "average_time_to_acknowledge_seconds": 120,
    "average_time_to_close_seconds": 900
  },
  "grc": {
    "mapping_count": 2,
    "mappings_with_evidence_count": 2,
    "review_required_count": 2
  }
}
```

### `GET /cases?manager_review_required=true`

```json
{
  "items": [
    {
      "case_id": "case_demo_001",
      "source": "generic_soar",
      "source_case_id": "SOAR-100245",
      "title": "Suspicious sign-in followed by mailbox rule creation",
      "status": "analyst_feedback_submitted",
      "triage_status": "completed",
      "triage": {
        "determination": "suspicious",
        "severity": "high",
        "disposition": "escalate",
        "confidence": 0.82
      },
      "manager_review_required": true,
      "healthcare_review_required": false,
      "guardrail_blocked": false,
      "created_at": "2026-05-21T18:31:03Z",
      "updated_at": "2026-05-21T19:02:44Z"
    }
  ],
  "next_cursor": null,
  "total": 1,
  "filters": {
    "manager_review_required": true
  }
}
```

## Implementation Notes

- Keep this as an API/backend slice. Do not start dashboard UI work.
- Prefer Pydantic response models for metrics and read-model envelopes.
- Keep aggregation logic in a service/module that can be tested without FastAPI.
- SQLite implementation can start from stored JSON payloads, but avoid a design
  that blocks later normalized tables or PostgreSQL.
- Keep existing tests passing. If `GET /cases` response shape changes, update
  all docs and tests in the same commit.
- Add fake fixture cases in tests rather than adding real data files unless a
  fake reusable payload is genuinely useful.

## Acceptance Criteria

- `GET /metrics` returns a stable aggregate response shape.
- `GET /cases` supports dashboard-useful filtering or has a documented
  companion route that does.
- Manager-review and healthcare-review case queues can be expressed through
  filters or dedicated routes.
- Detail routes return evidence, timeline, MITRE, GRC, and audit/event data in
  role-safe form.
- Metrics and read models do not expose raw potential PHI/ePHI or secrets.
- Role-aware routes record audit events when role-view policy is applied or
  rehydration is denied.
- GRC detail responses cite evidence IDs and avoid compliance claims.
- Tests cover metrics aggregation, filtering, manager review queue behavior,
  healthcare review queue behavior, detail routes, and no sensitive value leaks.
- Safe local validation passes.

## Recommended Implementation Prompt

```text
Implement Operational Read Models & Metrics API v0.1 for ThreatPrism.

Use the existing clean V2 backend. Do not add frontend dashboard work, live LLMs,
live SOAR calls, live enrichment calls, production credentials, or real
remediation. Keep ALLOW_REAL_ACTIONS=false and use fake fixtures only.

Add stable dashboard-ready read models and tests for:
- GET /metrics
- filtered case list or a companion case-list envelope route
- manager-review queue behavior
- healthcare-review queue behavior
- evidence, timeline, MITRE, GRC, and audit-events detail routes
- role-safe rendering on detail routes
- no raw potential PHI/ePHI or secrets in metrics, manager/GRC views, legal/privacy views, or audit/debug views
- GRC mappings still citing evidence IDs and avoiding compliance claims

Run:
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_metrics
```
