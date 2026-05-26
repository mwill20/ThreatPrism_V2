# 04 API Contract

## Contract Rules

- API responses must be JSON.
- Request and response models must be schema-validated.
- API output must be dashboard-ready.
- Case content is untrusted input.
- AI-generated fields must be marked by source and validated before persistence.
- Error responses must be structured and must not leak secrets.
- Raw source payloads must not be returned by default.
- Endpoints that return case details must return redacted or normalized fields unless an explicit future export permission is defined.
- Current route and key response-model expectations are covered by
  `tests/test_demo_scenarios_and_api_contract.py`.

## Contract Freeze Status

Demo Scenario Pack & API Contract Freeze v0.1 is implemented. Later slices may
add routes, but removing or renaming current routes must be treated as a
contract change and reflected in tests, docs, and decision records.

## API Security Boundary

Demo mode may run without authentication on localhost only.

Production-style deployments must require an authentication and authorization layer before exposing case data. The first implementation slice does not need full RBAC, but it must avoid designs that make RBAC difficult later.

Minimum future authorization roles:

- `analyst`: read cases, read reports, submit analyst feedback.
- `manager`: read aggregate metrics and manager-review queues.
- `engineer`: read integration diagnostics and eval results.
- `admin`: configure providers and integration settings.

No role in V2 may execute real remediation actions.

## Common Error Format

```json
{
  "error": {
    "code": "validation_error",
    "message": "Request payload did not match the expected schema.",
    "details": [
      {
        "field": "source_case_id",
        "issue": "required"
      }
    ],
    "request_id": "req_01JZ7P7KJWA41TNE6PVWJH64ZG"
  }
}
```

## Core Routes

### GET /health

Returns service health.

Example response:

```json
{
  "status": "ok",
  "service": "threatprism-api",
  "version": "0.1.0",
  "mode": "demo",
  "allow_real_actions": false
}
```

### POST /cases

Creates a normalized case from a source payload or normalized case request.

Example generic SOAR request:

```json
{
  "source": "generic_soar",
  "source_case_id": "SOAR-100245",
  "organization_context": {
    "environment": "demo",
    "business_unit": "internal_soc",
    "sensitivity": "demo"
  },
  "title": "Suspicious sign-in followed by mailbox rule creation",
  "description": "SOAR closed this case after automated checks. ThreatPrism should validate the closure.",
  "created_at": "2026-05-21T18:30:00Z",
  "alerts": [
    {
      "alert_id": "alert-001",
      "name": "Impossible travel sign-in",
      "severity": "medium",
      "source": "identity_provider",
      "description": "User sign-in from two distant locations within a short interval."
    }
  ],
  "events": [
    {
      "event_id": "evt-001",
      "timestamp": "2026-05-21T18:21:00Z",
      "event_type": "signin",
      "description": "Successful sign-in from unfamiliar location.",
      "raw_reference": "demo://events/evt-001"
    }
  ],
  "entities": [
    {
      "entity_type": "user",
      "value": "demo.user@example.invalid",
      "role": "subject"
    }
  ],
  "iocs": [
    {
      "ioc_type": "ip",
      "value": "203.0.113.42",
      "source": "alert"
    }
  ],
  "evidence": [
    {
      "evidence_id": "ev-001",
      "evidence_type": "log",
      "summary": "Identity sign-in log shows unfamiliar source IP.",
      "source_uri": "demo://logs/signin/evt-001"
    }
  ]
}
```

Example accepted response:

```json
{
  "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
  "source": "generic_soar",
  "source_case_id": "SOAR-100245",
  "status": "queued_for_triage",
  "triage_status": "queued",
  "tracking_id": "triage_01JZ7NQ2VBE3D9HB4C2M9P3VMF",
  "created_at": "2026-05-21T18:31:03Z",
  "links": {
    "case": "/cases/case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
    "triage_report": "/cases/case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX/triage-report",
    "analyst_feedback": "/cases/case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX/analyst-feedback"
  }
}
```

### GET /cases

Returns the compatibility case-summary list used by the first backend slice.

The dashboard-ready envelope route is `GET /cases/read-model`.

Example response:

```json
[
  {
    "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
    "source": "generic_soar",
    "source_case_id": "SOAR-100245",
    "title": "Suspicious sign-in followed by mailbox rule creation",
    "status": "triage_completed",
    "triage_status": "completed",
    "triage": {
      "determination": "suspicious",
      "severity": "high",
      "disposition": "escalate",
      "confidence": 0.82
    },
    "manager_review_required": true,
    "created_at": "2026-05-21T18:31:03Z",
    "updated_at": "2026-05-21T18:33:19Z"
  }
]
```

### GET /cases/read-model

Returns the dashboard-ready case-list envelope.

Query parameters:

- `source`
- `status`
- `triage_status`
- `severity`
- `determination`
- `manager_review_required`
- `healthcare_review_required`
- `guardrail_blocked`
- `authorization_denied`
- `created_after`
- `created_before`
- `limit`
- `cursor`
- `role`

Example response:

```json
{
  "items": [
    {
      "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
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
      "authorization_denied": false,
      "created_at": "2026-05-21T18:31:03Z",
      "updated_at": "2026-05-21T19:02:44Z"
    }
  ],
  "next_cursor": null,
  "total": 1,
  "filters": {
    "manager_review_required": true
  },
  "role_view": null
}
```

### GET /cases/{case_id}

Returns the full normalized case record, excluding raw sensitive payloads by default.

Example response:

```json
{
  "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
  "source": "generic_soar",
  "source_case_id": "SOAR-100245",
  "title": "Suspicious sign-in followed by mailbox rule creation",
  "description": "SOAR closed this case after automated checks. ThreatPrism should validate the closure.",
  "status": "triage_completed",
  "alerts": [],
  "events": [],
  "entities": [],
  "iocs": [],
  "evidence": [],
  "triage_status": "completed",
  "created_at": "2026-05-21T18:31:03Z",
  "updated_at": "2026-05-21T18:33:19Z"
}
```

### GET /cases/{case_id}/triage-report

Returns the latest validated triage report.

Example response:

```json
{
  "report_id": "report_01JZ7NSCBXY5K48FEJRBHX8WHR",
  "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
  "report_version": 1,
  "status": "completed",
  "summary": "Evidence suggests suspicious identity activity that needs analyst review before closure.",
  "determination": "suspicious",
  "severity": "high",
  "disposition": "escalate",
  "confidence": 0.84,
  "evidence": [
    {
      "evidence_id": "ev-001",
      "claim": "Unfamiliar IP was observed in the sign-in event.",
      "supports": ["severity", "disposition"]
    }
  ],
  "timeline": [
    {
      "timestamp": "2026-05-21T18:21:00Z",
      "event_type": "signin",
      "summary": "Successful sign-in from unfamiliar location.",
      "evidence_id": "ev-001"
    }
  ],
  "iocs": [
    {
      "ioc_type": "ip",
      "value": "203.0.113.42",
      "confidence": 0.7,
      "enrichment_status": "not_configured"
    }
  ],
  "mitre_mappings": [
    {
      "tactic": "Initial Access",
      "technique": "Valid Accounts",
      "technique_id": "T1078",
      "confidence": 0.66,
      "evidence_ids": ["ev-001"]
    }
  ],
  "hypotheses": [
    {
      "hypothesis": "The account may have been accessed with valid credentials from an unfamiliar location.",
      "confidence": 0.72,
      "evidence_ids": ["ev-001"]
    }
  ],
  "recommended_actions": [
    {
      "action": "Review recent sign-in history and mailbox rule changes.",
      "action_type": "analyst_review",
      "priority": "high"
    }
  ],
  "simulated_actions": [
    {
      "action": "simulate_account_disablement",
      "would_target": "demo.user@example.invalid",
      "real_action_executed": false,
      "blocked_reason": "Real remediation is disabled in V2."
    }
  ],
  "grc_controls": [
    {
      "category": "Identity and access management",
      "rationale": "Evidence involves suspicious sign-in behavior.",
      "evidence_ids": ["ev-001"]
    }
  ],
  "limitations": [
    "ThreatPrism did not access live identity provider logs beyond the submitted payload.",
    "Analyst review is required before final disposition."
  ],
  "analyst_review_required": true,
  "generated_at": "2026-05-21T18:33:19Z"
}
```

### POST /cases/{case_id}/analyst-feedback

Records analyst feedback and disagreement fields.

Example request:

```json
{
  "analyst_id": "analyst_demo_001",
  "analyst_determination": "benign",
  "analyst_severity": "low",
  "analyst_confidence": 0.78,
  "analyst_final_disposition": "close",
  "time_to_acknowledge_seconds": 420,
  "time_to_close_seconds": 1800,
  "analyst_notes": "Reviewed demo evidence and determined no further action is required.",
  "manager_review_required": true,
  "false_positive": true,
  "false_negative": false,
  "missed_ioc": false,
  "missed_mitre_mapping": false,
  "missed_escalation": true
}
```

Example response:

```json
{
  "feedback_id": "feedback_01JZ7NY3E0F46AQH69EQD5EF33",
  "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
  "recorded_at": "2026-05-21T19:02:44Z",
  "disagreement": {
    "determination_mismatch": true,
    "severity_mismatch": true,
    "disposition_mismatch": true,
    "confidence_delta": 0.06,
    "manager_review_required": true
  }
}
```

## Dashboard-Ready Routes

These routes are implemented as backend-only, demo-safe read surfaces. They do
not require a frontend dashboard or live integrations.

### GET /metrics

Returns aggregate SOC, triage, guardrail, and disagreement metrics.

Example response:

```json
{
  "window": {
    "start": "2026-05-21T00:00:00Z",
    "end": "2026-05-21T23:59:59Z"
  },
  "case_counts": {
    "total": 24,
    "by_source": {
      "generic_soar": 12,
      "sentinel": 8,
      "defender_xdr": 4
    }
  },
  "triage": {
    "queued": 1,
    "running": 0,
    "completed": 21,
    "failed": 1,
    "blocked_by_guardrail": 1
  },
  "disagreement": {
    "determination_mismatch_count": 3,
    "severity_mismatch_count": 4,
    "disposition_mismatch_count": 2,
    "manager_review_required_count": 5
  },
  "timing": {
    "average_time_to_acknowledge_seconds": 360,
    "average_time_to_close_seconds": 2400
  }
}
```

### GET /cases/{case_id}/evidence

Returns evidence records for a case.

Example response:

```json
{
  "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
  "items": [
    {
      "evidence_id": "ev-001",
      "evidence_type": "log",
      "summary": "Identity sign-in log shows unfamiliar source IP.",
      "source_uri": "demo://logs/signin/evt-001",
      "event_ids": ["evt-001"],
      "sensitivity": "demo"
    }
  ]
}
```

### GET /cases/{case_id}/timeline

Returns normalized timeline entries.

Example response:

```json
{
  "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
  "items": [
    {
      "timestamp": "2026-05-21T18:21:00Z",
      "event_type": "signin",
      "summary": "Successful sign-in from unfamiliar location.",
      "evidence_id": "ev-001"
    }
  ]
}
```

### GET /cases/{case_id}/ioc-enrichment

Returns IOC enrichment results from configured providers.

Example response when providers are not configured:

```json
{
  "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
  "items": [
    {
      "ioc_type": "ip",
      "value": "203.0.113.42",
      "provider": "abuseipdb",
      "status": "not_configured",
      "summary": "ABUSEIPDB_API_KEY is not configured.",
      "checked_at": "2026-05-21T18:33:19Z"
    }
  ]
}
```

### GET /cases/{case_id}/mitre

Returns MITRE ATT&CK mappings linked to evidence.

Example response:

```json
{
  "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
  "items": [
    {
      "tactic": "Initial Access",
      "technique": "Valid Accounts",
      "technique_id": "T1078",
      "confidence": 0.66,
      "evidence_ids": ["ev-001"],
      "review_required": true
    }
  ]
}
```

### GET /cases/{case_id}/grc-controls

Returns HITRUST-aligned GRC control category mappings.

Example response:

```json
{
  "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
  "items": [
    {
      "category": "Identity and access management",
      "rationale": "Evidence involves suspicious sign-in behavior.",
      "evidence_ids": ["ev-001"],
      "review_required": true,
      "language_note": "HITRUST-aligned category mapping only; this is not a compliance determination."
    }
  ]
}
```

### GET /cases/{case_id}/audit-events

Returns safe audit events for a case.

Example response:

```json
{
  "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
  "detail": "audit_events",
  "items": [
    {
      "audit_event_id": "audit_01JZ7P51E6TAP8G5WT3Y7WB3RF",
      "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
      "event_type": "authorization_decision",
      "actor": "demo_manager",
      "summary": "Authorization decision: allow.",
      "created_at": "2026-05-21T18:33:19Z",
      "metadata": {
        "decision": "allow",
        "reason": "role_view_allowed",
        "request_metadata_hash": "sha256:demo-redacted-request-metadata-hash"
      }
    }
  ]
}
```

## CSI/RGOI Read-Only Routes

These routes expose retrieval-governed cognition only. They do not write
memory, mutate trust, approve knowledge, publish suppressions, or execute
remediation.

All CSI routes require `tenant_id` and apply demo authorization, role/purpose
policy, retrieval-zone policy, evidence alignment, trust scoring, stale
cognition handling, and quarantine exclusion.

### GET /csi/objects

Searches visible cognitive objects.

Query parameters:

- `tenant_id`
- `query`
- `object_type`
- `retrieval_zone`
- `purpose`
- `include_stale`
- `limit`
- `role`

### GET /csi/objects/{object_id}

Returns one retrievable cognitive object with trust, evidence-alignment, and
authority-state metadata.

### GET /csi/lineage/{object_id}

Returns a visible reasoning lineage graph. Hidden cross-tenant, quarantined,
or unauthorized-zone objects are not disclosed.

### GET /csi/replay/{object_id}

Returns deterministic replay inputs and hashes for reconstruction. It does not
rerun an LLM.

### GET /csi/observability

Returns visible cognitive state metrics, stale counts, AI non-authoritative
counts, competing interpretation groups, and active controls.

### GET /csi/divergence

Returns AI-vs-human divergence telemetry for visible objects.

### POST /evals/run

Starts an evaluation run. The first implementation may support fixture or dry-run mode only.

Example request:

```json
{
  "eval_suite": "guardrails",
  "mode": "dry_run",
  "categories": [
    "prompt_injection",
    "hallucination",
    "unsafe_action_claim",
    "schema_validation",
    "evidence_grounding"
  ]
}
```

Example response:

```json
{
  "eval_run_id": "eval_01JZ7Q6AJK1TS7A6JZ8SWC7YRE",
  "status": "queued",
  "mode": "dry_run",
  "result_url": "/evals/eval_01JZ7Q6AJK1TS7A6JZ8SWC7YRE"
}
```
