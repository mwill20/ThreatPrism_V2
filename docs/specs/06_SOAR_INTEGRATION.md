# 06 SOAR Integration

## Goal

ThreatPrism must ingest SOAR-managed cases without depending on one SOAR vendor and without slowing down incident response.

## Integration Principles

- Provider-specific adapters convert payloads into the core `Case` model.
- The API returns quickly with a tracking ID.
- Triage processing is asynchronous.
- SOAR workflows continue even if ThreatPrism fails.
- Demo mode requires no live credentials.
- Demo payloads must be fake.

## Required Demo Payloads

Create these in a later implementation phase:

```text
examples/soar_payloads/
  generic_soar_case.json
  sentinel_incident.json
  defender_xdr_alert.json
  logic_apps_webhook_payload.json
  swimlane_case_mock.json
```

## Adapter Interface

Future implementation should expose an interface equivalent to:

```python
class SoarAdapter:
    source_name: str

    def can_handle(self, payload: dict) -> bool:
        ...

    def normalize(self, payload: dict) -> CaseCreate:
        ...
```

Adapters must return normalized data and warnings.

Example warning:

```json
{
  "code": "missing_source_severity",
  "message": "Source payload did not include severity. Defaulted to medium for review.",
  "field": "severity"
}
```

## Generic Webhook Adapter

Required input fields:

- `source_case_id`
- `title`
- `description`
- `created_at`

Optional input fields:

- `alerts`
- `events`
- `entities`
- `iocs`
- `evidence`
- `source_status`
- `soar_closure_reason`
- `automation_actions`

Example payload:

```json
{
  "source": "generic_soar",
  "source_case_id": "SOAR-100245",
  "title": "Suspicious sign-in followed by mailbox rule creation",
  "description": "Automated closure candidate for quality review.",
  "created_at": "2026-05-21T18:30:00Z",
  "source_status": "closed_by_automation",
  "soar_closure_reason": "Automated checks did not find confirmed compromise.",
  "automation_actions": [
    {
      "name": "identity_risk_check",
      "status": "completed",
      "result": "no_high_risk_signal"
    }
  ]
}
```

## Microsoft Sentinel / Logic Apps Style Adapter

The adapter must support payloads shaped like incident, alert, or workflow webhook bodies.

Fields to map when present:

- Incident ID to `source_case_id`.
- Incident title to `title`.
- Description to `description`.
- Severity to source severity metadata.
- Status to source status metadata.
- Entities to `entities`.
- Alerts to `alerts`.
- Tactics and techniques to initial `mitre_mappings`.
- Related events to `events`.

## Defender XDR Style Adapter

Fields to map when present:

- Incident or alert ID to `source_case_id`.
- Detection source to `source`.
- Evidence objects to `evidence`.
- User, device, mailbox, URL, IP, and file details to `entities` and `iocs`.
- Recommended actions to `recommended_actions`, never executed actions.

## Swimlane Mock Adapter

This is demo-only and must not require live credentials.

Use it to demonstrate provider-agnostic mapping from another SOAR case shape.

## Intake API Behavior

On valid payload:

```json
{
  "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
  "tracking_id": "triage_01JZ7NQ2VBE3D9HB4C2M9P3VMF",
  "triage_status": "queued"
}
```

On unsupported payload:

```json
{
  "error": {
    "code": "unsupported_payload",
    "message": "No SOAR adapter could normalize this payload.",
    "details": []
  }
}
```

## Callback Support

Callbacks are optional for a later phase.

If implemented, callbacks must:

- Be opt-in.
- Use configured destination allowlists.
- Redact sensitive values.
- Include report status and report URL, not full raw evidence by default.
- Fail safely without changing case status to failed unless explicitly configured.

## Failure Handling

- If normalization fails, return `400` with structured validation errors.
- If triage enqueue fails, store the case with `triage_status: failed` and return `202` only if the case was accepted.
- If async triage fails, update the triage job to `failed` and write an audit event.
- SOAR must not be required to retry to keep incident response moving.
