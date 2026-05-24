# 05 Data Model

## Model Principles

- Normalize provider-specific payloads into a stable ThreatPrism `Case`.
- Preserve evidence provenance from V1-style event envelopes where possible.
- Store enough structured fields for API, metrics, reporting, and future dashboard use.
- Keep demo persistence SQLite-compatible while avoiding designs that block PostgreSQL later.
- Treat raw source payloads as sensitive; store hashes and redacted references by default.

## Identifier Conventions

Recommended identifiers:

- `case_id`: `case_` prefix plus ULID or UUID-derived value.
- `triage_job_id`: `triage_` prefix.
- `report_id`: `report_` prefix.
- `feedback_id`: `feedback_` prefix.
- `evidence_id`: stable case-local ID such as `ev-001`.

## Core Case Model

```json
{
  "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
  "source": "generic_soar",
  "source_case_id": "SOAR-100245",
  "source_payload_hash": "sha256:demo-redacted-source-payload-hash",
  "source_metadata": {
    "source_status": "closed_by_automation",
    "source_severity": "medium"
  },
  "organization_context": {
    "environment": "demo",
    "business_unit": "internal_soc",
    "sensitivity": "demo"
  },
  "title": "Suspicious sign-in followed by mailbox rule creation",
  "description": "Demo case requiring post-automation quality review.",
  "created_at": "2026-05-21T18:30:00Z",
  "updated_at": "2026-05-21T18:33:19Z",
  "status": "triage_completed",
  "alerts": [],
  "events": [],
  "entities": [],
  "iocs": [],
  "evidence": [],
  "timeline": [],
  "hypotheses": [],
  "mitre_mappings": [],
  "threat_intelligence_enrichment": [],
  "recommended_actions": [],
  "simulated_actions": [],
  "grc_controls": [],
  "analyst_feedback": [],
  "triage_report": null,
  "audit_trail": []
}
```

## Case Fields

### `source`

Allowed initial values:

- `generic_soar`
- `sentinel`
- `defender_xdr`
- `logic_apps`
- `swimlane_mock`
- `windows_jsonl`
- `aws_cloudtrail`
- `gcp_audit`

The final three values preserve V1 data-source compatibility.

### `source_payload_hash`

Hash of the original source payload. Store this for traceability and deduplication without exposing raw payload content by default.

Recommended format:

```text
sha256:<hex digest>
```

### `source_metadata`

Provider-specific status, severity, closure, and routing metadata that should not become core model fields.

Example:

```json
{
  "source_status": "closed_by_automation",
  "source_severity": "medium",
  "source_queue": "demo_soc_queue",
  "automation_result": "no_high_risk_signal"
}
```

### `organization_context`

Demo-safe context about the internal SOC environment.

Do not include real employer, customer, tenant, or workplace names.

Example:

```json
{
  "environment": "demo",
  "business_unit": "internal_soc",
  "sensitivity": "demo",
  "operating_model": "mssp_to_internal_soc_transition"
}
```

## Event Model

```json
{
  "event_id": "evt-001",
  "timestamp": "2026-05-21T18:21:00Z",
  "event_type": "signin",
  "source": "identity_provider",
  "description": "Successful sign-in from unfamiliar location.",
  "normalized": {
    "actor": "demo.user@example.invalid",
    "target": "demo.user@example.invalid",
    "source_ip": "203.0.113.42"
  },
  "provenance": {
    "source_file": "demo://payloads/generic_soar_case.json",
    "record_index": 0,
    "source_event_id": "source-event-001"
  },
  "raw_reference": "demo://events/evt-001"
}
```

V1 compatibility requirement: preserve `source_file`, `record_index`, and optional `event_id` style provenance when source logs provide it.

## Evidence Model

```json
{
  "evidence_id": "ev-001",
  "evidence_type": "log",
  "summary": "Identity sign-in log shows unfamiliar source IP.",
  "source_uri": "demo://logs/signin/evt-001",
  "event_ids": ["evt-001"],
  "excerpt": "Successful sign-in from 203.0.113.42",
  "sensitivity": "demo",
  "created_at": "2026-05-21T18:31:03Z"
}
```

Every finding, hypothesis, MITRE mapping, and GRC mapping must be able to reference one or more `evidence_id` values.

## Sanitization And Tokenization Record

ThreatPrism should preserve a record of what was sanitized or tokenized without exposing sensitive raw values to the LLM.

Example:

```json
{
  "record_id": "sanitize_01JZ8A1Y1HWFAGFE9WTH8KQ7JB",
  "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
  "evidence_id": "ev-001",
  "operation": "tokenize",
  "field_path": "events[0].normalized.actor",
  "token": "tp_user_001",
  "token_type": "user",
  "raw_value_hash": "sha256:demo-redacted-actor-hash",
  "rehydration_allowed": true,
  "created_at": "2026-05-21T18:31:03Z"
}
```

Rules:

- Store raw value hashes for traceability.
- Store raw values only in a future protected secret store or encrypted local demo store if explicitly needed.
- Do not send token maps to the LLM.
- Keep token mappings case-scoped by default.
- Rehydrate only after output validation and authorization checks.

## IOC Model

```json
{
  "ioc_id": "ioc-001",
  "ioc_type": "ip",
  "value": "203.0.113.42",
  "source": "alert",
  "first_seen": "2026-05-21T18:21:00Z",
  "confidence": 0.7,
  "evidence_ids": ["ev-001"]
}
```

Allowed initial `ioc_type` values:

- `ip`
- `domain`
- `url`
- `file_hash`
- `email`
- `user`
- `host`
- `process`

## Triage Job Model

```json
{
  "triage_job_id": "triage_01JZ7NQ2VBE3D9HB4C2M9P3VMF",
  "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
  "status": "completed",
  "queued_at": "2026-05-21T18:31:03Z",
  "started_at": "2026-05-21T18:31:10Z",
  "completed_at": "2026-05-21T18:33:19Z",
  "provider": "openai",
  "model": "configured-model",
  "error": null
}
```

Allowed statuses:

- `queued`
- `running`
- `completed`
- `failed`
- `blocked_by_guardrail`
- `needs_review`

## Triage Report Schema

```json
{
  "report_id": "report_01JZ7NSCBXY5K48FEJRBHX8WHR",
  "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
  "report_version": 1,
  "summary": "Evidence suggests suspicious identity activity that needs analyst review before closure.",
  "determination": "suspicious",
  "severity": "high",
  "disposition": "escalate",
  "confidence": 0.84,
  "findings": [
    {
      "finding_id": "finding-001",
      "title": "Unfamiliar sign-in pattern",
      "summary": "A successful sign-in from an unfamiliar IP occurred before suspicious mailbox activity.",
      "severity": "high",
      "evidence_ids": ["ev-001"]
    }
  ],
  "evidence": [],
  "timeline": [],
  "iocs": [],
  "mitre_mappings": [],
  "hypotheses": [],
  "recommended_actions": [],
  "simulated_actions": [],
  "grc_controls": [],
  "limitations": [],
  "analyst_review_required": true,
  "schema_version": "triage-report/0.1",
  "generated_at": "2026-05-21T18:33:19Z"
}
```

## Analyst Feedback Model

```json
{
  "feedback_id": "feedback_01JZ7NY3E0F46AQH69EQD5EF33",
  "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
  "report_id": "report_01JZ7NSCBXY5K48FEJRBHX8WHR",
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
  "missed_escalation": true,
  "created_at": "2026-05-21T19:02:44Z"
}
```

## Disagreement Model

```json
{
  "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
  "feedback_id": "feedback_01JZ7NY3E0F46AQH69EQD5EF33",
  "determination_mismatch": true,
  "severity_mismatch": true,
  "disposition_mismatch": true,
  "confidence_delta": 0.06,
  "manager_review_required": true,
  "reasons": [
    "ThreatPrism recommended escalation while analyst selected close.",
    "ThreatPrism severity was high while analyst severity was low."
  ]
}
```

## Recommended Tables

Initial SQLite tables should map cleanly to PostgreSQL later:

- `cases`
- `case_source_payloads`
- `case_sanitization_records`
- `case_alerts`
- `case_events`
- `case_entities`
- `case_iocs`
- `case_evidence`
- `triage_jobs`
- `triage_reports`
- `analyst_feedback`
- `disagreement_records`
- `audit_events`
- `enrichment_results`
- `simulated_actions`

### `case_source_payloads`

This table should store payload traceability fields separately from normalized case fields.

Recommended fields:

- `case_id`
- `source`
- `source_case_id`
- `source_payload_hash`
- `redacted_payload_json`, optional for demo and debugging only
- `received_at`
- `normalization_warnings_json`

Raw unredacted payload storage should be disabled by default.

### `case_sanitization_records`

This table should store sanitization, tokenization, and rehydration metadata.

Recommended fields:

- `record_id`
- `case_id`
- `evidence_id`
- `operation`
- `field_path`
- `token`
- `token_type`
- `raw_value_hash`
- `rehydration_allowed`
- `created_at`
- `metadata_json`

## Audit Event Model

```json
{
  "audit_event_id": "audit_01JZ7P51E6TAP8G5WT3Y7WB3RF",
  "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
  "event_type": "triage_report_validated",
  "actor": "system",
  "summary": "Triage report passed schema and policy validation.",
  "created_at": "2026-05-21T18:33:19Z",
  "metadata": {
    "report_id": "report_01JZ7NSCBXY5K48FEJRBHX8WHR",
    "schema_version": "triage-report/0.1"
  }
}
```

## Operational Read Models

Operational read models are API response models, not new source-of-truth case
records.

Implemented Pydantic read models live in:

```text
src/threatprism/cases/read_models.py
```

The case-list read-model item includes:

- Case identity and source fields.
- Case and triage status.
- Triage determination, severity, disposition, and confidence.
- Manager-review flag.
- Healthcare-review flag.
- Guardrail-blocked flag.
- Authorization-denied flag.
- Created and updated timestamps.

The operational metrics model includes:

- Case counts.
- Triage counts.
- Report decision counts.
- Guardrail and healthcare safeguard counts.
- Authorization allow/deny counts.
- Disagreement and timing metrics.
- GRC mapping metrics.

Read models must remain safe derived views. They must not expose raw potential
PHI/ePHI, secrets, full credentials, raw source payload bodies, or token vault
mappings.

## Eval Result Models

Eval models are local regression artifacts, not production telemetry records.

Implemented Pydantic eval models live in:

```text
src/threatprism/evals/schemas.py
```

The eval result model includes:

- `run_id`.
- `fixture_id`.
- `category`.
- `passed`.
- `failure_reason`.
- `safe_sanitized_preview`.
- `artifact_path`.

Eval artifacts must store sanitized previews only. They must not store raw
potential PHI/ePHI, secrets, credentials, raw payload bodies, or token vault
mappings.
