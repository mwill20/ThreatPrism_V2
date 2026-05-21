# 01 Product Requirements

## Scope

This document defines implementation-ready requirements for the ThreatPrism specification phase. It does not authorize application-code implementation.

## Product Statement

ThreatPrism is a production-style, demo-safe SOC migration accelerator for organizations moving from outsourced MSSP-managed SOC operations to an internal SOC model.

## Functional Requirements

### PR-001 Case Intake

ThreatPrism must accept cases from provider-agnostic inputs.

Required intake paths:

- Generic SOAR webhook payload.
- Microsoft Sentinel-style incident payload.
- Defender XDR-style alert or incident payload.
- Logic Apps or Power Automate-style webhook payload.
- Mock case payload from another SOAR platform.

Acceptance:

- Demo payloads exist under `examples/soar_payloads/`.
- Each payload can be normalized into the core `Case` model.
- Missing optional fields do not crash normalization.

### PR-002 Core Case Record

ThreatPrism must represent each imported item as a case with:

- `case_id`
- `source`
- `source_case_id`
- `organization_context`
- `title`
- `description`
- `created_at`
- `updated_at`
- `status`
- `alerts`
- `events`
- `entities`
- `iocs`
- `evidence`
- `timeline`
- `hypotheses`
- `mitre_mappings`
- `threat_intelligence_enrichment`
- `recommended_actions`
- `simulated_actions`
- `grc_controls`
- `analyst_feedback`
- `triage_report`
- `audit_trail`

### PR-003 Structured Triage Report

Every triage report must include:

- Summary.
- Determination: `benign`, `suspicious`, `malicious`, or `critical`.
- Severity: `low`, `medium`, `high`, or `critical`.
- Disposition: `close`, `monitor`, `escalate`, or `needs_more_info`.
- Confidence as a number from `0.0` through `1.0`.
- Evidence citations.
- Timeline.
- IOCs.
- MITRE ATT&CK mapping.
- Hypotheses.
- Recommended analyst actions.
- Simulated response actions where applicable.
- GRC/HITRUST-aligned control categories.
- Limitations.
- Analyst review required statement.

### PR-004 Analyst Feedback

ThreatPrism must capture analyst feedback through:

`POST /cases/{case_id}/analyst-feedback`

Required fields:

- `analyst_determination`
- `analyst_severity`
- `analyst_confidence`
- `analyst_final_disposition`
- `time_to_acknowledge_seconds`
- `time_to_close_seconds`
- `analyst_notes`
- `manager_review_required`
- `false_positive`
- `false_negative`
- `missed_ioc`
- `missed_mitre_mapping`
- `missed_escalation`

The system must calculate and store disagreement indicators comparing ThreatPrism output to analyst feedback.

### PR-005 SOAR Safety

ThreatPrism must not block SOAR workflows.

In parallel SOAR mode:

- The SOAR sends a payload.
- ThreatPrism validates and stores a case.
- ThreatPrism immediately returns a tracking ID and status.
- Triage runs asynchronously.
- SOAR continues even if ThreatPrism is slow, fails, or times out.

### PR-006 AI Provider Abstraction

ThreatPrism must expose a provider-agnostic LLM interface.

Default provider: OpenAI.

Optional provider: OpenAI-compatible local endpoint or Ollama-compatible provider.

Business logic must not directly depend on one provider SDK.

### PR-007 Guardrails

ThreatPrism must implement or preserve:

- Deterministic prompt firewall.
- Input sanitization.
- Schema validation.
- Semantic prompt-injection classifier interface.
- Output policy scanner.
- Strict structured output.
- Evidence-grounding checks.
- No autonomous action enforcement.
- Audit logging.
- Fail-closed behavior where possible.

### PR-008 Action Safety

ThreatPrism must recommend and simulate actions only.

Required default:

```text
ALLOW_REAL_ACTIONS=false
```

Blocked actions in this version:

- Real endpoint isolation.
- Real account disablement.
- Real firewall blocking.
- Real email deletion.
- Real token revocation.
- Any production-impacting remediation or containment.

### PR-009 Threat Intelligence Stubs

ThreatPrism must define enrichment interfaces for:

- VirusTotal.
- URLScan.io.
- AbuseIPDB.
- WHOIS/RDAP.

Missing API keys must return structured `not_configured` results.

### PR-010 GRC Mapping

ThreatPrism must map evidence and findings to HITRUST-aligned control categories only.

The product must not claim:

- HITRUST compliance.
- HITRUST certification.
- That ThreatPrism implements HITRUST.

### PR-011 Dashboard-Ready API

ThreatPrism must be designed as:

`CLI + API service + dashboard-ready backend`

The first implementation should build the core API routes before any full frontend dashboard.

## Nonfunctional Requirements

### Security

- Never log raw secrets.
- Never log full API keys.
- Never store real customer data in demo payloads.
- Treat all case content as untrusted.
- Treat AI output as untrusted until validated.

### Reliability

- Failed AI generation must produce an explicit failed triage job state.
- Failed enrichment provider calls must not fail the whole case.
- SOAR webhook intake must return quickly.

### Auditability

- Every triage report must include evidence references.
- Analyst feedback must be tied to a case and report version.
- Guardrail failures must be captured in audit events.

### Portability

- Demo mode uses SQLite.
- Persistence should be PostgreSQL-ready.
- Configuration should use environment variables.
- Docker Compose should support local demo execution in a later phase.

## Out Of Scope

- Multi-org MSSP tenancy.
- Production enforcement actions.
- Full frontend dashboard.
- Live SOAR credentials for demos.
- Licensed HITRUST control mapping unless legally available.
