# Healthcare Safeguard Guardrails

This document summarizes the next ThreatPrism slice in plain operational terms.
The implementation-level spec is `docs/specs/15_HEALTHCARE_SAFEGUARD_GUARDRAILS.md`.

## Policy

ThreatPrism does not expect raw PHI or ePHI in SOAR payloads.

ThreatPrism still treats inbound SOAR data as potentially contaminated and
applies safeguards before persistence, model-visible payload creation, report
rendering, logging, or role-based display.

ThreatPrism does not classify every identifier as PHI/ePHI by itself.

Identifiers become PHI/ePHI risk when they are connected to health context,
patient context, care context, billing context, encounter context, or other data
that can reasonably identify an individual.

## Design Correction

Do not treat these as PHI/ePHI by default:

- IP address.
- Email.
- Username.
- URL.
- Hostname.
- File path.

Treat them as security telemetry unless they are tied to patient, care, billing,
portal, encounter, claims, or clinical context.

Examples:

- IP address in normal endpoint telemetry: security telemetry.
- IP address tied to patient portal activity: possible PHI/ePHI exposure.
- Email in analyst identity telemetry: security identity data.
- Email tied to patient, member, billing, appointment, portal, or encounter
  context: possible PHI/ePHI exposure.
- File path in a SOC alert: security telemetry.
- File path containing patient name, MRN, DOB, encounter ID, or clinical terms:
  possible PHI/ePHI exposure.

## Replacement Format

Use typed replacement tokens:

```text
[POTENTIAL_PHI:DOB:phi_0001]
[POTENTIAL_PHI:MRN:phi_0002]
[POTENTIAL_PHI:PATIENT_ID:phi_0003]
[POTENTIAL_PII:PHONE:pii_0001]
[SECURITY_TELEMETRY:IP:ioc_0001]
[SECURITY_TELEMETRY:URL:ioc_0002]
[SECRET:API_KEY:secret_0001]
```

Typed tokens preserve what analysts need to know without exposing raw sensitive
values.

## View Rules

- AI/model-visible payload: tokens only.
- Analyst: controlled security telemetry rehydration; potential PHI/ePHI stays
  redacted.
- Engineer: controlled technical rehydration for security/debug values;
  potential PHI/ePHI stays redacted.
- Manager/GRC: masked or tokenized by default.
- Legal/privacy: exposure metadata and audit trail only unless future
  break-glass governance exists.
- Audit/debug: token IDs, detector type, field path, hash, timestamp, and
  decision metadata only.

Secrets are never rehydrated.

## Compliance-Language Boundary

ThreatPrism uses healthcare safeguard language, not compliance-certification
language.

Allowed:

- HIPAA Security Rule safeguard theme.
- HITRUST-aligned category mapping.
- HITRUST-style framework category.
- Evidence alignment.
- Evidence organization.
- Requires review.
- Not a compliance determination.

Blocked:

- HIPAA compliant.
- HIPAA certified.
- HITRUST compliant.
- HITRUST certified.
- Control satisfied.
- Audit-ready.
- Certification-ready.
- Evidence proves compliance.

## Definition Of Done

- Context-aware sensitive-data scanner exists.
- Potential PHI/ePHI is detected only when identifier patterns connect to
  health, patient, care, billing, encounter, or similar context.
- Raw potential PHI/ePHI never appears in model-visible payloads, reports, logs,
  manager/GRC views, or audit/debug views.
- Security telemetry remains usable for response through role-based rendering.
- Compliance/certification claims are blocked.
- Audit events are recorded for tokenization, rehydration approval or denial,
  guardrail blocks, and report validation.
- Tests prove the above using fake fixtures only.
