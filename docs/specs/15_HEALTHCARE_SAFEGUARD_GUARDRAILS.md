# 15 Healthcare Safeguard And Evidence Alignment Guardrails

## Slice Name

Healthcare Safeguard & Evidence Alignment Guardrails v0.1

## Purpose

This slice hardens ThreatPrism for an internal healthcare SOC posture without
claiming HIPAA compliance, HITRUST certification, or audit readiness.

ThreatPrism does not expect raw PHI or ePHI in SOAR payloads. However,
ThreatPrism must treat every inbound payload as potentially contaminated until
deterministic safeguards inspect it.

## Core Policy

ThreatPrism does not classify every identifier as PHI or ePHI by itself.

ThreatPrism treats inbound SOAR data as potentially contaminated and applies
safeguards to prevent accidental exposure of identifiable health information.

Identifiers become PHI/ePHI risk when they are connected to health context,
patient context, care context, billing context, encounter context, or other data
that can reasonably identify an individual.

ThreatPrism uses healthcare safeguard language, not compliance-certification
language.

ThreatPrism may support evidence alignment to HIPAA Security Rule safeguard
themes and HITRUST-style framework categories, but it must not claim:

- A control is satisfied.
- The system is HIPAA compliant.
- The system is HITRUST certified.
- Evidence is audit-ready.
- A mapped case proves compliance.

All mappings are advisory, evidence-linked, and require human review.

## Official Reference Boundaries

Use official sources only for regulatory framing:

- HHS HIPAA Security Rule: https://www.hhs.gov/hipaa/for-professionals/security/index.html
- HHS de-identification guidance: https://www.hhs.gov/hipaa/for-professionals/special-topics/de-identification/index.html
- HITRUST overview and MyCSF materials: https://hitrustalliance.net/overview and https://hitrustalliance.net/mycsf

Do not quote or embed proprietary HITRUST control text unless the user provides
licensed material and explicitly authorizes its use.

## Data Classification Model

### Potential PHI/ePHI

Examples:

- Medical record numbers.
- Patient identifiers.
- Encounter identifiers.
- Health plan or member identifiers.
- Appointment identifiers.
- DOB or date-of-service values tied to patient or care context.
- Clinical note fragments.
- File paths containing patient names, MRNs, DOBs, encounter IDs, or clinical terms.
- Email, username, IP, URL, or hostname tied to patient portal, appointment,
  billing, encounter, claims, or clinical context.

Default handling:

- Replace with typed token.
- Do not rehydrate into model-visible payloads.
- Do not display raw values in reports, manager/GRC views, or audit/debug views.
- Add exposure metadata and privacy/legal review flag for high-confidence hits.

### PII And Sensitive Identifiers

Examples:

- Phone numbers.
- Street addresses.
- Personal email addresses.
- Social Security numbers.
- Driver license or government identifier patterns.
- Account or insurance-like identifiers without enough context to classify as
  PHI/ePHI.

Default handling:

- Tokenize or mask by role.
- Never send raw values to model-visible payloads unless a future approved
  governance policy exists.
- Record detector type, field path, token ID, hash, and confidence.

### Security Telemetry

Examples:

- IP addresses.
- URLs.
- Domains.
- Hostnames.
- Usernames.
- Corporate email addresses used as analyst or workforce identities.
- File paths that do not include patient/care/billing context.
- File hashes.
- Process names.

Default handling:

- Preserve enough detail for SOC response.
- Tokenize before model processing.
- Allow controlled rehydration for analyst and engineer views when needed for
  response.
- Keep manager/GRC views masked or tokenized by default.

### Secrets

Examples:

- API keys.
- OAuth tokens.
- Passwords.
- Private keys.
- Session tokens.

Default handling:

- Tokenize immediately.
- Never rehydrate.
- Add urgent audit event.
- Block any report or view that attempts to disclose the raw value.

## Typed Replacement Format

Use typed replacement tokens instead of a generic marker:

```text
[POTENTIAL_PHI:DOB:phi_0001]
[POTENTIAL_PHI:MRN:phi_0002]
[POTENTIAL_PHI:PATIENT_ID:phi_0003]
[POTENTIAL_PII:PHONE:pii_0001]
[SECURITY_TELEMETRY:IP:ioc_0001]
[SECURITY_TELEMETRY:URL:ioc_0002]
[SECRET:API_KEY:secret_0001]
```

The token must preserve:

- Class.
- Detector type.
- Case-local token ID.
- Field path.
- Evidence ID when available.
- Hash of the raw value.
- Confidence.
- Whether rehydration is allowed for each role.

## Context-Aware Examples

Do not blindly classify every identifier as PHI/ePHI.

Examples:

- IP address in normal endpoint telemetry: security telemetry.
- IP address tied to patient portal activity or clinical context: possible
  PHI/ePHI exposure.
- Email in analyst identity telemetry: security identity data.
- Email tied to patient, member, billing, appointment, portal, or encounter
  context: possible PHI/ePHI exposure.
- File path in a SOC alert: security telemetry.
- File path containing patient name, MRN, DOB, encounter ID, or clinical terms:
  possible PHI/ePHI exposure.

## Processing Flow

```text
Raw inbound payload
  -> request body capture without raw logging
  -> pre-persistence sensitive-data scanner
  -> typed tokenization and exposure metadata
  -> sanitized canonical case
  -> model-visible payload with tokens only
  -> provider-agnostic model call or deterministic demo provider
  -> schema validation
  -> output policy and compliance-language scan
  -> evidence-grounding checks
  -> action-safety checks
  -> role-based rendering
  -> audit event write
```

## Role-Based Display Policy

### AI / Model-Visible Payload

- Tokens only.
- No raw PHI/ePHI.
- No raw secrets.
- Security telemetry may remain tokenized with semantic type.

### Analyst

- Controlled rehydration for security telemetry needed for response.
- Potential PHI/ePHI remains redacted unless future break-glass governance
  exists.
- Secrets are never rehydrated.

### Engineer

- Controlled technical rehydration for debugging and detection engineering.
- Potential PHI/ePHI remains redacted.
- Secrets are never rehydrated.

### Manager / GRC

- Masked or tokenized by default.
- No raw PHI/ePHI.
- No raw secrets.
- Evidence alignment, risk, trend, and review status only.

### Legal / Privacy

- Exposure metadata and audit trail.
- Detector class, field path, token ID, hash, confidence, timestamp, and review
  status.
- Raw values only under a future explicit break-glass governance policy.

### Audit / Debug

- No raw PHI/ePHI.
- No raw secrets.
- Token IDs, detector type, field path, hash, timestamp, and decision metadata
  only.

## Handling Rules

### Low-Confidence Potential Exposure

- Tokenize.
- Continue processing with sanitized payload.
- Add audit event.
- Mark review as recommended.

### High-Confidence Potential PHI/ePHI Exposure

- Tokenize.
- Continue only with sanitized payload.
- Add `potential_sensitive_data_exposure=true`.
- Require privacy/legal review.
- Do not expose raw values in reports or non-break-glass views.

### Secret Exposure

- Tokenize.
- Never rehydrate.
- Add urgent audit event.
- Block any output that includes the raw secret.

## Compliance-Language Scanner

Block output language that claims or implies:

- HIPAA compliant.
- HIPAA certified.
- HITRUST certified.
- HITRUST compliant.
- Control satisfied.
- Audit-ready.
- Certification-ready.
- Evidence proves compliance.
- Case satisfies a control.

Allowed language:

- HIPAA Security Rule safeguard theme.
- HITRUST-aligned category mapping.
- HITRUST-style framework category.
- Evidence alignment.
- Evidence organization.
- Requires review.
- Not a compliance determination.

## Required Audit Events

Record audit events for:

- Potential PHI/ePHI detection.
- PII or sensitive identifier tokenization.
- Secret detection.
- Security telemetry tokenization.
- Rehydration approval.
- Rehydration denial.
- Compliance-language block.
- Guardrail block.
- Report validation.
- Role-based view rendering policy applied.

Audit events must not contain raw PHI/ePHI or raw secrets.

## Required Tests

- Potential PHI/ePHI is tokenized with typed replacement.
- Identifier-only security telemetry is not mislabeled as PHI/ePHI.
- Identifier plus patient/care/billing/encounter context is treated as possible
  PHI/ePHI exposure.
- Raw PHI/ePHI does not appear in model-visible payloads.
- Raw PHI/ePHI does not appear in reports.
- Raw PHI/ePHI does not appear in manager/GRC views.
- Secrets are never rehydrated.
- Compliance/certification claims are blocked.
- GRC mappings cite evidence IDs.
- Audit events are recorded for tokenization, rehydration denial, guardrail
  blocks, and report validation.

## Out Of Scope For v0.1

- Live LLM calls.
- Live SOAR calls.
- Real PHI/ePHI fixtures.
- Production credentials.
- Break-glass raw access implementation.
- Formal compliance assessment.
- HITRUST certification workflow.
- HIPAA legal opinion.
- Dashboard UI.
