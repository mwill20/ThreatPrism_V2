# 10 GRC And HITRUST-Aligned Mapping

## Language Policy

ThreatPrism may use:

- HIPAA Security Rule safeguard theme.
- HITRUST-aligned.
- HITRUST-inspired control mapping.
- HITRUST-style framework category.
- GRC-ready evidence organization.
- Control category mapping.
- Evidence-to-control traceability.
- Evidence alignment.

ThreatPrism must not claim:

- HIPAA compliance.
- HIPAA certification.
- HITRUST compliance.
- HITRUST certification.
- That ThreatPrism implements HITRUST.
- That a mapped case satisfies a control.
- That evidence is audit-ready.
- That evidence proves compliance.

ThreatPrism provides advisory, evidence-linked alignment only. Human review is
required.

## Healthcare Safeguard Framing

ThreatPrism does not classify every identifier as PHI/ePHI by itself.

Identifiers become PHI/ePHI risk when they are connected to health context,
patient context, care context, billing context, encounter context, or other data
that can reasonably identify an individual.

GRC views must default to masked or tokenized display for potential PHI/ePHI,
PII, and secrets. GRC mappings should explain risk and evidence alignment
without exposing raw regulated or sensitive values.

## Mapping Level

ThreatPrism maps to control categories only unless legally usable licensed control text is provided later.

## Initial Control Categories

- Access control.
- Audit logging.
- Incident response.
- Risk management.
- Vendor/third-party risk.
- Configuration management.
- Data protection.
- Vulnerability management.
- Change management.
- Security monitoring.
- Identity and access management.

## GRC Mapping Object

```json
{
  "category": "Identity and access management",
  "rationale": "Evidence involves suspicious sign-in behavior and account activity.",
  "evidence_ids": ["ev-001", "ev-002"],
  "confidence": 0.77,
  "review_required": true,
  "language_note": "HITRUST-aligned category mapping only; this is not a compliance determination."
}
```

## Mapping Rules

### Access Control

Map when evidence involves:

- Authorization failures.
- Privilege misuse.
- Excessive access.
- Suspicious access changes.

### Audit Logging

Map when evidence involves:

- Missing logs.
- Tampered logs.
- Audit event review.
- Logging gaps affecting triage confidence.

### Incident Response

Map when evidence involves:

- Case handling.
- Escalation.
- Response workflow.
- Containment recommendation or simulation.

### Risk Management

Map when evidence involves:

- Risk acceptance.
- High-impact uncertainty.
- Management review.
- Repeated analyst disagreement patterns.

### Vendor/Third-Party Risk

Map when evidence involves:

- External service dependencies.
- MSSP-to-internal SOC transition quality checks.
- Provider handoff evidence.

### Configuration Management

Map when evidence involves:

- Suspicious configuration changes.
- Mailbox rule creation.
- Cloud control-plane changes.
- Security setting changes.

### Data Protection

Map when evidence involves:

- Possible data exposure.
- Exfiltration indicators.
- Sensitive data movement.

### Vulnerability Management

Map when evidence involves:

- Exploit attempts.
- Vulnerable software.
- Unpatched asset indicators.

### Change Management

Map when evidence involves:

- Unauthorized changes.
- Unexpected administrative updates.
- Change-window violations.

### Security Monitoring

Map when evidence involves:

- Alerting.
- Detection coverage.
- SIEM/SOAR automation.
- Monitoring gaps.

### Identity And Access Management

Map when evidence involves:

- Sign-ins.
- Credential misuse.
- Account changes.
- MFA or conditional-access context.

## Required Docs In Later Documentation Phase

The handoff requires:

```text
docs/HITRUST_ALIGNMENT.md
docs/GRC_MAPPING.md
```

The spec pack is allowed to define the content before those top-level docs are created.

## Acceptance Criteria

- Every GRC mapping cites evidence IDs.
- No compliance or certification claims are present.
- HIPAA Security Rule references are framed as safeguard themes or evidence
  alignment only.
- Mappings are reviewable by analysts or GRC stakeholders.
- Mapping output includes a clear limitation statement.
