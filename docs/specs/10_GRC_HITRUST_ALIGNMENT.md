# 10 GRC And HITRUST-Aligned Mapping

## Language Policy

ThreatPrism may use:

- HITRUST-aligned.
- HITRUST-inspired control mapping.
- GRC-ready evidence organization.
- Control category mapping.
- Evidence-to-control traceability.

ThreatPrism must not claim:

- HITRUST compliance.
- HITRUST certification.
- That ThreatPrism implements HITRUST.
- That a mapped case satisfies a control.

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
- Mappings are reviewable by analysts or GRC stakeholders.
- Mapping output includes a clear limitation statement.
