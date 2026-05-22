# 08 AI Guardrails

## Guardrail Objective

ThreatPrism uses AI to assist structured triage, not to become an authority. All AI input and output must be constrained, validated, and reviewable.

For healthcare-oriented use, ThreatPrism expects SOAR payloads to be
security-only. It still treats every inbound payload as potentially
contaminated until deterministic safeguards inspect it.

ThreatPrism does not classify every identifier as PHI/ePHI by itself.
Identifiers become PHI/ePHI risk when they are connected to health context,
patient context, care context, billing context, encounter context, or other data
that can reasonably identify an individual.

## Threat Model

Case payloads can contain:

- Prompt-injection text.
- Malicious instructions embedded in logs.
- False claims from source systems.
- Sensitive data that should not be logged.
- Unsupported remediation claims.
- Ambiguous or incomplete evidence.

LLM output can contain:

- Hallucinated evidence.
- Unsupported conclusions.
- Unsafe action language.
- Schema violations.
- Overconfident severity or determination.
- Claims that actions were completed.

## Required Guardrail Layers

### 1. Deterministic Prompt Firewall

Detect and redact or quarantine instruction-like strings before model input.

Examples:

- `ignore previous instructions`
- `exfiltrate`
- `disable safety`
- `you are now`
- `system prompt`

### 2. Input Sanitization

Sanitization should:

- Preserve evidence meaning.
- Mark redacted fields.
- Avoid destroying provenance.
- Avoid logging raw sensitive values unnecessarily.

### 3. Sensitive-Value Tokenization

Before any LLM call, ThreatPrism should tokenize sensitive values that are not required in raw form for model reasoning.

Tokenization should:

- Replace sensitive values with deterministic case-local tokens.
- Preserve semantic type, such as `user`, `host`, `ip`, `domain`, `url`, `file_hash`, or `secret_like`.
- Preserve evidence provenance through `evidence_id`, `source_file`, `record_index`, and source event IDs.
- Store token mappings outside the model prompt path.
- Avoid sending raw secrets, API keys, tenant IDs, private hostnames, and unnecessary user identifiers to the LLM.
- Prefer safe documentation IP ranges and reserved domains in demo data.
- Preserve the difference between potential PHI/ePHI, PII, secrets, and
  security telemetry so SOC response does not lose useful IOCs unnecessarily.

Example tokenized input:

```json
{
  "evidence_id": "ev-001",
  "text": "Successful sign-in by user:tp_user_001 from ip:tp_ip_001.",
  "token_map_refs": ["tok_user_001", "tok_ip_001"],
  "provenance": {
    "source_file": "demo://payloads/generic_soar_case.json",
    "record_index": 0,
    "source_event_id": "source-event-001"
  }
}
```

### 4. LLM Prompt Assembly

Only sanitized and tokenized evidence summaries should enter the LLM prompt.

The prompt input should include:

- Case-safe summary fields.
- Evidence IDs.
- Tokenized entity values.
- Minimal timeline context.
- Guardrail instructions.
- Strict structured output schema.

The prompt input should not include:

- Raw source payloads.
- Raw secrets.
- Full API keys.
- Unredacted sensitive case artifacts unless explicitly allowed by a future policy.

### 5. Schema Validation

Structured output must validate against a strict schema before use.

Invalid output must not be stored as a completed report.

### 6. Semantic Prompt-Injection Classifier Interface

Define an interface for a semantic classifier. It may be rule-based, local, or LLM-backed later.

Classifier output:

```json
{
  "is_prompt_injection": true,
  "confidence": 0.91,
  "reason": "Case text attempted to override system instructions.",
  "evidence_ids": ["ev-003"]
}
```

### 7. Output Policy Scanner

Block or mark output containing:

- Claims of completed remediation.
- Instructions to execute real containment.
- Unsupported certainty.
- Missing evidence citations.
- Direct disclosure of secrets.
- HIPAA compliance, HITRUST certification, audit-ready, control satisfied, or
  similar compliance-certification claims.
- Clinical diagnosis, treatment, or patient-care recommendations.

### 8. Strict Structured Output

LLM output must be machine-validated before report rendering.

Recommended approach:

- JSON schema or Pydantic model.
- Enum validation for severity, determination, and disposition.
- Numeric validation for confidence.
- Evidence ID validation.

### 9. Evidence-Grounding Checks

Every finding, hypothesis, IOC, MITRE mapping, and GRC mapping must cite valid evidence IDs.

If evidence IDs are missing or invalid:

- Set report status to `needs_review` or `failed`.
- Record an audit event.
- Do not claim report completion.

### 10. Controlled Rehydration

Rehydration is the controlled replacement of approved tokens with display-safe values after model output has passed validation.

Rehydration may occur only after:

- Schema validation passes.
- Output policy scanning passes.
- Evidence-grounding checks pass.
- Action safety checks pass.
- The target response or report has an authorization context.

Rehydration rules:

- Rehydrate only fields needed for analyst review.
- Never rehydrate secrets, full API keys, or token-like credentials.
- Never rehydrate potential PHI/ePHI into model-visible payloads, reports,
  manager/GRC views, or audit/debug views.
- Prefer partial masking for sensitive values.
- Preserve the token in audit metadata so model-visible content remains traceable.
- Keep management and GRC views tokenized or masked unless raw values are necessary.

Example rehydrated analyst view:

```json
{
  "claim": "Successful sign-in by demo.user@example.invalid from 203.0.113.42.",
  "model_visible_claim": "Successful sign-in by user:tp_user_001 from ip:tp_ip_001.",
  "evidence_ids": ["ev-001"],
  "rehydration_policy": "analyst_view_masked"
}
```

### 11. No Autonomous Action Enforcement

Any real action request must fail closed when `ALLOW_REAL_ACTIONS=false`.

The scanner must reject language such as:

- `disabled the account`
- `isolated the endpoint`
- `blocked the IP`
- `deleted the email`
- `revoked the token`

Allowed language:

- `recommend reviewing`
- `simulate disabling`
- `dry-run plan`
- `analyst should consider`

### 12. Audit Logging

Write audit events for:

- Prompt firewall redactions.
- Sensitive-value tokenization.
- Controlled rehydration decisions.
- Classifier flags.
- Schema validation failures.
- Output policy failures.
- Evidence-grounding failures.
- Action safety blocks.

### 13. Fail-Closed Behavior

When guardrail status is uncertain, the system should:

- Avoid producing a completed report.
- Mark the triage job as `needs_review` or `blocked_by_guardrail`.
- Preserve enough diagnostic data for review without leaking sensitive content.

### 14. Healthcare Safeguard Scanner

Healthcare-oriented guardrails must detect potential accidental exposure without
panic-redacting all security identifiers.

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

Use typed replacement tokens, such as:

```text
[POTENTIAL_PHI:MRN:phi_0001]
[POTENTIAL_PII:PHONE:pii_0001]
[SECURITY_TELEMETRY:IP:ioc_0001]
[SECRET:API_KEY:secret_0001]
```

## Required Pre-LLM To Post-Validation Flow

The safe model boundary must follow this order:

```text
Raw source payload
  -> source payload hash
  -> normalize evidence and provenance
  -> deterministic prompt firewall
  -> input sanitization
  -> sensitive-value tokenization
  -> LLM prompt assembly
  -> provider-agnostic LLM call
  -> strict schema validation
  -> output policy scanner
  -> evidence-grounding checks
  -> action safety scanner
  -> controlled rehydration for authorized views
  -> deterministic report rendering
  -> audit event write
```

## Safe Triage Prompt Contract

The system prompt should require:

- Structured JSON only.
- No markdown.
- No invented evidence.
- No real action claims.
- Analyst review statement.
- Evidence IDs for every material claim.
- Tokenized entities only.

## Guardrail Acceptance Criteria

- Prompt-injection demo cases are flagged or sanitized.
- Unsafe action claims are blocked.
- Schema-invalid output is rejected.
- Reports without evidence citations are rejected.
- Missing LLM provider credentials do not crash dry-run validation.
- Audit events are written for guardrail decisions.
- Sensitive values are tokenized before model calls.
- Rehydration never occurs before validation and policy checks pass.
- Potential PHI/ePHI never appears in model-visible payloads, default reports,
  manager/GRC views, logs, or audit/debug views.
