# 🎓 Lesson 05: The Privacy Screen - Healthcare Safeguards And Role Views

## 🛡️ Welcome Back, Healthcare Safeguard Reviewer!

How do we avoid panic-redacting every identifier while still catching accidental regulated-data exposure? 🔍 Today we are exploring **healthcare safeguards and role views** - the "privacy screen" that detects context-aware exposure and controls display.

Goal: understand the healthcare safeguard slice and why identifiers are not automatically PHI/ePHI.

Time estimate: 60 minutes.

Prerequisites:

- Complete Lessons 00-04.
- Understand that demo data must stay fake.

## 🎯 Learning Objectives

- Explain context-aware potential PHI/ePHI detection.
- Distinguish security telemetry from healthcare exposure risk.
- Trace typed token generation.
- Describe role-view rendering behavior.
- Run healthcare safeguard tests.
- Explain how role views are enforced by demo API-key authorization.

## 🔍 What This Component Does

### ✅ Implemented Here

Primary files:

- `C:\Projects\ThreatPrismV2\src\threatprism\guardrails\healthcare.py`
- `C:\Projects\ThreatPrismV2\src\threatprism\guardrails\views.py`
- `C:\Projects\ThreatPrismV2\tests\test_healthcare_guardrails.py`
- `C:\Projects\ThreatPrismV2\docs\HEALTHCARE_SAFEGUARD_GUARDRAILS.md`

ThreatPrism assumes SOAR payloads should not contain raw PHI/ePHI, but it does not trust that assumption. It scans inbound payloads before persistence and model-visible payload creation.

### Recommended (not implemented here)

- Production privacy review workflow.
- Break-glass governance.
- False-positive tuning console.
- Central detector registry.
- Legal/privacy signoff for detector changes.

## 🧠 Real-World Analogy

The healthcare safeguard is like a privacy screen at a nurse station:

- Security staff can still see the alert they need.
- Patient-identifying details are blocked when they slip into the wrong place.
- The system records what was hidden without showing raw sensitive values.

## 🔗 Pipeline Context

```text
CaseRecord after normalization
  -> safeguard_value()
  -> typed tokens and SanitizationRecord entries
  -> safe persistence
  -> tokenized model-visible payload
  -> role-specific rendering
```

## 🎯 Key Concepts

### ✅ Implemented Here

| Concept | Meaning |
|---|---|
| Potential PHI/ePHI | Identifier tied to health, patient, care, billing, encounter, or similar context. |
| PII | Personal identifier such as SSN, phone, or street address. |
| Secret | API key, password, or credential-like value. |
| Security telemetry | IPs, URLs, emails, hashes, hosts, users used for SOC analysis. |
| Typed token | Replacement such as `[POTENTIAL_PHI:PATIENT_ID:phi_0001]`. |
| Role view | Rendering policy for roles like `analyst`, `manager_grc`, or `audit_debug`. |

### Recommended (not implemented here)

- Use detector confidence thresholds to route cases to privacy review queues.
- Keep a separate, encrypted vault for token mappings.
- Maintain a red-team corpus for healthcare exposure test cases.

## 📝 Code Walkthrough: Healthcare Rules

File: `C:\Projects\ThreatPrismV2\src\threatprism\guardrails\healthcare.py`

### Lines 14-34

```python
HEALTH_CONTEXT_TERMS = {
    "appointment",
    "billing",
    "care",
    "chart",
    "claim",
    "claims",
    "clinical",
    "diagnosis",
    "dob",
    "encounter",
    "health",
    "lab",
    "medical",
    "member",
    "mrn",
    "patient",
    "portal",
    "radiology",
    "visit",
}
```

Why: context terms prevent broad overclassification. An IP address alone is not PHI/ePHI here; an IP address in patient portal context is treated as potential PHI/ePHI exposure.

### Lines 122-171

`PHI_RULES` includes explicit healthcare identifiers:

- `mrn`
- `patient_id`
- `encounter_id`
- `member_id`
- `claim_id`
- `appointment_id`
- `dob`
- `clinical_file_path`

The `clinical_file_path` detector is intentionally path-like, so normal health-adjacent words do not trigger false positives.

### Lines 173-195

`CONTEXT_IDENTIFIER_RULES` catches email, IP, and URL only when health context is present.

This is the important correction:

```text
IP in normal endpoint telemetry -> security telemetry
IP tied to patient portal context -> possible PHI/ePHI exposure
```

## 📝 Code Walkthrough: Typed Token Vault

### Lines 53-97

```python
def token_for(
    self,
    raw_value: str,
    sensitive_class: SensitiveClass,
    detector: str,
    field_path: str,
) -> str:
    key = (sensitive_class, detector, raw_value)
    if key in self.mappings:
        return self.mappings[key]
```

Line-by-line:

1. The key deduplicates repeated raw values.
2. Tokens include the sensitive class and detector.
3. Raw values are stored only as hashes in `SanitizationRecord`.
4. `rehydration_allowed=False` for healthcare safeguard tokens.

Why: analysts can see the type of exposure without seeing the raw sensitive value.

## 📝 Code Walkthrough: Role Views

File: `C:\Projects\ThreatPrismV2\src\threatprism\guardrails\views.py`

### Lines 10-18

```python
ViewRole = Literal["ai", "analyst", "engineer", "manager_grc", "legal_privacy", "audit_debug"]

SECURITY_TELEMETRY_PATTERNS = [
    ("IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("URL", re.compile(r"https?://[^\s\"'<>]+", re.I)),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("FILE_HASH", re.compile(r"\b[a-fA-F0-9]{32,64}\b")),
]
```

### Lines 67-80

```python
def _render_text(text: str, role: ViewRole, metadata: dict[str, Any]) -> str:
    sensitive_tokens = SENSITIVE_TYPED_TOKEN_PATTERN.findall(text)
    if sensitive_tokens:
        metadata["sensitive_tokens_present"] += len(sensitive_tokens)
    if role in {"analyst", "engineer"}:
        return text
```

Line-by-line:

1. The view counts typed sensitive tokens.
2. Analyst and engineer views preserve security telemetry for response.
3. Other roles get security telemetry masked.
4. Sensitive typed tokens remain tokens; they are not rehydrated.

⚠️ Current limitation: demo API-key authorization is not a production IdP integration.

## 🧪 Manual Verification

### 🔬 Exercise 1: Security Telemetry Alone Is Not PHI

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -c "from threatprism.guardrails.healthcare import safeguard_text; t='Endpoint telemetry shows analyst@example.invalid connected from 203.0.113.42 to https://example.invalid/security-tool.'; r=safeguard_text(t, 'evidence[0].summary'); print(r.value == t); print(r.summary['token_count'])"
```

Expected output:

```text
True
0
```

### 🔬 Exercise 2: Patient Context Triggers Potential PHI Tokens

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -c "from threatprism.guardrails.healthcare import safeguard_text; r=safeguard_text('Patient portal alert for patient id PAT-44321 from 203.0.113.42 using jane.patient@example.invalid.', 'evidence[0].summary'); print(r.value); print(r.summary['token_count']); print(r.summary['privacy_legal_review_required'])"
```

Expected output:

```text
Patient portal alert for [POTENTIAL_PHI:PATIENT_ID:phi_0001] from [POTENTIAL_PHI:CONTEXT_IP:phi_0003] using [POTENTIAL_PHI:CONTEXT_EMAIL:phi_0002].
3
True
```

### 🔬 Exercise 3: Run The Healthcare Guardrail Suite

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest tests\test_healthcare_guardrails.py -q -p no:cacheprovider --basetemp .pytest_tmp_lesson05
```

Expected output:

```text
9 passed
```

### 🔬 Exercise 4: Role View Masking

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -c "from threatprism.guardrails.views import render_role_view; p={'summary':'Security telemetry contains 203.0.113.42 and [POTENTIAL_PHI:MRN:phi_0001].'}; v=render_role_view(p, 'manager_grc', case_id='case-demo'); print(v.payload['summary']); print(v.metadata['masked_security_telemetry']); print(v.metadata['sensitive_tokens_present'])"
```

Expected output:

```text
Security telemetry contains [SECURITY_TELEMETRY:IP:masked] and [POTENTIAL_PHI:MRN:phi_0001].
1
1
```

## 📚 Interview Prep

**Q: Why not classify every IP, email, URL, or username as PHI/ePHI?**  
**A**: HIPAA-style risk depends on whether health information identifies or can reasonably identify a person. ThreatPrism treats identifiers as potential PHI/ePHI when connected to patient, care, billing, encounter, or similar health context.

**Q: Why keep typed tokens instead of a generic `[REDACTED]`?**  
**A**: Typed tokens preserve investigative meaning. An analyst can tell whether the removed value was an MRN, patient ID, secret, or context IP without seeing the raw value.

**Q: Why do analyst and engineer views keep security telemetry?**  
**A**: SOC response depends on values like IPs, URLs, and hashes. Over-redacting those values would harm response workflows when they are not healthcare exposure tokens.

**Q: What is still missing?**  
**A**: Production identity-to-role enforcement. Demo API-key authorization exists, but real or shared data would still need a production IdP, governance, and deployment hardening.

## 🎯 Key Takeaways

- ThreatPrism treats inbound SOAR data as potentially contaminated.
- Identifiers become potential PHI/ePHI risk through context.
- Sensitive healthcare tokens are never rehydrated.
- Manager/GRC and audit/debug views are safer by default.
- Demo access control now protects role-aware API reads, but production access control remains future work.

## 📋 Summary Reference Card

| Item | Details |
|---|---|
| Scanner | `safeguard_value()` and `safeguard_text()` |
| Token format | `[POTENTIAL_PHI:DETECTOR:phi_0001]` |
| Secret format | `[SECRET:API_KEY:secret_0001]` |
| Role renderer | `render_role_view()` |
| Review flag | `privacy_legal_review_required` |
| Test suite | `tests/test_healthcare_guardrails.py` |

## 🚀 Ready For Lesson 06?

Next, study deterministic triage, MITRE/GRC mapping, enrichment stubs, and report rendering.

Remember: context-aware safeguard design reduces exposure without blinding the SOC. 🛡️
