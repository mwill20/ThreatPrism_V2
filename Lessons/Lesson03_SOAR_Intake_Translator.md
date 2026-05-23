# 🎓 Lesson 03: The Translator - SOAR Intake And Normalization

## 🛡️ Welcome Back, Intake Engineer!

How does ThreatPrism accept different SOAR-shaped payloads without hardwiring one vendor? 🔍 Today we are exploring the **SOAR adapter layer** - the "translator" that turns source-specific JSON into the common case model.

Goal: understand generic and Microsoft-friendly demo intake without live SOAR credentials.

Time estimate: 35 minutes.

Prerequisites:

- Complete Lessons 00-02.
- Know basic JSON and Python dictionaries.

## 🎯 Learning Objectives

- Explain what the SOAR adapter normalizes.
- Identify all fake demo payloads.
- Run payload normalization from PowerShell.
- Understand adapter inheritance in `generic.py`.
- Describe why provider-agnostic intake matters.
- Test unsupported or malformed intake behavior.

## 🔍 What This Component Does

### ✅ Implemented Here

Primary files:

- `C:\Projects\ThreatPrismV2\src\threatprism\soar\generic.py`
- `C:\Projects\ThreatPrismV2\examples\soar_payloads\generic_soar_case.json`
- `C:\Projects\ThreatPrismV2\examples\soar_payloads\sentinel_incident.json`
- `C:\Projects\ThreatPrismV2\examples\soar_payloads\defender_xdr_alert.json`
- `C:\Projects\ThreatPrismV2\examples\soar_payloads\logic_apps_webhook_payload.json`
- `C:\Projects\ThreatPrismV2\examples\soar_payloads\swimlane_case_mock.json`
- `C:\Projects\ThreatPrismV2\tests\test_soar_adapters.py`

ThreatPrism currently uses one base adapter plus small subclasses for Sentinel, Defender XDR, Logic Apps, and Swimlane mock payloads.

### Recommended (not implemented here)

- Real provider-specific payload transforms.
- Signature validation for webhook calls.
- Schema version checks per provider.
- Dead-letter handling for unsupported payloads.
- Source-specific normalization warnings.

## 🧠 Real-World Analogy

The SOAR adapter is like an interpreter at an incident handoff meeting:

- Every tool speaks slightly different JSON.
- ThreatPrism needs one internal language.
- The adapter translates without changing the investigation facts.

## 🔗 Pipeline Context

```text
examples/soar_payloads/*.json
  -> normalize_soar_payload()
  -> CaseCreate
  -> CaseService.create_case()
```

## 📝 Code Walkthrough: Generic Adapter

File: `C:\Projects\ThreatPrismV2\src\threatprism\soar\generic.py`

### Lines 10-25

```python
class GenericSoarAdapter:
    source_name = Source.generic_soar
    accepted_sources = {"generic_soar", "generic", None}

    def can_handle(self, payload: dict[str, Any]) -> bool:
        return payload.get("source", "generic_soar") in self.accepted_sources

    def normalize(self, payload: dict[str, Any]) -> CaseCreate:
        normalized = dict(payload)
        normalized["source"] = self.source_name
        normalized.setdefault("organization_context", OrganizationContext().model_dump(mode="json"))
        normalized.setdefault("alerts", [])
        normalized.setdefault("events", [])
        normalized.setdefault("entities", [])
        normalized.setdefault("iocs", [])
        normalized.setdefault("evidence", [])
```

Line-by-line:

1. `source_name` defines the internal source enum.
2. `accepted_sources` lists source values this adapter can handle.
3. `can_handle()` chooses an adapter based on `payload["source"]`.
4. `normalize()` copies input and fills missing optional fields.
5. `CaseCreate.model_validate()` later enforces the canonical schema.

Why: adapters prevent source-specific keys from leaking into core business logic.

### Lines 27-47

```python
if not normalized["evidence"]:
    normalized["evidence"] = [
        Evidence(
            evidence_id="ev-001",
            evidence_type="case_summary",
            summary=normalized.get("description") or normalized.get("title") or "Generic SOAR case",
            source_uri=f"demo://soar/{normalized.get('source_case_id', 'unknown')}",
            excerpt=normalized.get("description"),
        ).model_dump(mode="json")
    ]
```

Why this fallback exists: demo payloads should still produce evidence-linked reports even if a minimal payload lacks an explicit evidence list.

### Lines 55-86

```python
class SentinelSoarAdapter(GenericSoarAdapter):
    source_name = Source.sentinel
    accepted_sources = {"sentinel", "microsoft_sentinel"}
```

The subclasses reuse the generic normalization rules but change source matching.

⚠️ Current shortcut: Microsoft payloads are examples, not full production Sentinel or Defender schema transformations.

## 🧪 Manual Verification

### 🔬 Exercise 1: Normalize The Generic Payload

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -c "import json; from pathlib import Path; from threatprism.soar.generic import normalize_soar_payload; c=normalize_soar_payload(json.loads(Path('examples/soar_payloads/generic_soar_case.json').read_text())); print(c.source); print(c.source_case_id); print(c.evidence[0].evidence_id); print(c.events[0].event_type)"
```

Bash:

```bash
cd /c/Projects/ThreatPrismV2
PYTHONPATH=src python -c "import json; from pathlib import Path; from threatprism.soar.generic import normalize_soar_payload; c=normalize_soar_payload(json.loads(Path('examples/soar_payloads/generic_soar_case.json').read_text())); print(c.source); print(c.source_case_id); print(c.evidence[0].evidence_id); print(c.events[0].event_type)"
```

Expected output:

```text
generic_soar
SOAR-100245
ev-001
signin
```

### 🔬 Exercise 2: Validate All Demo SOAR Fixtures

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest tests\test_soar_adapters.py -q -p no:cacheprovider --basetemp .pytest_tmp_lesson03
```

Expected output:

```text
5 passed
```

### 🔬 Exercise 3: Intentional Unsupported Source Failure

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -c "from threatprism.soar.generic import normalize_soar_payload; p={'source':'unknown_vendor','source_case_id':'X-1','title':'Demo','description':'Demo'}; exec('try:\n    normalize_soar_payload(p)\nexcept Exception as exc:\n    print(type(exc).__name__)\n    print(str(exc))')"
```

Expected output:

```text
ValueError
No SOAR adapter could normalize this payload.
```

## 📚 Interview Prep

**Q: Why use adapters for SOAR intake?**  
**A**: Adapters isolate source-specific payload differences from the core case model. That makes the service provider-agnostic and easier to extend.

**Q: Why does the generic adapter create fallback evidence?**  
**A**: Reports must cite evidence. A fallback evidence item lets even minimal demo payloads proceed through evidence-grounded validation.

**Q: What is not production-ready about this adapter layer yet?**  
**A**: The Microsoft adapters currently inherit generic behavior. Production adapters would need source-specific parsing, signature validation, schema versions, and richer normalization warnings.

## 🎯 Key Takeaways

- SOAR intake is provider-friendly but core-model-first.
- Demo payloads are fake and safe.
- `normalize_soar_payload()` returns a `CaseCreate`.
- Evidence is required for trustworthy downstream analysis.

## 📋 Summary Reference Card

| Item | Details |
|---|---|
| Main function | `normalize_soar_payload(payload)` |
| Output | `CaseCreate` |
| Supported demo sources | `generic_soar`, `sentinel`, `defender_xdr`, `logic_apps`, `swimlane_mock` |
| Failure | `ValueError` when no adapter can handle the source |
| Test | `tests/test_soar_adapters.py` |

## 🚀 Ready For Lesson 04?

Next, study the guardrail gatekeepers that make untrusted input and untrusted output safer.

Remember: normalize early so the rest of the system can reason consistently. 🛡️
