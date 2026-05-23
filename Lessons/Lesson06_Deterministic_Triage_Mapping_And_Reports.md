# 🎓 Lesson 06: The Demo Analyst - Deterministic Triage, Mapping, Enrichment, And Reports

## 🛡️ Welcome Back, Triage Builder!

How does ThreatPrism generate a report without calling a live LLM? 🔍 Today we are exploring the **deterministic demo provider and report layer** - the "demo analyst" that produces structured output safely and repeatably.

Goal: understand local triage generation, MITRE/GRC mapping, enrichment stubs, simulated actions, and deterministic report rendering.

Time estimate: 45 minutes.

Prerequisites:

- Complete Lessons 00-05.
- Understand basic Python classes and functions.

## 🎯 Learning Objectives

- Explain why the demo provider is deterministic.
- Trace severity and determination logic.
- Identify where MITRE and GRC mappings are created.
- Explain `not_configured` enrichment behavior.
- Render a deterministic report.
- Describe what would change for a live LLM provider.

## 🔍 What This Component Does

### ✅ Implemented Here

Primary files:

- `C:\Projects\ThreatPrismV2\src\threatprism\llm\providers.py`
- `C:\Projects\ThreatPrismV2\src\threatprism\mitre\mapping.py`
- `C:\Projects\ThreatPrismV2\src\threatprism\grc\mapping.py`
- `C:\Projects\ThreatPrismV2\src\threatprism\enrichment\stubs.py`
- `C:\Projects\ThreatPrismV2\src\threatprism\reports\render.py`
- `C:\Projects\ThreatPrismV2\src\threatprism\actions\safety.py`

### Recommended (not implemented here)

- Live provider implementations behind the `TriageProvider` protocol.
- Prompt templates with strict JSON schema output.
- Provider retry, timeout, and error taxonomy.
- Real enrichment providers with missing-key `not_configured` behavior.
- Report export formats such as HTML, PDF, and JSONL artifacts.

## 🧠 Real-World Analogy

The deterministic provider is a flight simulator:

- It behaves like the future AI triage flow.
- It avoids real external services.
- It lets tests prove the workflow before live integrations exist.

## 🔗 Pipeline Context

```text
Tokenized CaseRecord
  -> DeterministicDemoProvider.generate_report()
  -> MITRE mapping
  -> GRC category mapping
  -> simulated action
  -> report validation
  -> render_report()
```

## 📝 Code Walkthrough: Provider Interface

File: `C:\Projects\ThreatPrismV2\src\threatprism\llm\providers.py`

### Lines 20-30

```python
class TriageProvider(Protocol):
    provider_name: str

    def generate_report(self, case: CaseRecord) -> TriageReport:
        ...


class DeterministicDemoProvider:
    provider_name = "deterministic_demo"

    def generate_report(self, case: CaseRecord) -> TriageReport:
```

Line-by-line:

1. `TriageProvider` is a protocol, not a concrete vendor dependency.
2. Business logic needs `generate_report()`, not a specific SDK.
3. `DeterministicDemoProvider` implements the same interface.

Why: provider abstraction keeps OpenAI, local endpoints, or future providers out of core workflow code.

### Lines 38-48

```python
severity = _severity_from_text(combined)
determination = _determination_from_severity(severity)
disposition = Disposition.escalate if severity in {Severity.high, Severity.critical} else Disposition.monitor
evidence_ids = [item.evidence_id for item in evidence]

finding = Finding(
    title="Evidence-linked SOAR case review",
    summary="Submitted evidence requires analyst review before relying on automation closure.",
    severity=severity,
    evidence_ids=evidence_ids or ["missing-evidence"],
)
```

Why: even demo output is evidence-linked and schema-shaped. This makes downstream guardrails realistic.

## 📝 Code Walkthrough: Mapping And Actions

### MITRE mapping, `src/threatprism/mitre/mapping.py`, lines 6-31

`map_mitre()` scans evidence text and creates mappings such as:

- `T1078 Valid Accounts` for sign-in, credential, account, or mailbox terms.
- `T1059 Command and Scripting Interpreter` for PowerShell, script, or command terms.

### GRC mapping, `src/threatprism/grc/mapping.py`, lines 6-45

`map_grc_controls()` maps evidence into advisory categories:

- Identity and access management.
- Security monitoring.
- Incident response.
- Risk management fallback.

Every `GrcControl` includes `language_note` from the schema:

```text
HITRUST-aligned category mapping only; this is not a compliance determination.
```

### Simulated action, `src/threatprism/actions/safety.py`, lines 6-12

```python
def simulated_action(action: str, would_target: str | None = None) -> SimulatedAction:
    return SimulatedAction(
        action=action,
        would_target=would_target,
        real_action_executed=False,
        blocked_reason="Real remediation is disabled in V2.",
    )
```

Why: the report can show what would be recommended without doing anything real.

## 📝 Code Walkthrough: Report Rendering

File: `C:\Projects\ThreatPrismV2\src\threatprism\reports\render.py`

### Lines 6-18

```python
def render_report(report: TriageReport) -> str:
    lines = [
        "ThreatPrism Triage Report",
        f"Report ID: {report.report_id}",
        f"Case ID: {report.case_id}",
        "",
        "Summary",
        report.summary,
        "",
        f"Determination: {report.determination}",
        f"Severity: {report.severity}",
        f"Disposition: {report.disposition}",
        f"Confidence: {report.confidence:.2f}",
```

Why: deterministic rendering makes reports stable and testable.

## 🧪 Manual Verification

### 🔬 Exercise 1: Generate A Deterministic Report

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -c "import json; from pathlib import Path; from threatprism.cases.service import CaseService; from threatprism.config import Settings; s=CaseService(Settings(database_url='sqlite:///:memory:')); a=s.create_case(json.loads(Path('examples/soar_payloads/generic_soar_case.json').read_text())); s.run_triage(a.case_id); r=s.get_report(a.case_id); print(r.severity); print(r.determination); print(r.simulated_actions[0].real_action_executed); print(r.grc_controls[0].language_note.startswith('HITRUST-aligned'))"
```

Expected output:

```text
high
suspicious
False
True
```

### 🔬 Exercise 2: Inspect Enrichment Stubs

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -c "from threatprism.enrichment.stubs import PROVIDERS; print(','.join(PROVIDERS))"
```

Expected output:

```text
virustotal,urlscan,abuseipdb,whois_rdap
```

### 🔬 Exercise 3: Run Enrichment Stub Test

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest tests\test_enrichment_stubs.py -q -p no:cacheprovider --basetemp .pytest_tmp_lesson06
```

Expected output:

```text
1 passed
```

### 🔬 Exercise 4: Render Report Text

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -c "import json; from pathlib import Path; from threatprism.cases.service import CaseService; from threatprism.config import Settings; s=CaseService(Settings(database_url='sqlite:///:memory:')); a=s.create_case(json.loads(Path('examples/soar_payloads/generic_soar_case.json').read_text())); s.run_triage(a.case_id); r=s.get_report(a.case_id); print(r.rendered_report.splitlines()[0]); print(r.rendered_report.splitlines()[4])"
```

Expected output:

```text
ThreatPrism Triage Report
Summary
```

## 📚 Interview Prep

**Q: Why use a deterministic provider now?**  
**A**: It proves the workflow, schema validation, guardrails, persistence, and API behavior without live LLM calls or credentials. That keeps the project demo-safe and testable.

**Q: How does the provider remain replaceable?**  
**A**: Business logic depends on the `TriageProvider` protocol. A live provider can implement `generate_report()` without changing the service orchestration.

**Q: Why are GRC mappings category-level only?**  
**A**: ThreatPrism organizes evidence for review. It does not claim compliance, certification, or control satisfaction.

**Q: Why render reports deterministically?**  
**A**: Stable rendering is easier to test, diff, and audit than free-form provider text.

## 🎯 Key Takeaways

- The demo provider is a safe stand-in for future AI.
- MITRE and GRC mapping are evidence-linked and advisory.
- Enrichment providers are currently stubs that return `not_configured`.
- Simulated actions never execute real remediation.
- Report rendering is deterministic.

## 📋 Summary Reference Card

| Component | Function |
|---|---|
| `TriageProvider` | Provider interface. |
| `DeterministicDemoProvider` | Local deterministic report generator. |
| `map_mitre()` | Rule-based MITRE mapping. |
| `map_grc_controls()` | Advisory GRC category mapping. |
| `not_configured_enrichment()` | Demo-safe enrichment placeholder. |
| `render_report()` | Deterministic text report rendering. |
| `simulated_action()` | Safe simulated action builder. |

## 🚀 Ready For Lesson 07?

Next, study SQLite persistence, configuration, and generated identifiers.

Remember: deterministic demos let you harden the pipeline before adding live providers. 🛡️
