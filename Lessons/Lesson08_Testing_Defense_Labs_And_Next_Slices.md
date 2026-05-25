# 🎓 Lesson 08: The Practice Range - Testing, Defense Labs, And Next Slices

## 🛡️ Welcome Back, Test And Eval Engineer!

How do you prove ThreatPrism is behaving safely before adding live integrations? 🔍 Today we are exploring the **test suite and defense labs** - the "practice range" where we validate workflows, edge cases, and unsafe output handling.

Goal: learn how to run, interpret, and extend the current tests, then understand the next build slice.

Time estimate: 45 minutes.

Prerequisites:

- Complete Lessons 00-07.
- Be comfortable running `pytest`.

## 🎯 Learning Objectives

- Run the full safe validation command.
- Identify which tests cover which subsystem.
- Explain prompt-injection and guardrail failure labs.
- Understand healthcare leakage tests.
- Describe current test gaps.
- Understand the implemented eval harness, safe validation wrapper, and fake-data-only CI path.

## 🔍 What This Component Does

### ✅ Implemented Here

Primary files:

- `C:\Projects\ThreatPrismV2\tests\test_api_flow.py`
- `C:\Projects\ThreatPrismV2\tests\test_soar_adapters.py`
- `C:\Projects\ThreatPrismV2\tests\test_guardrails.py`
- `C:\Projects\ThreatPrismV2\tests\test_guardrail_failures.py`
- `C:\Projects\ThreatPrismV2\tests\test_healthcare_guardrails.py`
- `C:\Projects\ThreatPrismV2\tests\test_enrichment_stubs.py`
- `C:\Projects\ThreatPrismV2\tests\test_access_control.py`
- `C:\Projects\ThreatPrismV2\tests\test_operational_read_models.py`
- `C:\Projects\ThreatPrismV2\tests\test_eval_harness.py`
- `C:\Projects\ThreatPrismV2\tests\evals\regression_cases.jsonl`
- `C:\Projects\ThreatPrismV2\docs\specs\17_ACCESS_CONTROL_AND_AUDIT_INTEGRITY.md`
- `C:\Projects\ThreatPrismV2\docs\specs\16_OPERATIONAL_READ_MODELS_AND_METRICS.md`

Current validated result:

```text
66 passed
```

### Recommended (not implemented here)

- Dedicated eval datasets under `tests/evals/`.
- CI workflow.
- Coverage reporting.
- Mutation testing for guardrails.
- Snapshot tests for rendered reports.
- Contract tests for future API response envelopes.

## 🧠 Real-World Analogy

The test suite is the SOC exercise range:

- Normal tests prove routine flow.
- Guardrail tests prove unsafe content is blocked.
- Healthcare tests prove sensitive values do not leak.
- Access-control tests prove users cannot force safer roles into unsafe views.
- Operational read-model tests prove dashboard-ready APIs stay safe.

## 🔗 Pipeline Context

```text
Fixture payloads
  -> unit tests
  -> service tests
  -> API flow tests
  -> guardrail failure tests
  -> healthcare leakage tests
```

## 📝 Test Walkthrough: API Flow

File: `C:\Projects\ThreatPrismV2\tests\test_api_flow.py`

### Lines 12-21

```python
def _client(tmp_path: Path) -> TestClient:
    app = create_app(
        Settings(
            env="test",
            database_url="sqlite:///:memory:",
            llm_provider="deterministic_demo",
            allow_real_actions=False,
        )
    )
    return TestClient(app)
```

Why: tests isolate the API with in-memory SQLite and safe settings.

### Lines 31-73

`test_generic_soar_case_flow_and_feedback()` proves:

- Case creation returns `202`.
- Triage completes.
- Severity is `high`.
- Simulated actions do not execute real actions.
- HITRUST language is alignment-only.
- Analyst feedback creates disagreement metrics.

## 📝 Test Walkthrough: Guardrail Failure Lab

File: `C:\Projects\ThreatPrismV2\tests\test_guardrail_failures.py`

### Lines 75-89

`test_policy_violation_blocks_triage_report()` injects a fake provider output claiming an account was disabled. ThreatPrism blocks the report and records `triage_blocked_by_guardrail`.

### Lines 91-115

`test_unknown_evidence_reference_blocks_triage_report()` injects a report citing `ev-missing`. Evidence grounding blocks it.

### Lines 117-140

`test_real_action_claim_blocks_triage_report()` injects `real_action_executed=True`. Action safety blocks it.

## 📝 Test Walkthrough: Healthcare Defense Lab

File: `C:\Projects\ThreatPrismV2\tests\test_healthcare_guardrails.py`

### Lines 118-128

`test_identifier_only_security_telemetry_is_not_phi()` proves normal endpoint telemetry is not blindly treated as PHI.

### Lines 130-145

`test_patient_context_identifiers_are_tokenized_as_potential_phi()` proves patient context triggers typed tokens and privacy/legal review metadata.

### Lines 162-190

`test_case_creation_and_triage_never_expose_raw_healthcare_values()` proves raw potential PHI/ePHI, secrets, and clinical paths do not appear in stored cases, model-visible payloads, report payloads, or rendered reports.

## 🧪 Manual Verification

### 🔬 Exercise 1: Run The Full Test Suite

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_lesson08_full
```

Bash:

```bash
cd /c/Projects/ThreatPrismV2
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_lesson08_full
```

Expected output:

```text
66 passed
```

### 🔬 Exercise 2: Run The Defense Labs Only

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest tests\test_guardrails.py tests\test_guardrail_failures.py tests\test_healthcare_guardrails.py -q -p no:cacheprovider --basetemp .pytest_tmp_lesson08_defense
```

Expected output:

```text
14 passed
```

### 🔬 Exercise 3: Prove Compliance Claims Are Blocked

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -c "from threatprism.guardrails.policy import scan_output_policy; claims=['HIPAA compliant','HITRUST certified','control is satisfied','audit-ready','evidence proves compliance']; print([bool(scan_output_policy({'summary': c})) for c in claims])"
```

Expected output:

```text
[True, True, True, True, True]
```

### 🔬 Exercise 4: Confirm The Next Slice Is Documented

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
Select-String -Path docs\WORKING_CHECKLIST.md -Pattern "Demo Scenario Pack"
```

Expected output includes:

```text
Demo Scenario Pack & API Contract Freeze v0.1 is implemented:
```

## 📚 Interview Prep

**Q: Why disable pytest plugin autoload?**  
**A**: The local Windows environment has global pytest plugin issues. Disabling plugin autoload keeps validation focused on this project and avoids unrelated dependency failures.

**Q: What does the guardrail failure suite prove?**  
**A**: It proves ThreatPrism blocks unsafe provider output instead of saving it: policy violations, unknown evidence references, and real-action claims fail closed.

**Q: What is the most important current test gap?**  
**A**: The scenario-pack and contract tests now cover local role workflows. The next gap is packaging/runtime smoke coverage outside the in-memory test app, such as Docker/local demo startup, before dashboard or live-integration work.

**Q: How would you extend the tests for live providers later?**  
**A**: Keep deterministic provider tests as the baseline, then add contract tests around provider interfaces with fake responses, timeouts, schema failures, and not-configured paths before live credentials are used.

## 🎯 Key Takeaways

- The current suite covers API flow, SOAR adapters, guardrails, healthcare safeguards, enrichment stubs, access control, operational read models, evals, demo scenarios, and API contract checks.
- The defense labs prove unsafe output is blocked.
- Healthcare tests prove raw sensitive values do not leak.
- Tests are local and require no live providers.
- Demo Operations & CI Hardening v0.1 is implemented.
- Demo Scenario Pack & API Contract Freeze v0.1 is implemented.

## 📋 Summary Reference Card

| Test File | Coverage |
|---|---|
| `test_api_flow.py` | API health, case flow, report, feedback. |
| `test_soar_adapters.py` | Demo payload source normalization. |
| `test_guardrails.py` | Prompt firewall and tokenization. |
| `test_guardrail_failures.py` | Policy/evidence/action blocks. |
| `test_healthcare_guardrails.py` | Context-aware sensitive-data safeguards and role views. |
| `test_enrichment_stubs.py` | `not_configured` enrichment providers. |
| `test_access_control.py` | Demo auth, role escalation denial, and safe authorization audit events. |
| `test_operational_read_models.py` | Metrics, filters, queues, detail routes, auth, and leakage prevention. |
| `test_eval_harness.py` | Dry-run eval harness, artifact sanitization, traversal rejection, and regression fixtures. |

## 🚀 Where To Go Next

Next implementation target:

- `C:\Projects\ThreatPrismV2\docs\WORKING_CHECKLIST.md`
- `C:\Projects\ThreatPrismV2\docs\ARCHITECTURAL_NORTH_STAR.md`

Optional advanced challenges:

- Add an access-control test before implementation.
- Add an eval fixture for prompt injection cases.
- Add snapshot testing for `render_report()`.
- Add a safe audit-summary route using the implemented authorization pattern.

Remember: tests are how ThreatPrism proves guardrails are real, not just documented. 🛡️
