# 🎓 Lesson 11: The Regression Range - Evaluation Harness And Defense Labs

## 🛡️ Welcome Back, Test And Eval Engineer!

How do you prove ThreatPrism still fails safely after new features are added? 🔍 Today we are exploring **Evaluation Harness & Regression Defense Labs** - the "regression range" that runs fake bad inputs through deterministic safety checks.

Goal: understand how the local eval harness protects ThreatPrism from safety regressions without using live LLMs, live SOAR, cloud calls, real data, or real remediation.

Time estimate: 55 minutes.

Prerequisites:

- Complete Lessons 00-10.
- Understand guardrails, role views, access control, and read models.
- Run commands from `C:\Projects\ThreatPrismV2`.

## 🎯 Learning Objectives

- Explain why eval artifacts can become a leakage risk.
- Run the dry-run eval harness.
- Inspect fake JSONL eval fixtures.
- Trace how fixture path traversal is rejected.
- Describe how sanitized previews avoid raw sensitive values.
- Explain why this harness is not a live-LLM safety proof.

## 🔍 Plain-English Explanation

### ✅ Implemented Here

ThreatPrism now has a local eval harness:

```text
Fake eval JSONL
  -> approved fixture directory check
  -> deterministic safety check
  -> sanitized preview
  -> approved output directory check
  -> .eval_runs/<run_id>/results.json
```

Primary files:

- `C:\Projects\ThreatPrismV2\src\threatprism\evals\schemas.py`
- `C:\Projects\ThreatPrismV2\src\threatprism\evals\runner.py`
- `C:\Projects\ThreatPrismV2\src\threatprism\evals\cli.py`
- `C:\Projects\ThreatPrismV2\tests\evals\regression_cases.jsonl`
- `C:\Projects\ThreatPrismV2\tests\evals\malformed_cases.jsonl`
- `C:\Projects\ThreatPrismV2\tests\test_eval_harness.py`

### Recommended (not implemented here)

- Live LLM shadow evaluation.
- Semantic LLM-as-judge checks.
- CI trend dashboards.
- SIEM export of eval failures.
- Production red-team dataset governance.

## 🧠 Real-World Analogy

Think of the eval harness like a controlled training range:

- The targets are fake.
- The scenarios are intentionally unsafe or ambiguous.
- The system must fail safely.
- The scorecard is sanitized so the test itself does not leak sensitive data.

## 🔗 Pipeline Context

```text
tests/evals/*.jsonl
  -> EvalFixture
  -> category-specific check
  -> EvalCaseResult
  -> EvalRunSummary
  -> .eval_runs/<run_id>/
```

## 🎯 Key Concepts

### ✅ Implemented Here

| Concept | Meaning |
|---|---|
| Eval fixture | A fake JSONL row describing one regression scenario. |
| Eval category | Scenario type such as `prompt_injection` or `audit_event_leakage`. |
| Safe preview | Sanitized, bounded preview stored in eval results. |
| Approved fixture directory | `tests/evals/`; runner rejects path traversal. |
| Approved output directory | `.eval_runs/`; runner rejects output traversal. |
| Regression gate | A local check proving known safety controls still work. |

### Recommended (not implemented here)

- Keep production eval datasets access-controlled.
- Version eval suites when fixtures become dashboard or CI dependencies.
- Separate deterministic evals from future live model evals.

## 📝 Code Walkthrough: Eval Schemas

File: `C:\Projects\ThreatPrismV2\src\threatprism\evals\schemas.py`

```python
class EvalCategory(StrEnum):
    prompt_injection = "prompt_injection"
    hallucinated_claims = "hallucinated_claims"
    unsafe_action_claims = "unsafe_action_claims"
    schema_violations = "schema_violations"
    unsupported_evidence_citations = "unsupported_evidence_citations"
    healthcare_safeguard_leakage = "healthcare_safeguard_leakage"
    authorization_escalation = "authorization_escalation"
```

This code does:

1. Defines supported regression categories.
2. Prevents ad hoc category strings from drifting.
3. Makes test coverage easy to map to risk areas.

```python
class EvalCaseResult(BaseModel):
    run_id: str
    fixture_id: str
    category: EvalCategory
    passed: bool
    failure_reason: str | None = None
    safe_sanitized_preview: str
    artifact_path: str | None = None
```

Why it matters:

- Results show pass/fail without storing raw payload bodies.
- `safe_sanitized_preview` gives enough debugging context while avoiding raw sensitive values.
- `artifact_path` points to the sanitized output file.

## 📝 Code Walkthrough: Runner Safety

File: `C:\Projects\ThreatPrismV2\src\threatprism\evals\runner.py`

```python
APPROVED_FIXTURE_DIR = Path("tests/evals")
APPROVED_OUTPUT_DIR = Path(".eval_runs")
MAX_PREVIEW_CHARS = 500
```

This code does:

1. Restricts fixture reads to `tests/evals/`.
2. Restricts output writes to `.eval_runs/`.
3. Bounds preview size so oversized payloads do not flood artifacts.

```python
def _resolve_under_approved_dir(candidate: str | Path, approved_dir: Path) -> Path:
    approved = approved_dir.resolve()
    raw = Path(candidate)
    ...
    if resolved != approved and approved not in resolved.parents:
        raise ValueError(f"Path must stay under approved directory: {approved}")
    return resolved
```

Why it matters:

- The eval harness cannot read arbitrary local files.
- The eval harness cannot write artifacts outside the approved output tree.
- This prevents the harness from becoming a new attack surface.

## 📝 Code Walkthrough: Sanitized Preview

```python
def _safe_preview(payload: dict[str, Any]) -> str:
    sanitized_prompt = sanitize_value(_payload_without_eval_metadata(payload)).value
    sanitized_healthcare = safeguard_value(sanitized_prompt, case_id="case_eval").value
    rendered = render_role_view(sanitized_healthcare, "audit_debug", case_id="case_eval").payload
    preview = json.dumps(rendered, sort_keys=True, default=str)
    if len(preview) > MAX_PREVIEW_CHARS:
        return f"{preview[:MAX_PREVIEW_CHARS]}..."
    return preview
```

This code does:

1. Removes eval metadata such as `expected_raw_values`.
2. Applies prompt sanitization.
3. Applies healthcare safeguard tokenization.
4. Applies audit/debug role rendering.
5. Truncates oversized previews.

⚠️ Common pitfall: blocking a secret in the application but writing the raw secret into eval results. This function prevents that class of regression.

## 🧪 Manual Verification

### 🔬 Exercise 1: Run Eval Harness Tests

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest tests\test_eval_harness.py -q -p no:cacheprovider --basetemp .pytest_tmp_lesson11_eval
```

Expected output:

```text
6 passed
```

### 🔬 Exercise 2: Run Full Validation

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_lesson11_full
```

Expected output: the current pass/skip count in
[../docs/VALIDATION_BASELINE.md](../docs/VALIDATION_BASELINE.md).

### 🔬 Exercise 3: Run The CLI Harness

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -m threatprism.evals.cli --fixtures regression_cases.jsonl
```

Expected output includes:

```text
"total": 15
"failed": 0
```

### 🔬 Exercise 4: Prove Traversal Is Rejected

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest tests\test_eval_harness.py::test_path_traversal_is_rejected_for_fixtures_and_outputs -q -p no:cacheprovider --basetemp .pytest_tmp_lesson11_paths
```

Expected output:

```text
1 passed
```

## 📚 Interview Prep

**Q: Why is this called a regression defense lab instead of just an eval harness?**  
**A**: Its main job is to prove known safety controls keep working after code changes. It is not a playground for live adversarial data.

**Q: Why not store raw eval payloads in result files?**  
**A**: Eval artifacts can leak the same sensitive values the product is supposed to block. ThreatPrism stores sanitized previews and category outcomes instead.

**Q: What does path traversal protection prevent?**  
**A**: It prevents the harness from reading arbitrary local files or writing artifacts outside `.eval_runs/`.

**Q: Does this prove live LLM safety?**  
**A**: No. It proves deterministic and controlled fake-provider regression checks. Live LLM shadow evaluation is a later slice.

## 🎯 Key Takeaways

- Eval fixtures are fake JSONL files under `tests/evals/`.
- Eval artifacts are sanitized and written under `.eval_runs/`.
- The harness covers prompt injection, unsafe actions, schema/evidence failures, healthcare leakage, auth escalation, role leakage, read-model leakage, audit leakage, token-vault exposure, and compliance overclaims.
- Malformed JSON fails safely.
- Production-like environments now reject disabled/demo auth.

## 📋 Summary Reference Card

| Item | Details |
|---|---|
| Main runner | `run_eval_suite()` |
| Single fixture evaluator | `evaluate_fixture()` |
| Fixture directory | `tests/evals/` |
| Output directory | `.eval_runs/` |
| CLI | `python -m threatprism.evals.cli --fixtures regression_cases.jsonl` |
| Test file | `tests/test_eval_harness.py` |
| Validation | [Canonical baseline](../docs/VALIDATION_BASELINE.md) |

## 🚀 Ready For The Next Slice?

Next, study **Demo Operations & CI Hardening v0.1** in Lesson 12.

Hands-on challenges:

- Add a safe validation script wrapping the known pytest command.
- Add lightweight CI that runs fake-data tests only.
- Add runbook steps for API, metrics, and eval workflows.

Remember: a safety claim is only useful when it keeps passing after the next change. 🛡️
