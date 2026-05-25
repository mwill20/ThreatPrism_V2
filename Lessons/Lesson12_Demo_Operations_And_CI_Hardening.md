# 🎓 Lesson 12: The Safety Rail - Demo Operations And CI Hardening

## 🛡️ Welcome Back, Operations Engineer!

How do you make a security backend easy to trust before adding live
integrations? 🔍 Today we are exploring **Demo Operations & CI Hardening** -
the "safety rail" that keeps local validation and CI fake-data-only.

Goal: understand how ThreatPrism validates safely from a repeatable script and
CI workflow.

Time estimate: 35 minutes.

Prerequisites:

- Complete Lessons 00-11.
- Run commands from `C:\Projects\ThreatPrismV2`.
- Understand that live LLM, SOAR, cloud, enrichment, dashboard, production
  IdP, and remediation work remain out of scope.

## 🎯 Learning Objectives

- Run the one-command validation wrapper.
- Explain why CI must be fake-data-only.
- Inspect the safety checker and its failure conditions.
- Confirm eval artifacts are ignored and sanitized.
- Describe what this slice does not prove.

## 🔍 Plain-English Explanation

### ✅ Implemented Here

ThreatPrism now has a repeatable validation path:

```text
PowerShell wrapper
  -> safety scanner
  -> pytest with plugin autoload disabled
  -> dry-run eval harness
  -> eval artifact hygiene scan
  -> lightweight GitHub Actions workflow
```

Primary files:

- `C:\Projects\ThreatPrismV2\tools\validate-threatprism.ps1`
- `C:\Projects\ThreatPrismV2\tools\check_demo_safety.py`
- `C:\Projects\ThreatPrismV2\.github\workflows\safe-validation.yml`
- `C:\Projects\ThreatPrismV2\tests\test_ops_safety.py`
- `C:\Projects\ThreatPrismV2\docs\DEMO_OPERATIONS_AND_CI_HARDENING.md`

### Recommended (not implemented here)

- Production release gates.
- Dependency vulnerability scanning.
- SAST or container scanning.
- Deployment approvals.
- Production IdP or secrets manager integration.

## 🧠 Real-World Analogy

Think of this slice like a pre-flight checklist:

- The validation wrapper is the checklist.
- The safety scanner checks for unsafe baggage.
- Pytest checks the system.
- The eval harness checks failure drills.
- CI makes sure every future change repeats the same checks.

## 🔗 Pipeline Context

```text
Code change
  -> tools/check_demo_safety.py
  -> pytest
  -> threatprism.evals.cli
  -> eval artifact hygiene scan
  -> docs/checklist/lessons updated
```

## 🎯 Key Concepts

| Concept | Meaning |
|---|---|
| Safe validation wrapper | PowerShell script that sets safe env vars and runs the validation sequence. |
| Safety checker | Python script that fails closed on unsafe local or CI posture. |
| Fake-data-only CI | Workflow that does not require repository secrets or live credentials. |
| Artifact hygiene | Keeping generated outputs ignored and checking eval outputs for forbidden raw values. |

## 📝 Code Walkthrough: Safety Checker

File: `C:\Projects\ThreatPrismV2\tools\check_demo_safety.py`

```python
LIVE_CREDENTIAL_ENV_VARS = {
    "OPENAI_API_KEY",
    "LOCAL_LLM_BASE_URL",
    "VIRUSTOTAL_API_KEY",
    "URLSCAN_API_KEY",
    "ABUSEIPDB_API_KEY",
}
```

This list defines environment variables that must be empty during safe local
validation and CI. These providers are not forbidden forever. This validation
path simply must not depend on live credentials.

```python
def run_checks(
    root: Path,
    *,
    include_untracked: bool = False,
    scan_eval_artifacts: bool = False,
) -> list[SafetyFinding]:
```

`run_checks()` is the command center. It collects environment checks,
runtime-guard checks, `.env.example` checks, gitignore checks, tracked artifact
checks, secret-pattern scans, and optional eval artifact scans.

```python
if _is_truthy(os.getenv("ALLOW_REAL_ACTIONS")):
    findings.append(...)
```

This fails if validation is running with real actions enabled. ThreatPrism V2
must remain recommendation/simulation-only.

## 📝 Code Walkthrough: Validation Wrapper

File: `C:\Projects\ThreatPrismV2\tools\validate-threatprism.ps1`

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = "1"
$env:THREATPRISM_ENV = "test"
$env:API_AUTH_MODE = "none"
$env:LLM_PROVIDER = "deterministic_demo"
$env:ALLOW_REAL_ACTIONS = "false"
$env:OPENAI_API_KEY = ""
```

The wrapper pins validation to the deterministic fake path and clears live
credential variables for the script process.

```powershell
python -m pytest -p no:cacheprovider --basetemp $BaseTemp
python -m threatprism.evals.cli --fixtures regression_cases.jsonl --output ops_ci
python tools/check_demo_safety.py --scan-eval-artifacts
```

These commands prove the main tests pass, the eval harness still passes, and
generated eval artifacts do not expose forbidden raw values.

## 🧪 Manual Verification

### 🔬 Exercise 1: Run The Full Wrapper

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1 -BaseTemp .pytest_tmp_lesson12
```

Expected output includes:

```text
ThreatPrism demo safety check passed.
51 passed
"failed": 0
ThreatPrism safe validation completed.
```

### 🔬 Exercise 2: Run Only The Safety Checker

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
python tools\check_demo_safety.py --include-untracked
```

Expected output:

```text
ThreatPrism demo safety check passed.
```

### 🔬 Exercise 3: Run The Ops Safety Tests

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest tests\test_ops_safety.py -q -p no:cacheprovider --basetemp .pytest_tmp_lesson12_ops
```

Expected output:

```text
4 passed
```

### 🔬 Exercise 4: Inspect The CI Workflow

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
Get-Content .\.github\workflows\safe-validation.yml
```

Expected output includes:

```text
ALLOW_REAL_ACTIONS: "false"
python tools/check_demo_safety.py
python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_ops_ci
python -m threatprism.evals.cli --fixtures regression_cases.jsonl --output ci
```

## 📚 Interview Prep

**Q: Why add a wrapper instead of telling people to run pytest manually?**  
**A**: The wrapper encodes the safe environment, disables unsafe plugin
autoloading, uses a fresh temp path, runs evals, and checks artifacts. It
reduces operator drift.

**Q: Why should CI avoid repository secrets right now?**  
**A**: ThreatPrism is still demo-safe. CI should prove local deterministic
behavior, not open live-provider or production paths.

**Q: Why scan eval artifacts after running the harness?**  
**A**: A tool can block sensitive data correctly but still leak it through test
outputs. Artifact scanning verifies the regression harness is not its own leak
path.

**Q: Does this make ThreatPrism production-ready?**  
**A**: No. It makes the local and CI validation path repeatable and safer. It
does not add production auth, deployment hardening, or live-provider review.

## 🎯 Key Takeaways

- `tools/validate-threatprism.ps1` is the preferred local validation entry
  point.
- `tools/check_demo_safety.py` checks environment posture, generated artifacts,
  secret-like content, and eval outputs.
- CI runs fake-data-only tests and evals without repository secrets.
- This slice improves operational discipline without adding live capability.

## 📋 Summary Reference Card

| Item | Details |
|---|---|
| Validation wrapper | `tools/validate-threatprism.ps1` |
| Safety checker | `tools/check_demo_safety.py` |
| CI workflow | `.github/workflows/safe-validation.yml` |
| Test file | `tests/test_ops_safety.py` |
| Eval output | `.eval_runs/` |
| Current validation | `51 passed` |
| Out of scope | Live providers, dashboard UI, production IdP, real remediation |

## 🚀 Ready For The Next Slice?

Next, build **Demo Scenario Pack & API Contract Freeze v0.1**.

Hands-on challenges:

- Add repeatable fake demo scenarios for each role.
- Confirm API response contracts before dashboard work.
- Keep every scenario fake-data-only.

Remember: repeatable safety beats one-time success. 🛡️
