# 🎓 Lesson 00: The North Star - System Overview And Architecture

## 🛡️ Welcome Back, ThreatPrism Builder!

Ever opened a repo and wondered, "What is this thing trying to become?" 🔍
Today we are exploring **ThreatPrism as a system** - the "map and compass" that keeps every slice pointed at the same destination.

Goal: understand why ThreatPrism exists, what has been built so far, and what must stay true as the project grows.

Time estimate: 25 minutes.

Prerequisites:

- Python 3.11+ installed.
- Dependencies installed from `requirements.txt`.
- Run commands from `C:\Projects\ThreatPrismV2`.

## 🎯 Learning Objectives

- Explain what ThreatPrism does in plain English.
- Identify the current implemented pipeline.
- Connect the codebase to the Architectural North Star.
- Distinguish implemented behavior from future production guidance.
- Run the baseline validation command.
- Describe the no-real-remediation and fake-data boundaries.

## 🔍 Plain-English Explanation

### ✅ Implemented Here

ThreatPrism is currently a demo-safe backend that accepts fake SOAR security cases, normalizes them into structured case records, applies guardrails, generates deterministic triage reports, saves data in SQLite, and exposes FastAPI endpoints.

Primary files:

- `C:\Projects\ThreatPrismV2\README.md`
- `C:\Projects\ThreatPrismV2\docs\ARCHITECTURAL_NORTH_STAR.md`
- `C:\Projects\ThreatPrismV2\docs\WORKING_CHECKLIST.md`
- `C:\Projects\ThreatPrismV2\src\threatprism\api\app.py`

### Recommended (not implemented here)

In a production deployment, this would also need production IdP integration, deployment hardening, observability, queues/workers, secret management, and real integration governance.

## 🧠 Real-World Analogy

Think of ThreatPrism like a quality-control review desk inside an internal SOC:

- A SOAR platform sends a case.
- ThreatPrism reviews the evidence.
- It checks for safety problems before using AI-style analysis.
- It writes a structured report.
- A human analyst still makes the final call.

It is not the person pushing the "contain threat" button. It is the reviewer organizing evidence before that decision.

## 🔗 Why This Matters

ThreatPrism is being built for security workflows where mistakes matter:

- Raw sensitive data should not leak into model-visible payloads.
- LLM output should not be trusted until validated.
- HITRUST/HIPAA language must not overclaim compliance.
- Real remediation must stay disabled in V2.

The North Star prevents future slices from drifting into unsafe shortcuts.

## 🎯 Key Concepts

### ✅ Implemented Here

| Term | Meaning In This Repo |
|---|---|
| Case | Normalized security case represented by `CaseRecord`. |
| Evidence | Structured item supporting a finding, mapping, or report claim. |
| SOAR payload | Fake demo JSON input under `examples/soar_payloads/`. |
| Guardrail | Deterministic checks for prompt injection, policy issues, evidence grounding, action safety, and healthcare safeguard exposure. |
| Role view | Rendered payload adjusted for roles such as `analyst`, `manager_grc`, or `audit_debug`. |
| Deterministic demo provider | Local report generator that avoids live LLM calls. |

### Recommended (not implemented here)

- Production identity provider integration.
- Central audit log storage with tamper-evidence.
- SIEM-forwarded operational telemetry.
- Human approval workflow for any future real remediation.

## 🧩 Architecture Context

```text
SOAR JSON fixture
  -> FastAPI /cases
  -> CaseService
  -> SOAR adapter
  -> Pydantic case model
  -> Healthcare safeguards
  -> Prompt firewall and tokenization
  -> Deterministic report provider
  -> Policy/evidence/action validation
  -> SQLite
  -> API response
```

## 📝 Code Walkthrough: North Star And Health Route

### `docs/ARCHITECTURAL_NORTH_STAR.md`

The North Star says the safe data flow is:

```text
Raw source payload
  -> Source payload hash
  -> Evidence and provenance normalization
  -> Deterministic healthcare safeguard scan
  -> Prompt firewall
  -> Input sanitization and sensitive-value tokenization
  -> Model-visible payload
  -> Provider-agnostic LLM or deterministic demo provider
  -> Strict schema validation
  -> Output policy scan
  -> Evidence-grounding checks
  -> Action-safety checks
  -> Authorization-aware role view
  -> Deterministic report or read model
  -> Safe audit event
```

Why it matters: this is the threat model in one picture. Every future slice should preserve this order unless a decision record changes it.

### `src/threatprism/api/app.py`, lines 17-31

```python
def create_app(settings: Settings | None = None) -> FastAPI:
    active_settings = settings or Settings.from_env()
    app = FastAPI(title="ThreatPrism API", version=__version__)
    app.state.settings = active_settings
    app.state.case_service = CaseService(active_settings)

    @app.get("/health")
    def health() -> dict[str, object]:
        return {
            "status": "ok",
            "service": "threatprism-api",
            "version": __version__,
            "mode": active_settings.env,
            "allow_real_actions": active_settings.allow_real_actions,
        }
```

Line-by-line:

1. `settings or Settings.from_env()` lets tests inject safe settings while local runs use environment variables.
2. `app.state.case_service` stores one service object for route handlers.
3. `/health` returns the active mode and `allow_real_actions`.
4. `allow_real_actions` is visible because action safety is a first-class boundary.

## 🧪 Manual Verification

### 🔬 Exercise 1: Run The Full Baseline

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_lesson00
```

Bash:

```bash
cd /c/Projects/ThreatPrismV2
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_lesson00
```

Expected output: the current pass/skip count in
[../docs/VALIDATION_BASELINE.md](../docs/VALIDATION_BASELINE.md).

### 🔬 Exercise 2: Inspect Configuration Defaults

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -c "from threatprism.config import Settings; s=Settings.from_env(); print(s.env); print(s.llm_provider); print(s.allow_real_actions)"
```

Expected output:

```text
demo
deterministic_demo
False
```

### 🔬 Exercise 3: Confirm The Product Version Loads

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -c "import threatprism; print(threatprism.__version__)"
```

Expected output:

```text
0.1.0
```

## 📚 Interview Prep

**Q: What problem does ThreatPrism solve?**  
**A**: ThreatPrism helps an organization moving from outsourced SOC operations toward an internal SOC by reviewing security cases, grounding findings in evidence, capturing analyst feedback, and producing role-safe outputs. This answer shows you understand the product goal, not just the code.

**Q: Why is the North Star important?**  
**A**: It prevents architecture drift. Future workarounds must either follow the guide or update the guide and decision records. This demonstrates architecture discipline.

**Q: Why is `ALLOW_REAL_ACTIONS=false` a non-negotiable?**  
**A**: V2 may recommend or simulate actions, but it must not perform containment or remediation. This protects the demo-safe boundary and keeps analysts in control.

## 🎯 Key Takeaways

- ThreatPrism is a demo-safe internal SOC migration accelerator.
- The current backend is real code, not just specs.
- Guardrails and evidence grounding are core architecture, not add-ons.
- Role views are protected by demo API-key authorization when `API_AUTH_MODE=demo_key`.
- Operational read models, metrics, and regression evals are implemented.
- The next active slice is Demo Scenario Pack & API Contract Freeze v0.1.

## 📋 Summary Reference Card

| Item | Value |
|---|---|
| Product | ThreatPrism |
| Canonical path | `C:\Projects\ThreatPrismV2` |
| Repo | `mwill20/ThreatPrism_V2` |
| Main backend entry | `src/threatprism/api/app.py` |
| CLI runner | `src/threatprism/cli/main.py` |
| Config defaults | `src/threatprism/config.py` |
| Current validation | [Canonical baseline](../docs/VALIDATION_BASELINE.md) |
| Hard safety default | `ALLOW_REAL_ACTIONS=false` |

## 🚀 Ready For Lesson 01?

Next, study the API command center: how `/health`, `/cases`, `/triage-report`, and analyst feedback connect to the service layer.

Remember: ThreatPrism is evidence-first, analyst-controlled, and guardrail-led. 🛡️
