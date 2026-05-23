# 📚 ThreatPrism Lessons Index

## Assumptions And Missing Context

- These lessons describe the code that exists now in `C:\Projects\ThreatPrismV2`.
- The current validated baseline is `34 passed`.
- Lessons use emojis because the lesson brief requested visual scanning markers.
- Line references are based on the live files at lesson creation time.
- This curriculum teaches implemented behavior first, then labels future guidance as `Recommended (not implemented here)`.

## How To Use These Lessons

Start at Lesson 00 and move in order. Each lesson includes:

- Goal, time estimate, and prerequisites.
- Pipeline context.
- Code walkthroughs with file and line references.
- Hands-on commands for PowerShell and bash where practical.
- Interview prep talk tracks.
- A quick reference card.

## Current ThreatPrism Pipeline

```text
Fake SOAR payload
  -> SOAR adapter normalization
  -> Case schema validation
  -> Healthcare safeguard scan
  -> Prompt firewall and tokenization
  -> Deterministic demo triage provider
  -> Schema, policy, evidence, and action-safety checks
  -> Controlled rehydration and role view rendering
  -> Deterministic report
  -> SQLite persistence
  -> Operational metrics and read models
  -> API responses and tests
```

## Lesson Plan

| Required | Lesson | Title | Primary Files |
|---|---|---|---|
| ✅ | [Lesson 00](Lesson00_System_Overview.md) | System Overview And North Star | `README.md`, `docs/ARCHITECTURAL_NORTH_STAR.md`, `docs/WORKING_CHECKLIST.md` |
| ✅ | [Lesson 01](Lesson01_API_Command_Center.md) | API Command Center | `src/threatprism/api/app.py`, `src/threatprism/cli/main.py`, `tests/test_api_flow.py` |
| ✅ | [Lesson 02](Lesson02_Case_Schemas_And_Service.md) | Case Schemas And Service Orchestration | `src/threatprism/cases/schemas.py`, `src/threatprism/cases/service.py` |
| ✅ | [Lesson 03](Lesson03_SOAR_Intake_Translator.md) | SOAR Intake Translator | `src/threatprism/soar/generic.py`, `examples/soar_payloads/*.json`, `tests/test_soar_adapters.py` |
| ✅ | [Lesson 04](Lesson04_Guardrail_Gatekeepers.md) | Prompt, Policy, Evidence, And Action Guardrails | `src/threatprism/guardrails/*.py`, `src/threatprism/actions/safety.py`, `tests/test_guardrails.py`, `tests/test_guardrail_failures.py` |
| ✅ | [Lesson 05](Lesson05_Healthcare_Safeguards_And_Role_Views.md) | Healthcare Safeguards And Role Views | `src/threatprism/guardrails/healthcare.py`, `src/threatprism/guardrails/views.py`, `tests/test_healthcare_guardrails.py` |
| ✅ | [Lesson 06](Lesson06_Deterministic_Triage_Mapping_And_Reports.md) | Deterministic Triage, Mapping, Enrichment, And Reports | `src/threatprism/llm/providers.py`, `src/threatprism/mitre/mapping.py`, `src/threatprism/grc/mapping.py`, `src/threatprism/enrichment/stubs.py`, `src/threatprism/reports/render.py` |
| ✅ | [Lesson 07](Lesson07_SQLite_Config_And_Identifiers.md) | SQLite, Config, And Identifiers | `src/threatprism/persistence/sqlite.py`, `src/threatprism/config.py`, `src/threatprism/ids.py`, `.env.example` |
| ✅ | [Lesson 08](Lesson08_Testing_Defense_Labs_And_Next_Slices.md) | Testing, Defense Labs, And Next Slices | `tests/*.py`, `docs/specs/16_*`, `docs/specs/17_*` |
| ✅ | [Lesson 09](Lesson09_Access_Control_And_Audit_Integrity.md) | Access Control And Audit Integrity | `src/threatprism/auth/demo.py`, `tests/test_access_control.py`, `.env.example` |
| ✅ | [Lesson 10](Lesson10_Operational_Read_Models_And_Metrics.md) | Operational Read Models And Metrics | `src/threatprism/cases/read_models.py`, `src/threatprism/api/app.py`, `tests/test_operational_read_models.py` |

## File Coverage Map

### Source Files

- `C:\Projects\ThreatPrismV2\src\threatprism\__init__.py` -> Lesson 00
- `C:\Projects\ThreatPrismV2\src\threatprism\api\app.py` -> Lesson 01
- `C:\Projects\ThreatPrismV2\src\threatprism\auth\demo.py` -> Lesson 09
- `C:\Projects\ThreatPrismV2\src\threatprism\auth\__init__.py` -> Lesson 09
- `C:\Projects\ThreatPrismV2\src\threatprism\cli\main.py` -> Lesson 01
- `C:\Projects\ThreatPrismV2\src\threatprism\cases\schemas.py` -> Lesson 02
- `C:\Projects\ThreatPrismV2\src\threatprism\cases\service.py` -> Lesson 02
- `C:\Projects\ThreatPrismV2\src\threatprism\cases\read_models.py` -> Lesson 10
- `C:\Projects\ThreatPrismV2\src\threatprism\soar\generic.py` -> Lesson 03
- `C:\Projects\ThreatPrismV2\src\threatprism\guardrails\prompt_firewall.py` -> Lesson 04
- `C:\Projects\ThreatPrismV2\src\threatprism\guardrails\tokenization.py` -> Lesson 04
- `C:\Projects\ThreatPrismV2\src\threatprism\guardrails\policy.py` -> Lesson 04
- `C:\Projects\ThreatPrismV2\src\threatprism\guardrails\evidence.py` -> Lesson 04
- `C:\Projects\ThreatPrismV2\src\threatprism\actions\safety.py` -> Lesson 04
- `C:\Projects\ThreatPrismV2\src\threatprism\guardrails\healthcare.py` -> Lesson 05
- `C:\Projects\ThreatPrismV2\src\threatprism\guardrails\views.py` -> Lesson 05
- `C:\Projects\ThreatPrismV2\src\threatprism\llm\providers.py` -> Lesson 06
- `C:\Projects\ThreatPrismV2\src\threatprism\mitre\mapping.py` -> Lesson 06
- `C:\Projects\ThreatPrismV2\src\threatprism\grc\mapping.py` -> Lesson 06
- `C:\Projects\ThreatPrismV2\src\threatprism\enrichment\stubs.py` -> Lesson 06
- `C:\Projects\ThreatPrismV2\src\threatprism\reports\render.py` -> Lesson 06
- `C:\Projects\ThreatPrismV2\src\threatprism\persistence\sqlite.py` -> Lesson 07
- `C:\Projects\ThreatPrismV2\src\threatprism\config.py` -> Lesson 07
- `C:\Projects\ThreatPrismV2\src\threatprism\ids.py` -> Lesson 07

### Tests And Fixtures

- `C:\Projects\ThreatPrismV2\tests\test_api_flow.py` -> Lessons 01 and 08
- `C:\Projects\ThreatPrismV2\tests\test_access_control.py` -> Lessons 08 and 09
- `C:\Projects\ThreatPrismV2\tests\test_operational_read_models.py` -> Lessons 08 and 10
- `C:\Projects\ThreatPrismV2\tests\test_soar_adapters.py` -> Lessons 03 and 08
- `C:\Projects\ThreatPrismV2\tests\test_guardrails.py` -> Lessons 04 and 08
- `C:\Projects\ThreatPrismV2\tests\test_guardrail_failures.py` -> Lessons 04 and 08
- `C:\Projects\ThreatPrismV2\tests\test_healthcare_guardrails.py` -> Lessons 05 and 08
- `C:\Projects\ThreatPrismV2\tests\test_enrichment_stubs.py` -> Lessons 06 and 08
- `C:\Projects\ThreatPrismV2\examples\soar_payloads\*.json` -> Lesson 03

## Fast Validation Commands

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_lessons
```

Bash:

```bash
cd /c/Projects/ThreatPrismV2
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_lessons
```

Expected output:

```text
34 passed
```

## What To Study Next

After Lesson 10, continue into the next active implementation slice:

- `C:\Projects\ThreatPrismV2\docs\specs\11_EVALUATION_PLAN.md`
- `C:\Projects\ThreatPrismV2\docs\ARCHITECTURAL_NORTH_STAR.md`
