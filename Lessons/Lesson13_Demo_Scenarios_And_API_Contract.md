# Lesson 13: Demo Scenarios And API Contract

## Goal

Understand how ThreatPrism now proves the current backend demo workflows and
API route contracts before dashboard or live-integration work begins.

## Primary Files

```text
src/threatprism/demo/scenarios.py
examples/demo_scenarios/demo_scenario_pack.json
examples/demo_scenarios/healthcare_safeguard_review_case.json
tests/test_demo_scenarios_and_api_contract.py
docs/DEMO_SCENARIO_PACK_AND_API_CONTRACT.md
docs/specs/19_DEMO_SCENARIO_PACK_AND_API_CONTRACT.md
```

## What The Slice Adds

Demo Scenario Pack & API Contract Freeze v0.1 adds:

- Typed scenario-pack validation.
- Five role-specific fake workflows.
- A fake healthcare-context safeguard review payload.
- Smoke tests that run against an in-memory FastAPI app.
- OpenAPI route and response-model contract assertions.

It does not add dashboard UI, live providers, production IdP integration, SOAR
callbacks, or remediation.

## Scenario Personas

The scenario pack must cover:

- `analyst`: review triage output and submit feedback.
- `manager_grc`: inspect disagreement metrics, queue items, and GRC controls.
- `legal_privacy`: inspect healthcare safeguard review output without raw
  potential PHI/ePHI.
- `audit_debug`: inspect safe authorization audit events.
- `engineer`: inspect evidence, timeline, and MITRE traceability.

## Contract Boundary

The contract test confirms the current implemented local routes still exist and
that the key OpenAPI response models remain stable:

```text
CaseAcceptedResponse
CaseSummary
OperationalMetrics
CaseReadModelEnvelope
ReviewQueueEnvelope
FeedbackResponse
```

Later slices can add routes. Removing or renaming frozen routes is a contract
change and should update docs, tests, and decision records.

## Run The Focused Check

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest tests\test_demo_scenarios_and_api_contract.py -p no:cacheprovider --basetemp .pytest_tmp_run_demo_contract_focus
```

Expected focused result:

```text
4 passed
```

## Review Questions

- Does every scenario use only local API routes?
- Do all payload paths stay under `examples/`?
- Are fake demo credentials the only credentials in the scenario pack?
- Do privacy/audit views block raw fake healthcare-context values?
- Does the OpenAPI route set still include every frozen route?
- Did any route rename update the docs and decision records?

## Quick Reference

- Scenario pack schema: `demo-scenario-pack/0.1`.
- Scenario artifacts: `examples/demo_scenarios/`.
- Focused tests: `tests/test_demo_scenarios_and_api_contract.py`.
- Full safe validation: `powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1`.
