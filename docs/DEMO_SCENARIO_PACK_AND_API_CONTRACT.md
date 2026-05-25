# Demo Scenario Pack And API Contract Freeze

Demo Scenario Pack & API Contract Freeze v0.1 is implemented.

This slice gives ThreatPrism a repeatable fake-data demo path for current
role-specific backend workflows and freezes the current API response contracts
with tests. It does not add a dashboard, live integrations, production IdP, or
real remediation.

## Implemented Files

```text
examples/demo_scenarios/demo_scenario_pack.json
examples/demo_scenarios/healthcare_safeguard_review_case.json
src/threatprism/demo/scenarios.py
tests/test_demo_scenarios_and_api_contract.py
```

## Scenario Coverage

The scenario pack covers:

- Analyst triage and feedback.
- Manager/GRC disagreement metrics, queue review, and GRC controls.
- Legal/privacy healthcare safeguard review.
- Audit/debug authorization denial review.
- Engineer evidence, timeline, and MITRE trace review.

All scenarios use local FastAPI routes, fake payloads, fake demo API keys, and
the deterministic demo provider.

## Contract Coverage

The contract freeze test confirms these implemented routes remain present:

```text
GET /health
POST /cases
GET /cases
GET /metrics
GET /cases/read-model
GET /queues/manager-review
GET /queues/healthcare-review
GET /cases/{case_id}
GET /cases/{case_id}/triage-report
GET /cases/{case_id}/evidence
GET /cases/{case_id}/timeline
GET /cases/{case_id}/mitre
GET /cases/{case_id}/grc-controls
GET /cases/{case_id}/audit-events
POST /cases/{case_id}/analyst-feedback
```

The test also checks OpenAPI response models and contract-declared status codes for:

- `CaseAcceptedResponse`.
- `CaseSummary`.
- `OperationalMetrics`.
- `CaseReadModelEnvelope`.
- `ReviewQueueEnvelope`.
- `FeedbackResponse`.

Additions are allowed in later slices, but renaming or removing these current
routes should be treated as a contract change and reflected in docs, tests, and
decision records.

## Run The Focused Checks

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest tests\test_demo_scenarios_and_api_contract.py -p no:cacheprovider --basetemp .pytest_tmp_run_demo_contract_focus
```

Expected focused result:

```text
4 passed
```

## Safety Boundary

The scenario pack must remain:

- Fake-data-only.
- Local-route-only.
- No live SOAR, LLM, cloud, enrichment, or remediation calls.
- No real organization, workplace, tenant, user, host, domain, IP, or secret
  values.
- No HIPAA/HITRUST compliance, certification, control-satisfied, or audit-ready
  claims.
