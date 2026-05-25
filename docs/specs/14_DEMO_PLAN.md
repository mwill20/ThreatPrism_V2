# 14 Demo Plan

## Demo Goal

Show how ThreatPrism helps an internal SOC validate SOAR automation and analyst decisions during a migration from outsourced SOC operations to an internal SOC model.

## Demo Safety Rules

- Use fake data only.
- Do not use live SOAR credentials.
- Do not use real customer payloads.
- Do not execute real remediation.
- Keep `ALLOW_REAL_ACTIONS=false`.
- Use dry-run or fixture-backed AI behavior when live provider keys are unavailable.

## Demo Scenario

Scenario: a generic SOAR platform automatically closed a suspicious identity case. ThreatPrism ingests the case, normalizes evidence, runs AI-assisted triage with guardrails, produces a structured report, and records analyst feedback showing whether the analyst agrees.

## Demo Payloads

Implemented fake SOAR payloads:

```text
examples/soar_payloads/generic_soar_case.json
examples/soar_payloads/sentinel_incident.json
examples/soar_payloads/defender_xdr_alert.json
examples/soar_payloads/logic_apps_webhook_payload.json
examples/soar_payloads/swimlane_case_mock.json
```

Implemented demo scenario pack:

```text
examples/demo_scenarios/demo_scenario_pack.json
examples/demo_scenarios/healthcare_safeguard_review_case.json
```

The scenario pack covers analyst, manager/GRC, legal/privacy, audit/debug, and
engineer workflows.

## Demo Flow

1. Start API in demo mode.
2. Confirm `GET /health`.
3. Submit `generic_soar_case.json` to `POST /cases`.
4. Receive `case_id`, `tracking_id`, and `triage_status: queued`.
5. Poll or fetch `GET /cases/{case_id}` until triage is complete.
6. Fetch `GET /cases/{case_id}/triage-report`.
7. Review evidence, timeline, IOCs, MITRE mappings, GRC mappings, limitations, and simulated actions.
8. Submit analyst feedback to `POST /cases/{case_id}/analyst-feedback`.
9. Review disagreement metrics.
10. Show manager-facing summary metrics.

## Example Commands For Future Implementation

PowerShell:

```powershell
$body = Get-Content .\examples\soar_payloads\generic_soar_case.json -Raw
Invoke-RestMethod -Method Post -Uri http://localhost:8000/cases -ContentType "application/json" -Body $body
```

bash:

```bash
curl -sS -X POST http://localhost:8000/cases \
  -H 'Content-Type: application/json' \
  --data @examples/soar_payloads/generic_soar_case.json
```

## Expected Demo Outputs

Case acceptance:

```json
{
  "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
  "tracking_id": "triage_01JZ7NQ2VBE3D9HB4C2M9P3VMF",
  "triage_status": "queued"
}
```

Triage summary:

```json
{
  "determination": "suspicious",
  "severity": "high",
  "disposition": "escalate",
  "confidence": 0.84,
  "analyst_review_required": true
}
```

Disagreement summary:

```json
{
  "determination_mismatch": true,
  "severity_mismatch": true,
  "disposition_mismatch": true,
  "manager_review_required": true
}
```

## Demo Narrative

The demo should emphasize:

- ThreatPrism does not replace analysts.
- ThreatPrism does not execute response actions.
- ThreatPrism catches possible misses in automation or analyst handling.
- Evidence is traceable.
- GRC mapping is evidence organization, not a compliance claim.
- The backend is ready for a future dashboard.

## Demo Completion Criteria

- Health endpoint works.
- Fake SOAR payload is accepted.
- Case is normalized.
- Triage job status is visible.
- Report is structured and evidence-linked.
- Simulated actions show no real action execution.
- Analyst feedback records disagreement metrics.
- Missing enrichment keys do not break the demo.
- Scenario-pack smoke tests pass.
- OpenAPI contract tests confirm the current backend route surface.
