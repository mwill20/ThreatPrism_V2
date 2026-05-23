# 🎓 Lesson 10: The Control Room - Operational Read Models And Metrics

## 🛡️ Welcome Back, Operations Engineer!

How do analysts, managers, GRC reviewers, and auditors see what is happening without exposing raw sensitive values? 🔍 Today we are exploring **Operational Read Models & Metrics** - the "control room" that turns case data into safe, dashboard-ready backend responses.

Goal: understand how ThreatPrism exposes metrics, filtered queues, and detail views without building a dashboard or adding live integrations.

Time estimate: 50 minutes.

Prerequisites:

- Complete Lessons 00-09.
- Understand role views and demo auth from Lessons 05 and 09.
- Run commands from `C:\Projects\ThreatPrismV2`.

## 🎯 Learning Objectives

- Explain why read models are separate from source-of-truth case records.
- Run the operational read-model test suite.
- Trace `GET /metrics` from API route to service aggregation.
- Use `GET /cases/read-model` filters for manager and healthcare review queues.
- Inspect role-safe detail routes for evidence, timeline, MITRE, GRC, and audit events.
- Describe what is implemented here versus production observability best practices.

## 🔍 Plain-English Explanation

### ✅ Implemented Here

ThreatPrism now exposes safe operational read routes:

```text
Stored cases + reports + feedback + audit trail
  -> service aggregation
  -> Pydantic read models
  -> FastAPI JSON routes
  -> role-safe rendering when needed
```

Primary files:

- `C:\Projects\ThreatPrismV2\src\threatprism\cases\read_models.py`
- `C:\Projects\ThreatPrismV2\src\threatprism\cases\service.py`
- `C:\Projects\ThreatPrismV2\src\threatprism\api\app.py`
- `C:\Projects\ThreatPrismV2\src\threatprism\persistence\sqlite.py`
- `C:\Projects\ThreatPrismV2\tests\test_operational_read_models.py`
- `C:\Projects\ThreatPrismV2\docs\OPERATIONAL_READ_MODELS_AND_METRICS.md`

### Recommended (not implemented here)

- Frontend dashboard.
- Production SIEM export.
- Data warehouse or BI sync.
- Tamper-evident centralized audit storage.
- Long-term metric retention and alerting.
- Production IdP or API gateway authorization.

## 🧠 Real-World Analogy

Think of this slice like a SOC control room:

- The case database is the filing cabinet.
- Metrics are the wall monitors.
- Read models are the view-specific work queues.
- Detail routes are drill-down panels.
- Role-safe rendering is the privacy screen.

The control room helps people work, but it does not replace analyst judgment.

## 🔗 Pipeline Context

```text
POST /cases
  -> normalize and safeguard
  -> run deterministic triage
  -> save report and audit trail
  -> POST analyst feedback
  -> GET /metrics
  -> GET /cases/read-model
  -> GET /cases/{case_id}/evidence|timeline|mitre|grc-controls|audit-events
```

## 🎯 Key Concepts

### ✅ Implemented Here

| Concept | Meaning |
|---|---|
| Read model | A safe API response shape derived from stored case data. |
| Metrics model | Aggregated counts and averages from cases, reports, feedback, disagreements, and audit events. |
| Manager-review queue | `GET /cases/read-model?manager_review_required=true`. |
| Healthcare-review queue | `GET /cases/read-model?healthcare_review_required=true`. |
| Detail route | A route that returns one type of case detail, such as evidence or audit events. |
| Role-safe rendering | Applying `render_role_view()` to a response before returning it. |

### Recommended (not implemented here)

- Version read-model schemas independently once dashboards depend on them.
- Emit metrics to a metrics backend in production.
- Keep audit storage append-only or tamper-evident.
- Use service accounts and scoped access tokens for dashboard callers.

## 📝 Code Walkthrough: Pydantic Read Models

File: `C:\Projects\ThreatPrismV2\src\threatprism\cases\read_models.py`

### Operational metrics shape

```python
class OperationalMetrics(BaseModel):
    window: MetricsWindow = Field(default_factory=MetricsWindow)
    case_counts: CaseCountMetrics = Field(default_factory=CaseCountMetrics)
    triage: TriageStatusMetrics = Field(default_factory=TriageStatusMetrics)
    report_decisions: ReportDecisionMetrics = Field(default_factory=ReportDecisionMetrics)
    guardrails: GuardrailMetrics = Field(default_factory=GuardrailMetrics)
    disagreement: DisagreementMetrics = Field(default_factory=DisagreementMetrics)
    timing: TimingMetrics = Field(default_factory=TimingMetrics)
    grc: GrcMetrics = Field(default_factory=GrcMetrics)
```

This code does:

1. Defines one stable response object for `GET /metrics`.
2. Groups related metrics instead of returning one flat dictionary.
3. Uses default factories so empty systems still return complete JSON shapes.
4. Keeps metrics safe because it only returns counts, averages, and categories.

### Case-list envelope

```python
class CaseReadModelEnvelope(BaseModel):
    items: list[CaseReadModelItem]
    next_cursor: str | None = None
    total: int
    filters: dict[str, Any] = Field(default_factory=dict)
    role_view: dict[str, Any] | None = None
```

This code does:

1. Returns `items` for dashboard rows.
2. Keeps `total` separate from pagination.
3. Echoes applied `filters` so callers know what they requested.
4. Allows optional `role_view` metadata when role-safe rendering was applied.

### Recommended (not implemented here)

- Add explicit schema version fields before a real dashboard depends on this API.
- Add cursor pagination once case volume grows.
- Add policy version IDs to role-view metadata.

## 📝 Code Walkthrough: Metrics Aggregation

File: `C:\Projects\ThreatPrismV2\src\threatprism\cases\service.py`

### Main function

```python
def get_operational_metrics(
    self,
    start: datetime | None = None,
    end: datetime | None = None,
) -> OperationalMetrics:
    cases = self._cases_in_window(self.repository.list_cases(), start, end)
    feedback = [
        item
        for item in self.repository.list_feedback()
        if any(case.case_id == item.case_id for case in cases)
    ]
    disagreements = [
        item
        for item in self.repository.list_disagreements()
        if any(case.case_id == item.case_id for case in cases)
    ]
```

This code does:

1. Reads cases from SQLite.
2. Applies the optional time window.
3. Pulls feedback and disagreement rows for the same cases.
4. Keeps aggregation in the service layer so FastAPI routes stay thin.

### Guardrail and authorization counters

```python
for event in case.audit_trail:
    if event.event_type == "rehydration_denied":
        guardrails.rehydration_denied_events += 1
    elif event.event_type == "role_view_policy_applied":
        guardrails.role_view_policy_applied_events += 1
    elif event.event_type == "authorization_decision":
        if event.metadata.get("decision") == "allow":
            guardrails.authorization_allowed_events += 1
        elif event.metadata.get("decision") == "deny":
            guardrails.authorization_denied_events += 1
```

Why this matters:

- Metrics include security-control behavior, not only case volume.
- Authorization denials become visible without exposing credentials.
- Rehydration denials show where sensitive tokens stayed protected.

### ⚠️ Pitfall

Do not put raw evidence excerpts, token vault mappings, or request bodies into metrics. Metrics should summarize what happened, not recreate the case payload.

## 📝 Code Walkthrough: FastAPI Routes

File: `C:\Projects\ThreatPrismV2\src\threatprism\api\app.py`

### Metrics route

```python
@app.get("/metrics", response_model=OperationalMetrics)
def get_metrics(request: Request) -> OperationalMetrics:
    _authorized_global_view_role(request, "get_metrics", None)
    return _service(request).get_operational_metrics()
```

This code does:

1. Checks demo auth when `API_AUTH_MODE=demo_key`.
2. Returns aggregate metrics.
3. Avoids role-specific case detail in the metrics response.

### Read-model route

```python
@app.get("/cases/read-model", response_model=CaseReadModelEnvelope)
def list_case_read_models(
    request: Request,
    source: Source | None = None,
    status: CaseStatus | None = None,
    triage_status: TriageStatus | None = None,
    severity: Severity | None = None,
    determination: Determination | None = None,
    manager_review_required: bool | None = None,
    healthcare_review_required: bool | None = None,
    guardrail_blocked: bool | None = None,
    authorization_denied: bool | None = None,
    created_after: datetime | None = None,
    created_before: datetime | None = None,
    limit: int = 50,
    cursor: str | None = None,
    role: ViewRole | None = None,
) -> CaseReadModelEnvelope:
```

This code does:

1. Keeps `GET /cases` compatible.
2. Adds a dedicated filtered envelope for dashboard-style views.
3. Supports manager-review, healthcare-review, guardrail, and authorization-denied queues.
4. Accepts `role` as a view request, not as authority.

### Detail routes

Implemented route family:

```text
GET /cases/{case_id}/evidence
GET /cases/{case_id}/timeline
GET /cases/{case_id}/mitre
GET /cases/{case_id}/grc-controls
GET /cases/{case_id}/audit-events
```

Each route calls `_authorized_view_role()` before service rendering when demo auth is enabled.

## 🧪 Manual Verification

### 🔬 Exercise 1: Run The Read-Model Tests

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest tests\test_operational_read_models.py -q -p no:cacheprovider --basetemp .pytest_tmp_lesson10_readmodels
```

Expected output:

```text
5 passed
```

### 🔬 Exercise 2: Run The Full Suite

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_lesson10_full
```

Bash:

```bash
cd /c/Projects/ThreatPrismV2
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_lesson10_full
```

Expected output:

```text
34 passed
```

### 🔬 Exercise 3: Inspect Metrics From The API

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -c "from fastapi.testclient import TestClient; from threatprism.api.app import create_app; from threatprism.config import Settings; app=create_app(Settings(env='test', database_url='sqlite:///:memory:', llm_provider='deterministic_demo', allow_real_actions=False)); c=TestClient(app); payload={'source_case_id':'SOAR-LESSON10-001','title':'Suspicious sign-in followed by mailbox rule creation','description':'SOAR closed this fake case after automated checks.','events':[{'event_type':'signin','description':'Successful sign-in from unfamiliar location.'}],'evidence':[{'evidence_id':'ev-001','summary':'Identity sign-in log shows suspicious mailbox activity.'}]}; r=c.post('/cases', json=payload); print(r.status_code); print(c.get('/metrics').json()['case_counts']['total'])"
```

Expected output:

```text
202
1
```

### 🔬 Exercise 4: Prove Demo Auth Protects Read Models

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest tests\test_operational_read_models.py::test_read_model_auth_denial_and_safe_audit_event_details -q -p no:cacheprovider --basetemp .pytest_tmp_lesson10_auth
```

Expected output:

```text
1 passed
```

## 📚 Interview Prep

**Q: Why add `GET /cases/read-model` instead of changing `GET /cases`?**  
**A**: The existing route was already used by tests and demos. Adding a companion envelope route gives dashboards a stable filtered shape without breaking compatibility.

**Q: Why are metrics in the service layer instead of the FastAPI route?**  
**A**: The route should handle HTTP concerns. The service owns business aggregation, making the logic easier to test without FastAPI.

**Q: What sensitive data should never appear in these read models?**  
**A**: Raw potential PHI/ePHI, secrets, full credentials, raw payload bodies, and token vault mappings. Read models should summarize or tokenize, not expose raw sensitive values.

**Q: How does this slice support future dashboards?**  
**A**: It provides stable JSON contracts for metrics, queues, and details. A frontend can consume those routes later without changing core triage logic.

**Q: What is still missing for production observability?**  
**A**: Durable metric retention, SIEM export, dashboard auth integration, alerting, audit immutability, and production deployment hardening.

## 🎯 Key Takeaways

- `GET /metrics` returns safe aggregate operational data.
- `GET /cases/read-model` is the dashboard-ready filtered envelope route.
- Detail routes expose evidence, timeline, MITRE, GRC, and audit events.
- Role-aware read routes reuse demo auth and role-safe rendering.
- This slice is backend-only and fake-data-only.
- Metrics/read models do not replace production monitoring or compliance reporting.

## 📋 Summary Reference Card

| Item | Details |
|---|---|
| Main models | `OperationalMetrics`, `CaseReadModelEnvelope`, `CaseReadModelItem`, `SafeAuditEvent` |
| Main service methods | `get_operational_metrics()`, `list_case_read_models()`, `get_evidence_view()`, `get_audit_events_view()` |
| Main routes | `/metrics`, `/cases/read-model`, `/cases/{case_id}/evidence`, `/timeline`, `/mitre`, `/grc-controls`, `/audit-events` |
| Filters | `source`, `status`, `triage_status`, `severity`, `determination`, `manager_review_required`, `healthcare_review_required`, `guardrail_blocked`, `authorization_denied` |
| Auth behavior | `API_AUTH_MODE=demo_key` requires fake demo credentials |
| Test file | `tests/test_operational_read_models.py` |
| Validation | `34 passed` |

## 🚀 Ready For The Next Slice?

Next, build **Evaluation Harness & Defense Labs v0.1** from `docs/specs/11_EVALUATION_PLAN.md`.

Hands-on challenges:

- Add one fake prompt-injection eval fixture.
- Add one fake healthcare-safeguard leakage eval fixture.
- Add one expected-output record that proves real remediation stays disabled.

Remember: operational visibility is only useful when it stays safe by default. 🛡️
