# 🎓 Lesson 02: The Air Traffic Controller - Case Schemas And Service Orchestration

## 🛡️ Welcome Back, Case Dispatcher!

What keeps a security case from becoming a pile of loose JSON? 🔍 Today we are exploring **case schemas and the service layer** - the "air traffic controller" that moves cases through intake, safeguards, triage, validation, feedback, and persistence.

Goal: understand the central data model and the workflow orchestrator.

Time estimate: 50 minutes.

Prerequisites:

- Complete Lessons 00 and 01.
- Know basic Pydantic model validation.

## 🎯 Learning Objectives

- Explain the core `CaseRecord` and `TriageReport` schemas.
- Trace `CaseService.create_case()` from payload to persisted record.
- Trace `CaseService.run_triage()` from queued case to validated report.
- Describe how analyst feedback becomes disagreement metrics.
- Identify audit events created during the workflow.
- Spot where guardrails plug into orchestration.

## 🔍 What This Component Does

### ✅ Implemented Here

Primary files:

- `C:\Projects\ThreatPrismV2\src\threatprism\cases\schemas.py`
- `C:\Projects\ThreatPrismV2\src\threatprism\cases\service.py`

`schemas.py` defines the domain vocabulary: case status, triage status, evidence, IOCs, findings, reports, feedback, disagreement, and audit events.

`service.py` orchestrates the workflow:

```text
payload -> normalize -> hash -> create CaseRecord -> healthcare scan -> save
case -> tokenized model input -> provider report -> guardrail checks -> report
feedback -> disagreement metrics -> audit trail
```

### Recommended (not implemented here)

- Separate repository interface protocol for easier mocking.
- Transaction boundaries around multi-table updates.
- Durable background job state with retries.
- Dedicated authorization context passed into service methods.

## 🧠 Real-World Analogy

The service layer is an air traffic controller:

- Cases are planes.
- Guardrails are safety checks.
- The repository is the runway log.
- The report provider is a specialized review crew.
- The service decides when each step can proceed.

## 🎯 Key Concepts

### ✅ Implemented Here

| Concept | File And Lines | Why It Matters |
|---|---|---|
| `Source` | `schemas.py` lines 16-25 | Restricts known case sources. |
| `CaseStatus` | `schemas.py` lines 27-36 | Tracks lifecycle state. |
| `TriageStatus` | `schemas.py` lines 39-45 | Tracks analysis state. |
| `Provenance` | `schemas.py` lines 76-87 | Preserves source traceability. |
| `Evidence` | `schemas.py` lines 124-133 | Grounds report claims. |
| `TriageReport` | `schemas.py` lines 205-228 | Defines structured output. |
| `AuditEvent` | `schemas.py` lines 266-273 | Creates internal paper trail. |

### Recommended (not implemented here)

- Include request identity and authorization decision fields in audit events.
- Use immutable audit storage for production.
- Add schema version migration strategy for long-lived records.

## 📝 Code Walkthrough: Key Schemas

### `Provenance`, lines 76-87

```python
class Provenance(BaseModel):
    source_file: str | None = None
    record_index: int | None = Field(default=None, ge=0)
    source_event_id: str | None = None

    @field_validator("source_event_id", mode="before")
    @classmethod
    def coerce_source_event_id(cls, value: Any) -> str | None:
        if value is None:
            return None
        return str(value)
```

Line-by-line:

1. `source_file` records where the evidence came from.
2. `record_index` keeps batch position and must be non-negative.
3. `source_event_id` preserves a source-specific ID.
4. The validator safely coerces event IDs to strings.

Why: provenance lets ThreatPrism say "this finding came from this evidence," which is essential for SOC review and GRC mapping.

### `TriageReport`, lines 205-228

```python
class TriageReport(BaseModel):
    report_id: str = Field(default_factory=lambda: new_id("report"))
    case_id: str
    report_version: int = 1
    status: TriageStatus = TriageStatus.completed
    summary: str
    determination: Determination
    severity: Severity
    disposition: Disposition
    confidence: float = Field(..., ge=0.0, le=1.0)
```

Line-by-line:

1. `report_id` gets a generated ID.
2. `case_id` ties the report back to a case.
3. `confidence` is bounded from 0.0 to 1.0.
4. Enumerations constrain output vocabulary.

Why: LLM or provider output is not trusted until it fits a strict schema.

## 📝 Code Walkthrough: Service Workflow

### `create_case()`, lines 43-81

```python
def create_case(self, payload: dict[str, Any]) -> CaseAcceptedResponse:
    case_create = normalize_soar_payload(payload)
    source_hash = _payload_hash(payload)
    case_id = new_id("case")
    case = CaseRecord.model_validate(
        {
            **case_create.model_dump(mode="json", exclude_none=True),
            "case_id": case_id,
            "source_payload_hash": f"sha256:{source_hash}",
            "status": CaseStatus.queued_for_triage,
            "triage_status": TriageStatus.queued,
```

Line-by-line:

1. Normalize first, so business logic uses `CaseCreate`.
2. Hash the original payload for traceability without relying on raw payload storage.
3. Generate a case ID.
4. Validate the full `CaseRecord`.
5. Set lifecycle state to queued.

### `run_triage()`, lines 129-151

```python
tokenized_case, records, vault = self._prepare_case_for_model(case)
case.sanitization_records.extend(records)

report = self.provider.generate_report(tokenized_case)
issues = []
issues.extend(scan_output_policy(report.model_dump(mode="json")))
issues.extend(validate_report_evidence(report, {item.evidence_id for item in tokenized_case.evidence}))
issues.extend(enforce_action_safety(report.model_dump(mode="json")))

if issues:
    case.status = CaseStatus.needs_analyst_review
    case.triage_status = TriageStatus.blocked_by_guardrail
```

Why this is important:

- The provider sees a tokenized case.
- Output is checked for policy, evidence, and action safety.
- Any issue blocks report persistence.

### `_disagreement()`, lines 311-346

This method compares analyst feedback to the ThreatPrism report:

- Determination mismatch.
- Severity mismatch.
- Disposition mismatch.
- Confidence delta.
- Manager review trigger.

Why: disagreement tracking turns analyst feedback into management and process-improvement signals.

## 🧪 Manual Verification

### 🔬 Exercise 1: Validate A Case Payload Through The Service

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -c "import json; from pathlib import Path; from threatprism.cases.service import CaseService; from threatprism.config import Settings; s=CaseService(Settings(database_url='sqlite:///:memory:')); a=s.create_case(json.loads(Path('examples/soar_payloads/generic_soar_case.json').read_text())); print(a.status); print(a.triage_status); print(a.links['triage_report'].startswith('/cases/case_'))"
```

Expected output:

```text
queued_for_triage
queued
True
```

### 🔬 Exercise 2: Run Triage And Print Report Status

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -c "import json; from pathlib import Path; from threatprism.cases.service import CaseService; from threatprism.config import Settings; s=CaseService(Settings(database_url='sqlite:///:memory:')); a=s.create_case(json.loads(Path('examples/soar_payloads/generic_soar_case.json').read_text())); s.run_triage(a.case_id); r=s.get_report(a.case_id); print(r.status); print(r.severity); print(r.disposition)"
```

Expected output:

```text
completed
high
escalate
```

### 🔬 Exercise 3: Intentional Guardrail Failure

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest tests\test_guardrail_failures.py -q -p no:cacheprovider --basetemp .pytest_tmp_lesson02_failures
```

Expected output:

```text
3 passed
```

## 📚 Interview Prep

**Q: Why use Pydantic schemas for triage reports?**  
**A**: They constrain output shape and values before the report is trusted or persisted. This is important because model output can be malformed, unsupported, or unsafe.

**Q: Why does `CaseService` hash the raw payload?**  
**A**: The hash gives a stable reference to the source input without needing to expose raw payload contents in every downstream object.

**Q: What happens when guardrail checks fail?**  
**A**: The case is marked `needs_analyst_review`, triage becomes `blocked_by_guardrail`, an audit event records the issues, and the report is not saved.

**Q: Why track analyst disagreement?**  
**A**: It converts human review into measurable QA signals: mismatches, missed escalation, false positives, and manager-review triggers.

## 🎯 Key Takeaways

- `schemas.py` defines the language of the system.
- `service.py` controls workflow order.
- Tokenization happens before provider analysis.
- Reports are saved only after policy, evidence, and action-safety checks pass.
- Analyst feedback is part of the product, not an afterthought.

## 📋 Summary Reference Card

| Item | Details |
|---|---|
| Input | Raw SOAR payload dictionary. |
| Case model | `CaseRecord`. |
| Report model | `TriageReport`. |
| Main orchestrator | `CaseService`. |
| Failure behavior | Guardrail issue blocks report persistence. |
| Dependencies | SOAR adapter, healthcare guardrails, tokenization, provider, repository. |

## 🚀 Ready For Lesson 03?

Next, study the SOAR intake translator. That is where provider-specific JSON becomes a ThreatPrism case.

Remember: structured cases are what make evidence-first analysis possible. 🛡️

---

## ⚖️ Decisions & Trade-offs

### Decisions Touched

| Decision | Statement | Why It Matters Here |
|----------|-----------|---------------------|
| D-010 | V2 permits recommended/simulated actions only; `ALLOW_REAL_ACTIONS=false` by default | `enforce_action_safety()` is the last check before `save_report()`; the schema's `real_action_executed` field exists precisely to be blocked |
| D-011 | V2 must use layered guardrails with fail-closed behavior | `CaseService.run_triage()` applies healthcare, prompt firewall, tokenization, output policy, evidence, and action-safety in a fixed order; any failure sets `blocked_by_guardrail` |
| D-012 | Demo mode uses SQLite; designed so PostgreSQL can be added later | `SQLiteRepository` stores full Pydantic blobs; `CaseService` depends on the repository interface, not the SQLite implementation directly |
| D-015 | V2 preserves V1 concepts: Pydantic-style structured validation, deterministic report rendering, SQLite demo persistence | `CaseRecord` and `TriageReport` use Pydantic; reports render deterministically from schema fields, not from LLM prose |
| D-016 | First vertical slice: Generic SOAR → normalize → async triage → structured report → feedback | The entire `CaseService` lifecycle was shaped by this decision; the class implements exactly this flow |
| D-019 | Current demo uses FastAPI in-process background tasks for triage execution | `run_triage()` runs as a `BackgroundTask`; this is why `POST /cases` returns 202 and tests can immediately read results via `TestClient` |

### What We Explicitly Rejected

- **SQLAlchemy ORM:** An ORM generates SQL schema from model classes, requiring migration tooling when Pydantic models change. The JSON-blob approach lets `CaseRecord` evolve without SQL migrations — Pydantic is the schema boundary, not the database.
- **Synchronous triage in the request handler:** Blocking the HTTP response on triage execution would make `POST /cases` appear to hang for large payloads. D-019 chose in-process background tasks so the 202 Accepted response is immediate.
- **Normalized SQL columns for every case field:** Individual columns for `severity`, `disposition`, `findings`, etc. would require a migration on every schema addition. The denormalized index columns (`case_id`, `source`, `status`, `triage_status`, `created_at`, `updated_at`) provide query anchors; the blob provides the full record.

### Trade-off Log

| Choice Made | What We Gained | What We Gave Up |
|-------------|----------------|-----------------|
| JSON blob in SQLite | Schema evolution without migrations; Pydantic stays the single schema truth | No SQL-level queries on payload fields; all filtering happens in Python after deserialization |
| In-process `BackgroundTask` for triage | No infra deps; `TestClient` executes triage synchronously before returning, so tests require no polling | No worker isolation; no retry/backoff on triage failure; a hung triage occupies that thread |
| Single `CaseService` orchestrator | All pipeline stages visible and sequenced in one class; the full flow is traceable in one file | Monolithic for POC scope; harder to scale individual pipeline stages independently |
| `StrEnum` for status fields | Self-documenting API; serializes as plain string in JSON; exhaustiveness checks at schema level | Enum additions require code changes; unused values accumulate until explicitly removed |

### Future Gate Conditions

This component's design would change if:

- **A dedicated queue/worker is added** → re-opens D-019; `run_triage()` becomes a worker entrypoint and the in-process `BackgroundTask` pattern is retired
- **PostgreSQL is added** → re-opens D-012; `SQLiteRepository` must implement a shared interface; the JSON-blob strategy needs reconsideration for query performance on large case volumes

### Limitations in Scope

- `[Demo-Safe Boundary]` In-process background tasks are sufficient for single-org fake-data demo; a separate worker and queue should be considered after API, persistence, guardrails, and demo workflow are stable (D-019)
- `[Gated Future Work]` PostgreSQL or other production-grade persistence requires its own implementation slice with migration tooling
