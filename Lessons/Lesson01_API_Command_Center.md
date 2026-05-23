# 🎓 Lesson 01: The Command Center - FastAPI And CLI Entry Points

## 🛡️ Welcome Back, API Responder!

How does a fake SOAR case become a ThreatPrism case and report? 🔍 Today we are exploring the **API layer** - the "command center" that receives requests and routes them to the case service.

Goal: understand the API routes, CLI runner, and how tests prove the basic workflow.

Time estimate: 35 minutes.

Prerequisites:

- Complete Lesson 00.
- Dependencies installed.
- Run commands from `C:\Projects\ThreatPrismV2`.

## 🎯 Learning Objectives

- Identify every currently implemented API route.
- Explain how `create_app()` wires settings and service state.
- Trace the `/cases` request into `CaseService.create_case()`.
- Describe why background triage is used.
- Run the API flow tests.
- Recognize the current role-view limitation.

## 🔍 What This Component Does

### ✅ Implemented Here

`C:\Projects\ThreatPrismV2\src\threatprism\api\app.py` defines the FastAPI app and these routes:

- `GET /health`
- `POST /cases`
- `GET /cases`
- `GET /cases/{case_id}`
- `GET /cases/{case_id}/triage-report`
- `POST /cases/{case_id}/analyst-feedback`

`C:\Projects\ThreatPrismV2\src\threatprism\cli\main.py` starts the API with Uvicorn.

### Recommended (not implemented here)

- Production authentication middleware.
- Rate limiting.
- Request IDs and structured access logs.
- Strong typed response envelopes for every endpoint.
- OpenAPI examples for every route.

## 🧠 Real-World Analogy

The API is the SOC front desk:

- It receives a case.
- It gives the caller a tracking link.
- It sends the case to the internal reviewer.
- It returns reports and feedback status.

The front desk does not investigate by itself. It routes work to the right service.

## 🔗 Pipeline Context

```text
HTTP client or CLI
  -> FastAPI route
  -> CaseService
  -> repository / guardrails / provider
  -> JSON response
```

## 📝 Code Walkthrough: `create_app()`

File: `C:\Projects\ThreatPrismV2\src\threatprism\api\app.py`

### Lines 17-22

```python
def create_app(settings: Settings | None = None) -> FastAPI:
    active_settings = settings or Settings.from_env()
    app = FastAPI(title="ThreatPrism API", version=__version__)
    app.state.settings = active_settings
    app.state.case_service = CaseService(active_settings)
```

Line-by-line:

1. `settings` can be injected by tests.
2. `Settings.from_env()` is used for normal local runs.
3. `FastAPI(title="ThreatPrism API")` sets the public app name.
4. `app.state.case_service` shares one service instance with route handlers.

Why designed this way: app factories are easy to test because each test can build an app with an in-memory database.

### Lines 33-45

```python
@app.post("/cases", response_model=CaseAcceptedResponse, status_code=202)
def create_case(
    payload: dict,
    background_tasks: BackgroundTasks,
    request: Request,
) -> CaseAcceptedResponse:
    service = _service(request)
    try:
        accepted = service.create_case(payload)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    background_tasks.add_task(service.run_triage, accepted.case_id)
    return accepted
```

Line-by-line:

1. The route accepts raw JSON as `payload`.
2. `service.create_case(payload)` normalizes and persists the case.
3. Any normalization or validation error becomes HTTP 400.
4. `background_tasks.add_task(...)` schedules triage after the response starts.
5. The response is `202 Accepted`, not `200 OK`, because triage is asynchronous.

⚠️ Current shortcut: FastAPI background tasks are fine for demo mode. A production system would likely use a durable queue.

### Lines 51-80

```python
@app.get("/cases/{case_id}")
def get_case(case_id: str, request: Request, role: ViewRole | None = None) -> dict:
    if role is not None:
        view = _service(request).get_case_view(case_id, role)
        if view is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return view
```

Line-by-line:

1. `role` is currently a request parameter.
2. If present, the service renders a role-specific view.
3. If missing, the full case is returned.

⚠️ Important: in `API_AUTH_MODE=demo_key`, this route now derives the allowed role view from demo credentials before rendering.

## 🧪 Manual Verification

### 🔬 Exercise 1: Run The API Flow Tests

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest tests\test_api_flow.py -q -p no:cacheprovider --basetemp .pytest_tmp_lesson01
```

Expected output:

```text
2 passed
```

### 🔬 Exercise 2: Start The API Locally

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
$env:ALLOW_REAL_ACTIONS='false'
python -m uvicorn threatprism.api.app:create_app --factory --host 127.0.0.1 --port 8000
```

Expected output includes:

```text
Uvicorn running on http://127.0.0.1:8000
```

Stop it with `Ctrl+C`.

### 🔬 Exercise 3: Check Health In A Second PowerShell Window

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Expected fields:

```text
status             : ok
service            : threatprism-api
mode               : demo
allow_real_actions : False
```

### 🔬 Exercise 4: Intentional Failure

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -c "from threatprism.api.app import create_app; app=create_app(); print(app.title); print(len(app.routes) > 0)"
```

Expected output:

```text
ThreatPrism API
True
```

## 📚 Interview Prep

**Q: Why does `POST /cases` return 202 instead of 200?**  
**A**: Because intake and triage are separated. The API accepts and persists the case, then schedules triage as background work. This keeps the caller from waiting on analysis.

**Q: Why use an app factory?**  
**A**: `create_app(settings)` allows tests to inject safe in-memory settings while local runs use environment variables. It improves testability and keeps startup predictable.

**Q: What is risky about `?role=` today?**  
**A**: In local `API_AUTH_MODE=none`, it remains a demo view selector. In `API_AUTH_MODE=demo_key`, it is only a requested view; the effective role comes from the demo credential and unauthorized views are denied.

## 🎯 Key Takeaways

- `app.py` is thin routing code.
- `CaseService` owns business workflow.
- API tests use `TestClient` and in-memory SQLite.
- The CLI is currently a simple Uvicorn runner.
- Access control is now in place for role-aware case and report reads before dashboard/read-model expansion.

## 📋 Summary Reference Card

| Route | Purpose |
|---|---|
| `GET /health` | Service health and safety mode. |
| `POST /cases` | Accept SOAR payload and queue triage. |
| `GET /cases` | List case summaries. |
| `GET /cases/{case_id}` | Fetch case or role-rendered case view. |
| `GET /cases/{case_id}/triage-report` | Fetch report or pending status. |
| `POST /cases/{case_id}/analyst-feedback` | Record analyst feedback and disagreement. |

## 🚀 Ready For Lesson 02?

Next, study the case schemas and service orchestration. That is where the actual case lifecycle lives.

Remember: routes should stay thin; orchestration belongs in the service layer. 🛡️
