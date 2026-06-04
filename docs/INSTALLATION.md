# Installation

This document covers setting up ThreatPrism for local development, running
the API server, and verifying the installation.

---

## Prerequisites

- **Python 3.11 or later** - required by `pyproject.toml`
  (`requires-python = ">=3.11"`). The codebase uses `StrEnum`, `X | Y` union
  syntax, and other 3.11+ features.
- **Git** - for cloning the repository.
- **Windows recommended** - the project was developed on Windows 11. All
  documented commands use PowerShell syntax. The code itself is
  platform-independent, but test validation commands and paths reference
  Windows conventions.

No external services are required. ThreatPrism uses an in-memory SQLite
database for tests and a local file-backed SQLite database for the API server.
No LLM API keys, cloud credentials, or network access are needed for local
development.

---

## Setup

### 1. Clone the repository

```powershell
git clone https://github.com/mwill20/ThreatPrism_V2.git C:\Projects\ThreatPrismV2
Set-Location C:\Projects\ThreatPrismV2
```

### 2. Create a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

On Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

This installs the direct dependencies pinned in `requirements.txt`:

| Package | Purpose |
|---------|---------|
| `fastapi==0.115.12` | API framework |
| `pydantic==2.11.2` | Data validation and serialization |
| `uvicorn==0.34.2` | ASGI server for running FastAPI |
| `pytest==8.3.4` | Test framework |
| `httpx==0.28.1` | HTTP client used by FastAPI's `TestClient` |
| `cryptography==44.0.2` | Local fake-JWKS JWT signature verification |

### 4. Copy the environment template

```powershell
Copy-Item .env.example .env
```

The `.env` file is gitignored. The defaults in `.env.example` are safe for
local development - all credentials are empty or fake demo values.

---

## Verify the Installation

### Run safe validation

Use the project validation wrapper first:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

Expected current result: see the canonical baseline in
[`docs/VALIDATION_BASELINE.md`](VALIDATION_BASELINE.md).

### Run the test suite directly

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_verify
```

Expected current result: see the canonical baseline in
[`docs/VALIDATION_BASELINE.md`](VALIDATION_BASELINE.md).

If Windows locks a pytest cache directory, use a fresh `--basetemp`:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_verify
```

### Run a single test

```powershell
pytest tests/test_api_flow.py::test_generic_soar_case_flow_and_feedback -v
```

### Run the eval harness

```powershell
$env:PYTHONPATH='src'
python -m threatprism.evals.cli
```

This reads fixtures from `tests/evals/`, evaluates them against the guardrail
pipeline, and writes sanitized result artifacts to `.eval_runs/`. All fixtures
should pass.

---

## Run the API Server

### Start the server

```powershell
$env:PYTHONPATH='src'
$env:ALLOW_REAL_ACTIONS='false'
$env:API_AUTH_MODE='none'
$env:THREATPRISM_LOCAL_DEV_ACK='true'
python -m uvicorn threatprism.api.app:create_app --factory --reload
```

Or using the CLI module:

```powershell
$env:PYTHONPATH='src'
$env:ALLOW_REAL_ACTIONS='false'
$env:API_AUTH_MODE='none'
$env:THREATPRISM_LOCAL_DEV_ACK='true'
python -m threatprism.cli.main
```

The server starts at `http://127.0.0.1:8000` by default.

The CLI module accepts `--host` and `--port` arguments:

```powershell
python -m threatprism.cli.main --host 0.0.0.0 --port 9000
```

### Verify the server is running

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Expected response:

```json
{
  "status": "ok",
  "service": "threatprism-api",
  "version": "0.1.0",
  "mode": "demo",
  "allow_real_actions": false
}
```

## Run With Docker Compose

```powershell
docker compose up --build
```

The Compose service starts the backend at `http://127.0.0.1:8000` with fake
demo API keys, deterministic demo triage, empty live-provider credentials, and
`ALLOW_REAL_ACTIONS=false`.

Stop the service:

```powershell
docker compose down
```

### Submit a demo case

```powershell
$payload = Get-Content -Raw .\examples\soar_payloads\generic_soar_case.json | ConvertFrom-Json
$created = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/cases -Body ($payload | ConvertTo-Json -Depth 20) -ContentType 'application/json'
$created
```

### Fetch the triage report

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/cases/$($created.case_id)/triage-report"
```

---

## Configuration

All configuration is through environment variables. No config files are used
at runtime.

### Core settings

| Variable | Default | Description |
|----------|---------|-------------|
| `THREATPRISM_ENV` | `demo` | Environment name. Setting to `prod` or `production` activates the runtime guard that rejects demo auth modes. |
| `DATABASE_URL` | `sqlite:///./data/threatprism.db` | SQLite database path. Tests use `sqlite:///:memory:`. |
| `LLM_PROVIDER` | `deterministic_demo` | Triage provider. Only `deterministic_demo` is implemented. |
| `ALLOW_REAL_ACTIONS` | `false` | Action safety switch. Must remain `false` in V2. |

### Authentication settings

| Variable | Default | Description |
|----------|---------|-------------|
| `API_AUTH_MODE` | `none` | Auth mode: `none` (all callers get admin only when explicitly acknowledged for local development) or `demo_key` (credential-based role mapping). `.env.example` uses `demo_key`. |
| `API_TOKEN` | (empty) | Reserved for future auth modes. Not currently used. |
| `DEMO_API_KEYS` | (empty unless configured) | Comma-separated list of `credential:identity:role` entries for demo auth. Required when `API_AUTH_MODE=demo_key`. |
| `THREATPRISM_AUTH_REQUIRED` | `true` | When true, disabled auth is rejected unless local development is explicitly acknowledged. |
| `THREATPRISM_LOCAL_DEV_ACK` | `false` | Must be `true` to run `API_AUTH_MODE=none` for local fake-data development. |
| `DEMO_ROLE_OVERRIDE_ENABLED` | `false` | Reserved. Not currently used. |

### API resource controls

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_REQUEST_BODY_BYTES` | `262144` | Maximum accepted `POST /cases` request body size. Oversized bodies return HTTP 413. |
| `CASE_POST_RATE_LIMIT_PER_MINUTE` | `60` | In-process per-client `POST /cases` rate limit. Bursts beyond this return HTTP 429. |
| `TRIAGE_CONCURRENCY_LIMIT` | `4` | In-process cap for concurrent background triage runs. |

### Threat intelligence settings (stubs)

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | (empty) | Not used with `deterministic_demo` provider. |
| `LOCAL_LLM_BASE_URL` | (empty) | Not used with `deterministic_demo` provider. |
| `VIRUSTOTAL_API_KEY` | (empty) | Stub returns `not_configured` when empty. |
| `URLSCAN_API_KEY` | (empty) | Stub returns `not_configured` when empty. |
| `ABUSEIPDB_API_KEY` | (empty) | Stub returns `not_configured` when empty. |
| `WHOIS_RDAP_PROVIDER` | `default` | Stub returns `not_configured`. |

### Using demo API-key authentication

To enable role-based access control for the demo:

```powershell
$env:API_AUTH_MODE='demo_key'
```

Then pass a demo key with requests:

```powershell
# As analyst
Invoke-RestMethod -Headers @{ 'X-ThreatPrism-Demo-Key' = 'demo-analyst-key' } `
  -Uri "http://127.0.0.1:8000/cases/$($created.case_id)/triage-report?role=analyst"

# As manager/GRC (security telemetry will be masked)
Invoke-RestMethod -Headers @{ 'X-ThreatPrism-Demo-Key' = 'demo-manager-key' } `
  -Uri "http://127.0.0.1:8000/cases/$($created.case_id)/triage-report?role=manager_grc"
```

Available demo keys (from `.env.example`):

| Key | Identity | Role |
|-----|----------|------|
| `demo-analyst-key` | `demo_analyst` | `analyst` |
| `demo-engineer-key` | `demo_engineer` | `engineer` |
| `demo-manager-key` | `demo_manager` | `manager_grc` |
| `demo-legal-key` | `demo_legal` | `legal_privacy` |
| `demo-audit-key` | `demo_audit` | `audit_debug` |
| `demo-admin-key` | `demo_admin` | `admin` |

---

## Project Layout

```
C:\Projects\ThreatPrismV2\
├── src/threatprism/          Application source
│   ├── api/                  FastAPI routes
│   ├── auth/                 Demo authentication and authorization
│   ├── cases/                Case model, service, schemas, read models
│   ├── cli/                  CLI entry point
│   ├── enrichment/           Threat intel stubs
│   ├── evals/                Eval harness runner and schemas
│   ├── grc/                  GRC control mapping
│   ├── guardrails/           Prompt firewall, tokenization, policy, views
│   ├── llm/                  LLM provider protocol and demo implementation
│   ├── mitre/                MITRE ATT&CK mapping
│   ├── persistence/          SQLite repository
│   ├── reports/              Report rendering
│   └── soar/                 SOAR payload adapters
├── tests/                    pytest test suite
│   └── evals/                Eval fixture JSONL files
├── examples/soar_payloads/   Demo SOAR payload JSON files
├── docs/                     Architecture, specs, and operational docs
│   └── specs/                Per-component specification documents
├── Lessons/                  Educational curriculum
├── data/                     SQLite database (gitignored, created at runtime)
├── .eval_runs/               Eval output artifacts (gitignored)
├── requirements.txt          Python dependencies
├── pyproject.toml            Project metadata and pytest config
├── .env.example              Environment variable template
└── .gitignore                Excludes .env, data/, .eval_runs/, caches
```

---

## Troubleshooting

### `ModuleNotFoundError: No module named 'threatprism'`

The `src/` layout requires either:
- `PYTHONPATH=src` set in the environment, or
- `pytest` to be run from the project root (pytest reads `pythonpath = ["src"]`
  from `pyproject.toml` automatically)

### pytest cache directory locked on Windows

Windows sometimes locks `__pycache__` or `.pytest_cache` directories. Use a
fresh `--basetemp`:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_fresh
```

### `FileNotFoundError` on `examples/soar_payloads/generic_soar_case.json`

Tests that submit demo SOAR payloads load fixture files from the `examples/`
directory. Run tests from the project root directory, not from `tests/` or
`src/`.

### SQLite `data/` directory

The API server creates `data/threatprism.db` on first run. The `data/`
directory is gitignored. If you delete it, the server recreates it
automatically on the next startup.

### Production environment startup failure

If `THREATPRISM_ENV` is set to `prod` or `production`,
`Settings.validate_runtime()` will reject `API_AUTH_MODE=none` and
`API_AUTH_MODE=demo_key` with:

```
ValueError: Production environments cannot use disabled or demo API authentication.
```

This is intentional. Production-like environments must use the static
`external_oidc` readiness mode. Live production token verification is not yet
implemented.

Outside production, `API_AUTH_MODE=demo_key` also fails closed unless
`DEMO_API_KEYS` is configured, and `API_AUTH_MODE=none` fails closed unless
`THREATPRISM_LOCAL_DEV_ACK=true` or auth is explicitly disabled for tests.
