# 🎓 Lesson 07: The Filing Cabinet - SQLite, Config, And Identifiers

## 🛡️ Welcome Back, Persistence Engineer!

Where does ThreatPrism keep cases and reports during the demo? 🔍 Today we are exploring **SQLite persistence, configuration, and generated IDs** - the "filing cabinet" that keeps state across API calls.

Goal: understand how demo persistence works and where production hardening would be needed.

Time estimate: 40 minutes.

Prerequisites:

- Complete Lessons 00-06.
- Know basic SQLite concepts.

## 🎯 Learning Objectives

- Explain how `DATABASE_URL` becomes a SQLite path.
- Identify the tables created by `SQLiteRepository`.
- Save and load a case through the repository.
- Explain why Pydantic JSON is stored in SQLite.
- Read configuration defaults from environment variables.
- Generate ThreatPrism IDs.

## 🔍 What This Component Does

### ✅ Implemented Here

Primary files:

- `C:\Projects\ThreatPrismV2\src\threatprism\persistence\sqlite.py`
- `C:\Projects\ThreatPrismV2\src\threatprism\config.py`
- `C:\Projects\ThreatPrismV2\src\threatprism\ids.py`
- `C:\Projects\ThreatPrismV2\.env.example`

The current repo uses SQLite for demo persistence. Tests use `sqlite:///:memory:` so they do not write real files.

### Recommended (not implemented here)

- SQLAlchemy repository abstraction.
- Alembic migrations.
- PostgreSQL deployment profile.
- Encrypted storage for token mappings.
- Separate append-only audit log storage.
- Connection pooling and transaction management.

## 🧠 Real-World Analogy

SQLite is the local filing cabinet:

- Good for demos and local validation.
- Easy to inspect.
- Not the final records system for production.

## 🔗 Pipeline Context

```text
CaseService
  -> SQLiteRepository.save_case()
  -> SQLite cases table
  -> SQLiteRepository.get_case()
  -> CaseRecord.model_validate_json()
```

## 📝 Code Walkthrough: Settings

File: `C:\Projects\ThreatPrismV2\src\threatprism\config.py`

### Lines 7-15

```python
@dataclass(frozen=True)
class Settings:
    env: str = "demo"
    database_url: str = "sqlite:///./data/threatprism.db"
    api_auth_mode: str = "none"
    api_token: str | None = None
    llm_provider: str = "deterministic_demo"
    allow_real_actions: bool = False
```

Line-by-line:

1. Defaults are demo-safe.
2. `api_auth_mode` exists but auth enforcement is not implemented yet.
3. `llm_provider` defaults to deterministic mode.
4. `allow_real_actions` defaults to `False`.

### Lines 16-25

`Settings.from_env()` reads environment variables and parses `ALLOW_REAL_ACTIONS`.

Why: configuration can change behavior without editing code, but safe defaults remain in code.

## 📝 Code Walkthrough: SQLite Repository

File: `C:\Projects\ThreatPrismV2\src\threatprism\persistence\sqlite.py`

### Lines 17-22

```python
def sqlite_path_from_url(database_url: str) -> str:
    if database_url.startswith("sqlite:///"):
        return database_url.removeprefix("sqlite:///")
    if database_url == "sqlite:///:memory:":
        return ":memory:"
    return database_url
```

Why: the repository accepts a URL-like value but passes a filesystem path to `sqlite3`.

### Lines 36-71

`initialize()` creates four tables:

- `cases`
- `triage_reports`
- `analyst_feedback`
- `disagreement_records`

Each table stores a `payload_json` column. This is simple and demo-friendly.

⚠️ Shortcut: storing full JSON is easy for demos, but production reporting may need indexed fields and migrations.

### Lines 73-98

`save_case()` writes the full `CaseRecord` JSON. `get_case()` reads it and rebuilds a Pydantic model with `CaseRecord.model_validate_json(row[0])`.

Why: the schema remains the source of truth, even when storage is simple.

## 📝 Code Walkthrough: IDs

File: `C:\Projects\ThreatPrismV2\src\threatprism\ids.py`

### Lines 6-7

```python
def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"
```

Why: IDs are unique and readable by type: `case_`, `report_`, `audit_`, and so on.

## 🧪 Manual Verification

### 🔬 Exercise 1: Inspect Settings Defaults

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -c "from threatprism.config import Settings; s=Settings.from_env(); print(s.env); print(s.database_url); print(s.llm_provider); print(s.allow_real_actions)"
```

Expected output:

```text
demo
sqlite:///./data/threatprism.db
deterministic_demo
False
```

### 🔬 Exercise 2: Convert SQLite URLs

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -c "from threatprism.persistence.sqlite import sqlite_path_from_url; print(sqlite_path_from_url('sqlite:///./data/threatprism.db')); print(sqlite_path_from_url('sqlite:///:memory:'))"
```

Expected output:

```text
./data/threatprism.db
:memory:
```

### 🔬 Exercise 3: Generate A Typed ID

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -c "from threatprism.ids import new_id; value=new_id('case'); print(value.startswith('case_')); print(len(value) > 10)"
```

Expected output:

```text
True
True
```

### 🔬 Exercise 4: Save And Read Through SQLite

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -c "import json; from pathlib import Path; from threatprism.cases.service import CaseService; from threatprism.config import Settings; s=CaseService(Settings(database_url='sqlite:///:memory:')); a=s.create_case(json.loads(Path('examples/soar_payloads/generic_soar_case.json').read_text())); c=s.get_case(a.case_id); print(c.source_case_id); print(c.triage_status)"
```

Expected output:

```text
SOAR-100245
queued
```

## 📚 Interview Prep

**Q: Why use SQLite for this phase?**  
**A**: It keeps the demo locally runnable without external infrastructure while still proving persistence, model serialization, and API state transitions.

**Q: Why store JSON payloads in SQLite?**  
**A**: It is a pragmatic early slice choice. Pydantic models validate the shape, while SQLite stores full records with minimal schema overhead.

**Q: What would change for production?**  
**A**: Add a repository interface, PostgreSQL, migrations, indexed query fields, secure audit storage, and stronger transaction boundaries.

**Q: How are safe defaults enforced?**  
**A**: `Settings` defaults to `env='demo'`, `llm_provider='deterministic_demo'`, and `allow_real_actions=False`.

## 🎯 Key Takeaways

- SQLite is a demo persistence layer, not a final production database design.
- Settings are safe by default.
- Pydantic models remain the schema boundary.
- Tests use in-memory SQLite.
- IDs are prefixed UUID hex strings.

## 📋 Summary Reference Card

| Item | Value |
|---|---|
| Default DB | `sqlite:///./data/threatprism.db` |
| Test DB | `sqlite:///:memory:` |
| Repository | `SQLiteRepository` |
| Tables | `cases`, `triage_reports`, `analyst_feedback`, `disagreement_records` |
| Config file | `.env.example` |
| ID helper | `new_id(prefix)` |

## 🚀 Ready For Lesson 08?

Next, study testing, defense labs, and the next implementation slices.

Remember: simple persistence is acceptable when the architecture leaves room to harden later. 🛡️
