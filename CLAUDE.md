# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## Context-Light Startup

Do not paste large handoff docs into a new chat. Start with `START_HERE.md`,
then read only the specific files needed for the current task.

Required short read order:

1. `START_HERE.md`
2. `AGENTS.md`
3. `docs/THREATPRISM_V2_CODEX_HANDOFF.md`
4. `docs/WORKING_CHECKLIST.md`
5. `docs/ARCHITECTURAL_NORTH_STAR.md`

When context is approaching 75% used, or less than roughly 25% remains, output
a compact handoff prompt and update durable handoff files before continuing.

Generate the compact handoff prompt with:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\generate-compact-handoff.ps1
```

---

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run all tests
pytest

# Run a single test
pytest tests/test_api_flow.py::test_generic_soar_case_flow_and_feedback -v

# Run the API server
python -m threatprism.cli.main

# Run the eval suite
python -m threatprism.evals.cli

# Run evals against a specific fixture file
python -m threatprism.evals.cli --fixtures tests/evals/regression_cases.jsonl

# Generate a compact fresh-chat handoff prompt
powershell -ExecutionPolicy Bypass -File .\tools\generate-compact-handoff.ps1
```

Tests use `sqlite:///:memory:` — no local database required. The live database is at `data/threatprism.db` and is not used during tests.

Tests depend on example payloads at `examples/soar_payloads/` — these files must exist for the API flow tests to pass.

---

## Architecture

ThreatPrism is a SOC triage automation backend. It accepts SOAR case payloads, runs them through a multi-stage guardrail pipeline, generates a triage report, and returns role-filtered views of the results.

### Request lifecycle

```
POST /cases
  → normalize_soar_payload()       # SOAR adapter (source-specific normalization)
  → _apply_healthcare_safeguards() # PHI/PII/secret tokenization at intake
  → repository.save_case()         # persist with tokenized content
  → 202 Accepted

BackgroundTask: run_triage()
  → _prepare_case_for_model()      # prompt firewall + TokenVault (second tokenization pass)
  → provider.generate_report()     # deterministic demo or real LLM (Protocol)
  → scan_output_policy()           # regex guardrails on LLM output
  → validate_report_evidence()     # LLM must cite only provided evidence_ids
  → enforce_action_safety()        # blocks real_action_executed: true
  → _rehydrate_report()            # restore safe tokens; PHI/PII/SECRET stay redacted
  → repository.save_report()
```

GET endpoints poll for results. The triage report is not ready until the background task completes.

### Four-layer guardrail pipeline

The guardrails are not interchangeable — each layer catches a different class of problem, and they execute in a fixed order:

1. **Prompt firewall** (`guardrails/prompt_firewall.py`) — regex rules that detect and redact/quarantine prompt injection attempts in inbound text. Runs per-field during `_prepare_case_for_model()`. Quarantined content blocks triage.

2. **Healthcare safeguards** (`guardrails/healthcare.py`) — detects PHI, PII, and secrets at case intake (Stage 1 tokenization). Uses context-aware rules — some detectors (email, IP, URL) only fire when healthcare terms are present in the payload. Tokens are **never** rehydrated.

3. **Output policy** (`guardrails/policy.py`) — `PROHIBITED_PATTERNS` regex list scanned against the serialized report JSON. Catches overclaiming language (compliance/certification claims), action execution claims, leaked secrets, and clinical language.

4. **Evidence validation** (`guardrails/evidence.py`) — every `evidence_id` cited in findings, MITRE mappings, GRC controls, and hypotheses must exist in the case's evidence set. Prevents hallucinated citations.

If any layer returns issues, the case is set to `blocked_by_guardrail` and triage stops.

### Two tokenization stages — why both exist

**Stage 1 — Healthcare safeguard** (`guardrails/healthcare.py`): runs at case intake, before anything is stored. Detects PHI, PII, and secrets in the raw inbound payload and replaces them with typed tokens (`[POTENTIAL_PHI:SSN:phi_0001]`). These tokens are written to the database and never reversed.

**Stage 2 — Prompt firewall + TokenVault** (`guardrails/tokenization.py`): runs during triage prep, before the LLM sees the case. Tokenizes security telemetry (IPs, URLs, file hashes) that is safe to rehydrate after validation. The `TokenVault` tracks the mapping. After the report passes guardrail checks, `_rehydrate_report()` restores these tokens — but any Stage 1 typed tokens remain redacted permanently.

The `REHYDRATABLE_TYPES` set in `tokenization.py` controls which Stage 2 token types can be restored. `secret_like` is explicitly excluded.

### Role-based views

`render_role_view()` in `guardrails/views.py` masks content dynamically at read time — the database always stores the full record. Every role-view access generates an `AuditEvent`.

The masking logic: `analyst` and `engineer` roles see raw security telemetry (IPs, URLs, hashes, emails). All other roles (`manager_grc`, `legal_privacy`, `audit_debug`, `ai`) get security telemetry replaced with `[SECURITY_TELEMETRY:TYPE:masked]` tokens. Stage 1 typed tokens (`[POTENTIAL_PHI:...]`) remain visible to all roles but are never reversed.

Role → allowed ViewRoles mapping is in `auth/demo.py`:
- `analyst`: `{analyst, ai}`
- `engineer`: `{engineer, analyst, ai, audit_debug}`
- `manager_grc`: `{manager_grc, ai}`
- `legal_privacy`: `{legal_privacy, audit_debug, ai}`
- `admin`: all roles

### Persistence — JSON-blob-in-SQLite

`SQLiteRepository` stores full Pydantic models as JSON blobs in `payload_json` columns. The SQL columns (`case_id`, `source`, `status`, `triage_status`, `created_at`, `updated_at`) are denormalized indexes — the blob is the source of truth. To read a case, the repo deserializes the JSON blob back into a `CaseRecord`. This means schema changes to Pydantic models must be backwards-compatible with existing stored blobs, or a migration is needed.

In-memory mode (`sqlite:///:memory:`) uses a single persistent connection held on the repository instance. File-backed mode creates a new connection per operation.

### LLM provider is a swappable Protocol

`TriageProvider` in `llm/providers.py` defines the interface. Only `DeterministicDemoProvider` is implemented — it uses keyword matching on case text to assign severity. All tests, the demo, and the eval suite use this provider. Adding a real LLM means implementing `TriageProvider` and registering it in `get_provider()`.

### API surface

Core case lifecycle:
- `POST /cases` — create case, trigger background triage (202)
- `GET /cases` — list case summaries
- `GET /cases/{case_id}` — full case record
- `GET /cases/{case_id}/triage-report` — triage report (or pending status)
- `POST /cases/{case_id}/analyst-feedback` — submit analyst feedback, compute disagreement metrics

Detail views (all support `?role=` query param for role-filtered views):
- `GET /cases/{case_id}/evidence`
- `GET /cases/{case_id}/timeline`
- `GET /cases/{case_id}/mitre`
- `GET /cases/{case_id}/grc-controls`
- `GET /cases/{case_id}/audit-events`

Operational endpoints:
- `GET /metrics` — aggregated operational metrics across all cases
- `GET /cases/read-model` — filterable case list with triage summaries, supports all filter combinations
- `GET /queues/manager-review` — cases requiring manager review (disagreements, false negatives, missed escalations)
- `GET /queues/healthcare-review` — cases flagged by healthcare safeguards

### Auth modes

Controlled by `API_AUTH_MODE` env var:
- `none` (default): local development only. Startup requires `THREATPRISM_LOCAL_DEV_ACK=true` or `THREATPRISM_AUTH_REQUIRED=false`; callers get admin.
- `demo_key`: API keys parsed from `DEMO_API_KEYS` env var in format `key:identity:role`; startup fails closed if keys are missing.

Demo keys are defined in `.env.example`. Pass via `X-ThreatPrism-Demo-Key` header or `Authorization: Bearer`.

### Eval harness

The eval suite (`src/threatprism/evals/`) is a regression defense system that validates guardrails and security boundaries without a live LLM. Fixtures are JSONL files under `tests/evals/` — one JSON object per line, each conforming to `EvalFixture` (fixture_id, category, description, payload).

There are 16 eval categories defined in `evals/schemas.py:EvalCategory`, covering: prompt injection, hallucinated claims, unsafe actions, schema violations, evidence citation integrity, healthcare safeguard leakage, authorization escalation, cross-role data leakage, metrics/read-model leakage, audit event leakage, token vault exposure, compliance overclaiming, ambiguity handling, oversized payloads, malformed JSON, and conflicting evidence.

Adding a new eval: add a new `EvalCategory` enum value, implement the evaluation logic in `_evaluate_by_category()` in `evals/runner.py`, and add fixture lines to the JSONL files. The runner path-sandboxes fixture and output directories to `tests/evals/` and `.eval_runs/` respectively.

### Invariants that must not be broken

- `ALLOW_REAL_ACTIONS=false` is enforced by `enforce_action_safety()` — any report containing `real_action_executed: true` is blocked at the guardrail layer regardless of what the provider returns
- The LLM never sees raw PHI/PII — Stage 1 tokenization runs before `_prepare_case_for_model()`
- Stage 1 typed tokens (`[POTENTIAL_PHI:...]`, `[POTENTIAL_PII:...]`, `[SECRET:...]`) are never rehydrated — the `rehydration_allowed=False` flag on their `SanitizationRecord` is permanent
- Every authorization decision is recorded as an `AuditEvent` on the case — denials and allows both
- Eval fixture and output paths are sandboxed — `_resolve_under_approved_dir()` rejects paths that escape the approved directories
- `validate_runtime()` blocks production environments from using `none` or `demo_key` auth modes

### Key files

| File | Role |
|------|------|
| `src/threatprism/api/app.py` | All HTTP routes; calls `CaseService` |
| `src/threatprism/cases/service.py` | Full case lifecycle orchestration |
| `src/threatprism/cases/schemas.py` | All Pydantic models: `CaseRecord`, `TriageReport`, enums |
| `src/threatprism/cases/read_models.py` | Operational metrics and filterable read model schemas |
| `src/threatprism/guardrails/prompt_firewall.py` | Prompt injection detection and redaction |
| `src/threatprism/guardrails/healthcare.py` | PHI/PII/secret detection with context-aware rules |
| `src/threatprism/guardrails/tokenization.py` | Stage 2 tokenization/rehydration and `TokenVault` |
| `src/threatprism/guardrails/policy.py` | Output regex guardrails (`PROHIBITED_PATTERNS`) |
| `src/threatprism/guardrails/evidence.py` | Evidence citation validation |
| `src/threatprism/guardrails/views.py` | Role-based view masking and audit |
| `src/threatprism/auth/demo.py` | Auth logic and `ROLE_VIEW_POLICY` |
| `src/threatprism/llm/providers.py` | `TriageProvider` protocol + demo implementation |
| `src/threatprism/soar/generic.py` | SOAR adapters (Sentinel, Defender, Swimlane, etc.) |
| `src/threatprism/persistence/sqlite.py` | JSON-blob SQLite repository |
| `src/threatprism/config.py` | All settings from environment |
| `src/threatprism/evals/runner.py` | Eval harness execution engine |
| `src/threatprism/evals/schemas.py` | `EvalCategory` enum and fixture/result models |

### Adding a new SOAR source

Subclass `GenericSoarAdapter` in `soar/generic.py`, override `source_name` and `accepted_sources`, and add an instance to the `adapters` list in `normalize_soar_payload()`. Add a matching `Source` enum value in `cases/schemas.py`.

### Testing patterns

Tests use `FastAPI`'s synchronous `TestClient` with an in-memory SQLite database. The factory pattern is:

```python
def _client(tmp_path: Path) -> TestClient:
    app = create_app(Settings(env="test", database_url="sqlite:///:memory:", ...))
    return TestClient(app)
```

Because `TestClient` is synchronous, FastAPI `BackgroundTasks` (like `run_triage`) execute inline before the response returns — so tests can `POST /cases` and immediately `GET` the triage report without polling.

### Spec and decision documents

Before adding significant features, read in this order:
1. `docs/ARCHITECTURAL_NORTH_STAR.md` — directional constraints
2. `docs/specs/` — per-component specs
3. `DECISIONS.md` — locked decisions that are not open for re-debate
4. `LIMITATIONS.md` — what this system intentionally does not do

### Security threats and treatment

Before adding a feature that introduces a new trust boundary, attacker surface, data store, or LLM/agent capability, read in this order:

1. `docs/threat-models/README.md` — entry point for the v0.2 threat model pack (STRIDE + MITRE ATLAS/OWASP LLM Top 10 + LINDDUN). This pack is the source of truth for security threats — do not re-derive threats from prose elsewhere.
2. The lens file(s) that match your change (`stride-threat-model.md`, `llm-agent-threat-model.md`, `healthcare-data-threat-model.md`).
3. `docs/threat-models/mitigations-traceability.md` — confirm each mitigation you rely on has a test, and identify gaps your change introduces.
4. `docs/specs/21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md` — locate the treatment decision for the threat(s) your change touches. If your change would invalidate an Avoid decision (e.g., adding memory, tools, or multi-tenancy), re-open spec 21 before proceeding.

If your change introduces a new threat not covered by the pack, run the global `/threat-model` skill (matches the v0.2 format) to refresh the affected lens file before shipping. Slice G (quarantine enforcement) is the most recent completed treatment — see `docs/specs/21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md` for its slice description and `tests/test_quarantine_enforcement.py` for the regression test.
