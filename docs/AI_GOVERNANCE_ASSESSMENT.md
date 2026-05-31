# AI Governance Assessment — ThreatPrism vs. the Enterprise AI Governance Triangle

Maps ThreatPrism's current controls to the three governance pillars — **Control**
(what can AI do), **Auditability** (what did AI do), **Safety** (what can't AI do)
— with status, gaps, and standards-based fixes.

**Status legend:** ✅ implemented · ⚠️ partial · ❌ gap (or gated)

**Standards referenced:** NIST AI RMF (AI 100-1) + Generative AI Profile
(NIST AI 600-1, 2024); ISO/IEC 42001:2023 (AI management systems); OWASP LLM Top 10
(2025), esp. **LLM10 Unbounded Consumption**; MITRE ATLAS; EU AI Act logging/
transparency for high-risk systems.

---

## 1. Control — *What can AI do?*

| Item | ThreatPrism today | Status | Gap → standards-based fix |
|---|---|---|---|
| Permission models (allow/deny tools) | No tool/function-calling exists; the LLM only returns a report (L8/OT-L4 deliberately absent) | ✅ (by absence) | When tools are ever added: reverse-deny allowlist per role/case + human approval per call (threat model "Before Tools"; OWASP LLM06 Excessive Agency) |
| File access restrictions | LLM has **no** filesystem access; eval/fixture/dataset paths are sandboxed (`_resolve_under_approved_dir`, curated path sandbox) | ✅ | None for the LLM path |
| Dry-run mode enforcement | `ALLOW_REAL_ACTIONS=false` default; all actions are `simulated_action()` | ✅ | None |
| Destructive operation blocking | `enforce_action_safety()` blocks `real_action_executed: true` regardless of model output | ✅ | None |
| Model selection governance | `LLM_PROVIDER` / `LLM_MODEL_ID` / `LLM_MODEL_REVISION` config; `validate_runtime()` requires a key for the real provider | ⚠️ | **No approved-model allowlist.** Fix: an in-code `APPROVED_MODELS` frozenset (same anti-tamper pattern as `DATASET_ALLOWED_LICENSE_REVIEW`); reject unlisted model ids at startup (ISO 42001 governance; NIST GOVERN) |

## 2. Auditability — *What did AI do?*

| Item | ThreatPrism today | Status | Gap → standards-based fix |
|---|---|---|---|
| Full action logging with timestamps | `AuditEvent` on every authz allow/deny, guardrail block, role-view, feedback, triage validation, **and provider failure** (`triage_provider_failure`); sanitized metadata | ✅ | None (demo scope) |
| Diff capture for every edit | No file edits; `SanitizationRecord` captures token replacements; no report versioning/diff | ⚠️ | **Report version + diff.** Fix: store report revisions and a structured diff on re-triage (EU AI Act record-keeping) |
| Prompt history tracking | Failure records carry `model_id`/`revision`/`attempt`; the prompt/response themselves are not audited | ❌ | **Sanitized per-call audit.** Fix: an `LLMCallAudit` AuditEvent per call — model id+revision, input/output token counts, and a **hash** of prompt+response (never raw PHI) (NIST MEASURE; EU AI Act logging) |
| Token usage and cost tracking | Not implemented (no real provider yet) | ❌ | **`UsageRecord` per call** (input/output tokens, estimated cost) persisted + aggregated into `/metrics` (OWASP LLM10; NIST MEASURE; provider usage APIs) |
| Compliance-ready export formats | Audit events live in SQLite blobs; `SafeAuditEvent` projection for the API; no export/retention | ❌ (gated — OT-8) | **Append-only audit + export** (JSON/CSV) + retention policy (EU AI Act; ISO 42001; tracked as OT-8, gated to non-demo data) |

## 3. Safety — *What can't AI do?*

| Item | ThreatPrism today | Status | Gap → standards-based fix |
|---|---|---|---|
| Pre-execution validation hooks | Four-layer guardrail pipeline: prompt firewall (pre-model) + output policy / evidence / action safety (post-model, pre-persist). LLM output is untrusted and validated (`validate_llm_report`) | ✅ | Add the semantic firewall (spec 32) once the LLM acts on text |
| Secret detection and blocking | Healthcare safeguard tokenizes secrets (API keys/passwords, never rehydrated); output policy blocks `sk-` shapes; sanitizers redact credentials | ✅ | None |
| Scope enforcement (no mass edits) | No edit surface; `BATCH_MAX_EVENTS`/token budget, request body cap, in-process rate limit, triage concurrency cap | ✅ | None |
| Budget limits and spend caps | **Input** token budget for batching (`BATCH_MAX_INPUT_TOKENS`); **no spend/cost cap** | ❌ | **Deterministic spend cap.** Fix: `enforce_spend_cap()` — a per-run / per-day cost+token ceiling that fails closed (`budget_exceeded` already in the taxonomy) before any further call (OWASP **LLM10 Unbounded Consumption**; NIST MANAGE) |
| Human-in-the-loop gates | Every report `analyst_review_required=True`; manager-review queue; analyst feedback/disagreement loop; `ALLOW_REAL_ACTIONS=false` | ✅ | None |

---

## 4. Gap summary (prioritized)

ThreatPrism is **strong on Control and Safety today** (dry-run default, destructive
blocking, no tool/file surface, pre-execution validation, secret blocking, HITL).
The gaps cluster in **Auditability** and the **cost/spend** corner of Safety — and
they all become *acute exactly when the real LLM turns on*:

| # | Gap | Pillar | Status |
|---|-----|--------|--------|
| 1 | **Spend cap / cost ceiling** (Unbounded Consumption) | Safety | ✅ `enforce_spend_cap()` / `metered_generate()` in `llm/governance.py`; `validate_runtime` requires a cap for the real provider |
| 2 | **Token usage + cost accounting** (`UsageRecord`, `SpendLedger`) | Auditability | ✅ `llm/governance.py` (`CostModel`, `SpendLedger`); provider sets `last_usage`; **surfaced** to `/metrics` (`OperationalMetrics.llm_usage`) and the run summary |
| 3 | **Sanitized per-LLM-call audit** (model+tokens+hash) | Auditability | ✅ `build_llm_call_audit()` (hashes prompt+response, never raw) |
| 4 | **Approved-model allowlist** | Control | ✅ `APPROVED_MODELS` enforced in `validate_runtime()` |
| 5 | Append-only audit + compliance export + retention (OT-8) | Auditability | ❌ gated (non-demo data) |
| 6 | Report versioning/diff | Auditability | ❌ (lower priority) |

> Gaps 1–4 implemented and tested (`tests/test_llm_governance.py`, no network).
> `run_triage` already routes provider calls through `metered_generate` +
> `build_llm_call_audit` behind the gate flag — metering, spend cap, and per-call
> audit are active from the first live call. Only keys + SDK verification remain.

**Gaps 1–4 are deterministic, testable without keys, and are precisely the
controls a paid LLM needs before it is turned on.** Turning on a metered LLM with
no spend cap or cost tracking is the textbook OWASP LLM10 Unbounded Consumption
risk — governance should lead the gate, not trail it.

---

## 5. Recommended sequencing

**Build the real-LLM governance controls (gaps 1–4) as a deterministic slice
*before* opening the live gate.** Each plugs into the existing seam:
- `enforce_spend_cap()` runs in `safe_generate_report` / the batch runner; exhaustion → `budget_exceeded` failure (already defined), fail closed.
- `UsageRecord` is emitted per call and aggregated like the existing metrics.
- `LLMCallAudit` is an `AuditEvent` variant (hash, not raw content).
- `APPROVED_MODELS` is an in-code allowlist enforced in `validate_runtime()`.

Then open the gate (spec 33 / `OPEN_REAL_LLM_GATE.md`) with cost tracking, a spend
cap, per-call audit, and model governance already enforcing — so the live LLM is
metered, logged, and bounded from its first call.

Gaps 5–6 remain gated to non-demo data / production (OT-8) and are tracked in the
threat-model treatment register.
