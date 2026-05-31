# Spec 33 — Real-LLM Triage Provider, Executive Summaries, Batching & Failure Reporting

Status: **design-only / gated.** Not implemented. Opening this gate is the "real
LLM provider integration" precondition that
[spec 21](21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md) and
[spec 32](32_SEMANTIC_PROMPT_INJECTION_LAYER.md) §9 both gate behind a
threat-model re-review. The build environment cannot make or test paid LLM calls;
the live integration is verified by the owner with their own API keys. This spec
defines the contract so implementation is mechanical and auditable.

Owner decisions captured (2026-05-30):
- **ThreatPrism's brain:** Anthropic Claude (paid; cost acknowledged).
- **Mock analyst (Evolution 2 grader):** **OpenAI** (a cheaper model, e.g.
  `gpt-4o-mini` or current equivalent). It MUST be a different provider/model path
  than the Claude triage provider, or the comparison is circular.
- **Executive summary:** both per-event and batch; batch ranked most-critical-first
  with provenance/traceability for auditors.

---

## 1. Determinism stance — hybrid (the core design rule)

**The narrative prose is nondeterministic (LLM); everything that carries security
or audit weight is deterministic.** This is the project's "deterministic for
production paths, probabilistic for exploration" rule applied precisely:

| Element | Deterministic? | Why |
|---|---|---|
| Severity ranking, ordering, `by_severity` counts | **Deterministic** | Audit ordering must be reproducible |
| Provenance (`sha256` source hash), evidence-ID traceability | **Deterministic** | Lineage must not depend on a model |
| Schema of the report and the executive summaries | **Deterministic** (Pydantic) | The structure is a contract |
| Guardrail validation of all output | **Deterministic** | Security decisions never gated by a probabilistic model |
| Narrative prose (per-event `summary`, batch `narrative`) | **Nondeterministic** (LLM) | Synthesis is what the LLM is for |

So the answer to "deterministic or nondeterministic?" is **nondeterministic prose
inside a deterministic, validated, structured envelope.** The LLM may only ever
*fill defined fields*; it never decides ranking, never sets the provenance, and its
output is rejected if it fails the deterministic guardrails. Use a low temperature
and a pinned model id/version for repeatability, but never *rely* on determinism
from the model — rely on the validation gate.

---

## 2. The executive summary contract

### 2.1 Per-event summary
Fills `TriageReport.summary`. Requirements the LLM output MUST satisfy (enforced
deterministically after generation):
- Grounded: may reference only evidence present in the case; cited `evidence_id`s
  are validated by `validate_report_evidence()`.
- No overclaim: passes `scan_output_policy()` (no compliance/certification claims,
  no leaked secrets, no first-person remediation, no `real_action_executed`).
- Length-bounded (config `SUMMARY_MAX_CHARS`).
- If it fails any check → the report is rejected and a failure report is produced
  (§4); the case does not silently ship a bad summary.

### 2.2 Batch executive summary
Extends the already-implemented deterministic `BatchExecutiveSummary`
(`run_soc_demo.py`): ranked most-critical-first, `by_severity`, per-case provenance
(`sha256`) and evidence-ID traceability, blocked cases surfaced. This spec adds the
LLM-filled `narrative`:
- The narrative may reference only the `source_case_id`s and severities present in
  the batch (no inventing cases) — validated against the batch's own item set.
- It leads with the most critical cases, matching the deterministic ranking.
- It carries no determination not already in the structured items.
- Until generated, `narrative=None`, `narrative_status="pending_real_llm_provider"`
  (current behavior). After generation it is validated by the same output policy.

---

## 3. Batching strategy

**Dual trigger — close a batch when *either* limit is hit, whichever first:**

| Limit | Config | Default | Rationale |
|---|---|---|---|
| Max events per batch | `BATCH_MAX_EVENTS` | 50 | Bounds blast radius + keeps a batch reviewable |
| Max input tokens per batch | `BATCH_MAX_INPUT_TOKENS` | model context window − `OUTPUT_TOKEN_RESERVE` | Prevents context overflow + runaway cost |

This matches the prior "≈50 events or a token limit, whichever triggers first"
approach and makes it explicit and configurable.

Rules:
- **Deterministic boundaries.** Cases are ordered (severity-rank, then
  `source_case_id`) *before* batching, so the same input always produces the same
  batches — required for reproducible provenance.
- **Never split a case** across batches; a single case never exceeds a batch.
- **Token estimation** uses the provider's tokenizer (or a conservative
  chars/token heuristic) on the *already tokenized + firewalled* case text — never
  raw PHI (Stage-1 runs first).
- **One executive summary per batch**, plus an optional roll-up across batches.
- **Oversized single case** (exceeds `BATCH_MAX_INPUT_TOKENS` alone) → not sent;
  produces a `budget_exceeded` failure report (§4), case set to `needs_review`.
- **Cost note.** Batching amortizes per-call overhead; the token cap is the hard
  cost ceiling per call. Both are owner-tunable.

---

## 4. Failure / error reporting (required)

Every failure produces a structured, auditable `TriageFailureReport` — never a
silent pass. **Fail closed:** any failure sets the case to `blocked_by_guardrail`
or `needs_review`, never `completed`.

### 4.1 Failure taxonomy

| `failure_type` | Stage | Trigger |
|---|---|---|
| `provider_unreachable` | call | Network error, DNS, connection refused |
| `provider_timeout` | call | Exceeded `LLM_CALL_TIMEOUT_SECONDS` |
| `provider_rate_limited` | call | HTTP 429 / quota |
| `provider_auth_error` | call | 401/403 — bad/missing key |
| `provider_response_unparseable` | parse | Non-JSON, truncated, or empty completion |
| `schema_validation_failure` | parse | Pydantic `ValidationError` building `TriageReport` |
| `evidence_grounding_failure` | guardrail | `validate_report_evidence()` — cited `evidence_id` not in case |
| `output_policy_rejection` | guardrail | `scan_output_policy()` — overclaim/secret/clinical/action |
| `action_safety_rejection` | guardrail | `enforce_action_safety()` — `real_action_executed: true` |
| `prompt_quarantine` | pre-model | Prompt firewall / semantic firewall quarantined the input |
| `budget_exceeded` | batch | Single case or batch over the token budget |

### 4.2 Each failure record carries

- `failure_type` (above) and `stage` (`pre_model` / `call` / `parse` / `guardrail` / `batch`)
- `what` — human-readable one-liner
- `why` — detail (e.g., the timeout value, the rejected pattern name, the missing evidence_id)
- `pydantic_triggered: bool` + `pydantic_errors` (summarized `ValidationError`, field paths only — no raw values)
- `guardrail` — which guardrail rejected it, if any
- `provider`, `model_id`, `model_revision`, `attempt` (for retries)
- `case_id` / `batch_id`, `terminal_status` applied (fail-closed)
- **No raw payloads, no secrets, no raw PHI** in the failure record (same redaction discipline as audit events)

### 4.3 Retry / degrade policy
- Transient call failures (`unreachable`/`timeout`/`rate_limited`) → bounded retry
  with backoff (`LLM_MAX_RETRIES`, default 2); on exhaustion → fail closed.
- `schema_validation_failure` → one re-ask with a stricter "return only valid JSON
  matching this schema" instruction; on second failure → fail closed.
- Guardrail rejections → **no retry of the same output**; the case is blocked and
  the failure recorded. (Re-asking to dodge a guardrail is forbidden.)
- A batch produces a `BatchFailureReport` aggregating per-case failures so an
  operator sees, at a glance, what failed, why, and how many.

### 4.4 Determinism of failures
Given the same provider output, the parse + guardrail verdict is deterministic, so
failure reports are reproducible and testable with a fake provider (§8).

---

## 5. Guardrail integration (reuse, do not bypass)

The LLM provider plugs into the existing `run_triage()` pipeline. LLM output is
**untrusted** and passes the same deterministic gates already in place:

- `scan_output_policy()` ([policy.py](../../src/threatprism/guardrails/policy.py)) — the serialized report *including the exec summary text* is scanned.
- `validate_report_evidence()` ([evidence.py](../../src/threatprism/guardrails/evidence.py)) — every cited id must exist.
- `enforce_action_safety()` ([policy.py](../../src/threatprism/guardrails/policy.py)) — `ALLOW_REAL_ACTIONS=false` invariant holds.
- Prompt firewall (and the gated semantic firewall, spec 32) on the *input*.

No new guardrail bypass is introduced. The exec summary sits visually at the top of
the report but is *last in trust*: generated, then validated.

---

## 6. Authentication & authorization (unchanged)

The provider does not alter auth. Existing controls apply:
- Demo: API-key→role auth + `ROLE_VIEW_POLICY` ([auth/demo.py](../../src/threatprism/auth/demo.py)).
- Production-readiness: static `external_oidc` + local token verifier ([auth/production.py](../../src/threatprism/auth/production.py)); live IdP gated.
- The mock-analyst batch harness is an offline/admin operation, not a public route.

---

## 7. Configuration & secrets

| Setting | Purpose |
|---|---|
| `LLM_PROVIDER=anthropic_claude` | Selects the real triage provider |
| `ANTHROPIC_API_KEY` (env only) | Claude key — never logged, never committed |
| `LLM_MODEL_ID`, `LLM_MODEL_REVISION` | Pinned model for repeatability + audit |
| `LLM_TEMPERATURE` (low, e.g. 0.2) | Reduce variance; not relied on for safety |
| `LLM_CALL_TIMEOUT_SECONDS`, `LLM_MAX_RETRIES` | Failure handling |
| `BATCH_MAX_EVENTS`, `BATCH_MAX_INPUT_TOKENS`, `OUTPUT_TOKEN_RESERVE` | Batching |
| `SUMMARY_MAX_CHARS` | Per-event summary bound |
| `MOCK_ANALYST_PROVIDER=openai` + `OPENAI_API_KEY` (env) + `MOCK_ANALYST_MODEL_ID` | Evolution 2 grader (independent from Claude) |

`.env.example` gets placeholders only. `validate_runtime()` keeps real providers
out of unsafe postures (no real provider while `env` is a test fixture; keys
required when the real provider is selected).

---

## 8. Tests (fake-provider, no network)

CI must never call a live API. A `FakeTriageProvider` returns canned structured
output to exercise the wiring:
- Happy path: fake report fills `summary` + batch `narrative`; passes guardrails.
- `schema_validation_failure`: fake returns malformed JSON → `TriageFailureReport` with `pydantic_triggered=true`, case fails closed.
- `provider_unreachable`/`timeout`: fake raises → retry then fail-closed failure report.
- `evidence_grounding_failure`: fake cites a missing `evidence_id` → guardrail rejection recorded.
- `output_policy_rejection`: fake emits an overclaim → blocked, recorded.
- Batching: deterministic boundaries at `BATCH_MAX_EVENTS` and at the token cap; no case split; oversized single case → `budget_exceeded`.
- No-network assertion: the real provider is never constructed in the default test settings.
- Mock-analyst independence: the analyst provider id differs from the triage provider id.

---

## 9. Threat-model re-open (must accompany implementation)

Per spec 32 §9 and spec 21's Gated Treatments:
- Move `I4/RR-I4/OT-7` toward Mitigated with the semantic firewall as the input
  control once it ships; the real provider makes it *warranted*.
- Activate `OT-L3` (token/context budget — §3 here) and `OT-L7` (output
  regurgitation — the output policy covers credential shapes; broader detection is
  still residual).
- Model the **egress boundary**: case text goes to a third-party API. This is
  acceptable only because Stage-1 tokenization runs first, so the model never
  receives raw PHI/PII/secrets — re-confirm this invariant in
  `healthcare-data-threat-model.md` and `llm-agent-threat-model.md`.
- `OT-L11` (semantic classifier surface) and the mock-analyst supply-chain note.
- Update `mitigations-traceability.md` with the new provider + failure-report
  controls and their tests.

---

## 10. Out of scope / honest constraints

- Live API calls are not made or tested in the build environment — the owner runs
  the live verification with their keys.
- The mock-analyst harness (Evolution 2 batch backtest) and the live co-pilot
  (Evolution 3) are separate slices that build on this provider; this spec covers
  the provider, the executive summaries, batching, and failure reporting only.
- No fine-tuning, no RAG, no memory/write-back, no real PHI, no multi-tenancy.
