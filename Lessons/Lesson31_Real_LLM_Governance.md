# 💰 Lesson 31 — Real-LLM Governance: Spend Caps, Metering & Dual-Provider Accounting

> **Goal:** Understand the controls that must wrap a *paid* LLM before it is turned
> on — spend caps, usage/cost accounting, per-call audit, an approved-model
> allowlist — and how they extend to a second, independent provider.
> **Time:** ~30 min · **Prerequisites:** Lesson 06 (the triage provider),
> `docs/AI_GOVERNANCE_ASSESSMENT.md`.

Covers specs 33 (real-LLM seam), 35 (failed-call metering), 36 (analyst spend).

---

## 1. 🎯 Why governance comes *before* the gate

Turning on a metered LLM with no spend cap or cost tracking is the textbook OWASP
**LLM10 Unbounded Consumption** failure. ThreatPrism enforces four controls
(`llm/governance.py`), all deterministic and testable with **no keys**:

| Control | Where | Standard |
|---|---|---|
| Spend cap (fail-closed `budget_exceeded`) | `enforce_spend_cap()` | OWASP LLM10 |
| Usage/cost accounting | `UsageRecord` + `SpendLedger` + `CostModel` | NIST AI 600-1 MEASURE |
| Per-call audit (hashes, never raw) | `build_llm_call_audit()` | EU AI Act |
| Approved-model allowlist | `APPROVED_MODELS` frozenset | ISO/IEC 42001 |

The allowlist is **code-authoritative**: config cannot select a model the code did
not approve (anti-tamper). `validate_runtime()` refuses to start a real provider
without an approved model *and* a spend cap > 0.

---

## 2. 🔌 The deterministic envelope around a probabilistic core

`metered_generate()` is the pattern: check the budget *before* the call → run the
provider through `safe_generate_report` (which converts every failure into a
structured `TriageFailureReport`, never an exception) → price the actual reported
usage and add it to the ledger → emit a sanitized `llm_call` audit.

The LLM's *output* is untrusted: it still passes the existing deterministic
guardrails (output policy, evidence, action safety) before it is believed. This is
the **hybrid-determinism rule** — nondeterministic prose inside a deterministic
validated envelope.

---

## 3. 🧾 Meter on *attempt*, not just success (spec 35)

A call that completes the paid API round-trip and *then* fails downstream
(`provider_response_unparseable`, `schema_validation_failure`) still cost tokens.
Originally those were only ledgered on the success branch → `/metrics` and the
spend cap **undercounted** (seen live: a failed response showed `usd 0`).

The fix:
- the provider **resets** `last_usage`/`last_prompt`/`last_response` per attempt and
  sets usage only after a real response — so a non-`None` record means a call
  happened;
- `metered_generate` ledgers whenever usage is present, **success or failure**,
  tagging `UsageRecord.failure_type`;
- `run_triage` persists the `llm_call` audit on the failure branch too;
- `/metrics` gains `llm_usage.failed_call_count`.

Pre-call failures (unreachable/timeout/auth/budget) leave `last_usage` `None` →
nothing billed (correct — no call was made).

> 🧭 The financial analogue of audit logging: a consequential event (spend) is
> recorded **regardless of downstream outcome**, like logging an auth attempt on
> both allow and deny.

---

## 4. 👥 Two LLMs, two ledgers (spec 36)

Evolution 2 grades ThreatPrism's triage with an **independent** analyst (a
*different* model — OpenAI — or the comparison is circular). Because it is a
different model, its cost cannot fold into the triage ledger: `metered_evaluate()`
governs the analyst with its **own** `CostModel` + `SpendLedger` + cap + audit. The
backtest surfaces both `triage_llm_usage` and `analyst_llm_usage`. Governance has
to respect the same provider boundary the methodology does.

`LlmUsageMetrics.from_ledger()` aggregates any ledger, reused by `/metrics` and the
backtest.

---

## 5. 🧪 The testing pattern (the through-line)

Every one of these is tested with **no network**: a fake provider/analyst that sets
`last_usage` then returns or raises, behind the `TriageProvider` / `AnalystGrader`
Protocol seam. You fake the *untrusted, paid* dependency and test the *deterministic
governance logic* for real — the spend math, the ledger-on-failure, the cap, the
hash-only audit. The live paid runs are the owner's, gated behind keys + explicit
consent.

| Concern | File |
|---|---|
| Caps, ledger, cost model, `metered_generate`/`metered_evaluate`/`metered_narrative`, audit, allowlist | `src/threatprism/llm/governance.py` |
| Provider usage capture (reset+set per attempt) | `src/threatprism/llm/providers.py`, `src/threatprism/llm/mock_analyst.py` |
| Failure taxonomy | `src/threatprism/llm/failures.py` |
| Surfaced usage metrics | `src/threatprism/cases/read_models.py` (`LlmUsageMetrics`) |
| Tests | `tests/test_llm_governance.py`, `tests/test_real_llm_provider.py`, `tests/test_backtest.py` |

---

## 6. 🎤 Interview talk track

> "Before turning on a paid LLM I wired the LLM10 controls: a fail-closed spend cap,
> a usage/cost ledger surfaced to `/metrics`, a per-call audit that stores hashes
> not content, and a code-authoritative approved-model allowlist. A subtle bug I
> fixed: usage was only ledgered on success, so a call that completed the paid
> round-trip then failed to parse showed `$0` — I moved metering to *attempt*, with
> a per-attempt reset so nothing double-counts. And when we added an independent
> analyst on a different provider, I gave it its own cost model and ledger rather
> than conflating two models' spend. All of it tests with no keys by faking the
> provider at a Protocol seam."
