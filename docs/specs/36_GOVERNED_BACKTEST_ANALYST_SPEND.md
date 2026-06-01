# Spec 36 — Govern + Surface the Independent Analyst's Spend (Evolution 2)

Status: **implemented** (2026-05-31). Extends the spec-35 metering discipline to
the *second* LLM in the Evolution 2 backtest.

## 1. Problem

The Evolution 2 backtest (`demo/backtest.py`) runs two independent LLMs: Claude
triages each case (governed via `metered_generate` — spend cap + usage ledger +
`llm_call` audit), and the OpenAI `MockAnalyst` plays an independent analyst to
surface disagreements. But the **analyst side was ungoverned**: `MockAnalyst._call`
captured no usage, had no spend cap, and emitted no audit. A live 32-case backtest
spent real OpenAI money with zero accounting — the OWASP LLM10 (Unbounded
Consumption) gap spec 35 closed for the triage provider, still open for the grader.
The backtest output also surfaced no spend at all (triage or analyst).

The independence rule (`mock_analyst.py`) makes this two-sided: the analyst MUST be
a different model from the triage brain, so its cost cannot fold into the triage
ledger — it needs its own pricing and its own ledger.

## 2. Fix

- **Usage capture** (`mock_analyst.py`): `MockAnalyst` resets
  `last_usage`/`last_prompt`/`last_response` per `evaluate()` and sets `last_usage`
  only after a real Chat Completions response (`usage.prompt_tokens` /
  `completion_tokens`) — the spec-35 contract.
- **`metered_evaluate`** (`llm/governance.py`): the analyst analogue of
  `metered_generate`. Spend-cap-gated before the call; runs the grader; ledgers the
  *attempted* spend (success OR downstream parse/schema failure) against the
  analyst's own `CostModel`; emits a sanitized `llm_call` audit. Every failure mode
  → a structured `TriageFailureReport` so the backtest fails closed for that case
  rather than fabricating an analyst verdict.
- **Backtest wiring** (`demo/backtest.py`): `run_backtest` routes each grading call
  through `metered_evaluate` with its own `SpendLedger` + `CostModel` + cap; a
  failure (provider/parse/schema OR cap breach) counts as a grading failure. The
  `BacktestReport` now carries `triage_llm_usage` and `analyst_llm_usage`, and the
  human render prints an `LLM spend` section for both sides.
- **Pricing** (`config.py`, `.env*`): `MOCK_ANALYST_INPUT_PRICE_PER_MTOK` /
  `MOCK_ANALYST_OUTPUT_PRICE_PER_MTOK` (gpt-4o-mini standard: $0.15 / $0.60 per 1M).
  The per-run cap reuses `LLM_MAX_COST_USD_PER_RUN` / `LLM_MAX_TOTAL_TOKENS_PER_RUN`.
- **Reuse:** `LlmUsageMetrics.from_ledger()` aggregates any ledger (used by both
  `/metrics` and the backtest report) — removes the duplicated aggregation.

## 3. Invariants

- The demo `HeuristicDemoAnalyst` exposes no `last_usage` → analyst spend is zero
  and the caps are inert. The non-`--live` backtest is unchanged.
- Pre-call analyst failures (unreachable/timeout/auth) leave `last_usage` None →
  nothing ledgered. Failed-after-call (parse/schema) is metered (tokens were spent).
- The analyst audit hashes prompt/response (never raw), same as the triage audit.

## 4. Tests (no network)

`tests/test_llm_governance.py`: `metered_evaluate` meters + audits a success;
pre-call failure not metered; failed-after-call metered with `failure_type`; cap
blocks without calling the analyst. `tests/test_backtest.py`: a fake metered
analyst surfaces `analyst_llm_usage` (31 calls) while the deterministic triage side
shows zero; the heuristic analyst yields zero analyst spend.

## 5. Gated (owner runs)

The live two-model backtest (`python -m threatprism.demo.backtest --live`) — paid on
both Claude (triage, during seeding) and OpenAI (grading). Verify `openai` usage
attribute names against the pinned SDK before relying on the analyst cost numbers.
Validated GREEN deterministically: 228 passed.
