# Live Backtest Findings (Evolution 2, real Anthropic + OpenAI)

Real-LLM two-model backtest: ThreatPrism (Claude) triage vs. an independent
OpenAI analyst, over the curated synthetic SOC dataset. No real-world data.

## Smoke run #1 — 2026-06-01 (`--live --limit 2`)

**Purpose:** verify the live Anthropic/OpenAI SDK plumbing before the full corpus.

**Result: caught a real bug for ~$0.01.** Both providers were reached — Claude
triage (2 calls, 1,291 tok, ~$0.0094) and OpenAI analyst (2 calls, 5,857 tok,
~$0.001), total **~$0.0104** — but **all gradings failed** (`graded_total: 0,
grading_failures: 2`). The full 31-case corpus would have produced 31 failures and
wasted ~$1+. This is exactly the loss the smoke step exists to prevent.

**Root cause:** `MockAnalyst._call()` did not request OpenAI **JSON mode**. The
system prompt mandates "ONLY a JSON object," but without
`response_format={"type": "json_object"}`, gpt-4o-mini returns markdown-fenced or
prose-wrapped JSON, so `json.loads()` in `evaluate()` raises
`ProviderResponseUnparseable` — every grading fails closed.

**Diagnosis gap also found:** `run_backtest` counted failures but **discarded the
reason** (`grading_failures += 1; continue`), so the report couldn't say *why*. The
root cause had to be inferred from code rather than read from the report.

**Fixes (committed before any re-run):**
1. `MockAnalyst._call()` now passes `response_format={"type": "json_object"}`
   ([llm/mock_analyst.py](../src/threatprism/llm/mock_analyst.py)).
2. `BacktestReport` gains `grading_failure_types` (failure_type → count); the
   report is now self-diagnosing ([demo/backtest.py](../src/threatprism/demo/backtest.py)).
   Regression: `test_grading_failure_types_are_recorded_not_silent`.

**Cost accounting verified working:** the `openai`/`anthropic` usage-attribute
names (`prompt_tokens`/`completion_tokens`, and the triage side) read correctly —
token counts and costs populated, so the register's SDK-attribute pre-flight risk
is cleared for both providers.

**Status:** fix applied; **re-run pending owner go-ahead** (paid). Awaiting
confirmation per the "ask before any paid run" rule.

## Smoke run #2 — pending

## Full corpus run — pending
