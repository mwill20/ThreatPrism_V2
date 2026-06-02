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

## Smoke run #2 — 2026-06-01 (`--live --limit 2`, post-fix)

Confirmed the JSON-mode fix: `graded_total: 2, grading_failures: 0,
grading_failure_types: {}`, agreement 1.0, ~$0.0103. Cleared to run the full corpus.

## Full corpus run — 2026-06-01 (`--live`)

| Metric | Value |
|--------|-------|
| Graded | **27** (0 failures, `grading_failure_types: {}`) |
| **Agreement rate** | **1.0 (100%)** — 0 determination mismatches, 0 severity mismatches |
| ThreatPrism determinations | 20 benign, 7 suspicious (0 malicious/critical in graded set) |
| Flagged-then-cleared by analyst | 0 |
| Triage (Claude) | 27 calls, 20,772 tok, $0.1566 |
| Analyst (OpenAI gpt-4o-mini) | 27 calls, 85,722 tok, $0.0143 |
| **Total cost** | **$0.171** (session live-run total incl. smokes: ~$0.19) |

### Analysis

**1. 100% agreement (27/27) — what it does and doesn't show.** The independent
OpenAI analyst reached the *same* determination and severity as ThreatPrism's
Claude triage on every graded case. This **validates the end-to-end live two-model
plumbing** (real triage → guardrails → real independent grader → disagreement
metrics) and shows the two models agree on clear-cut cases. It does **not** exercise
the disagreement-detection path: the curated corpus is unambiguous (20 benign /
7 suspicious, no malicious), so there was nothing to disagree about. The
deterministic `HeuristicDemoAnalyst` was purpose-built to force divergence for
testing; the *real* analyst agreed fully. **To stress-test disagreement detection
(DisagreementRecord → manager-review queue), the next dataset needs ambiguous /
adversarial cases**, not more clear ones.

**Follow-up done 2026-06-02 (spec 37):** built `fixtures/curated_adversarial/` (8
synthetic triage-ambiguous cases) + `backtest --dataset adversarial`. Deterministic
baseline over the set is **agreement 0.5** (4/8 mismatches) vs. 1.0 on the curated
set — the disagreement path is now exercised. A confirming **live**
`--live --dataset adversarial` run (paid, owner-run) is the optional next step to
see whether two *real* models also diverge on engineered ambiguity.

**2. 27 graded vs. 31 on the deterministic baseline.** The deterministic backtest
grades 31 (32 seeded, 1 blocked). Live, only 27 produced a gradeable report — ~4
more cases yielded **no report** under the real pipeline. The most likely cause is
the guardrail pipeline (prompt firewall / quarantine / evidence validation) firing
on real-Claude output where the deterministic demo provider's canned output passed
— i.e., **the guardrails doing their job on a real model**. But this run did not
capture the per-case reason. **Follow-up done 2026-06-02 (non-paid):** `run_backtest` now
records `no_report_total` + `no_report_reasons` (keyed on `triage_status`), so the
27-vs-31 gap is no longer silent — the next live (or deterministic) run reports
whether the missing cases were `blocked_by_guardrail`, `failed`, etc. Regression:
`test_no_report_cases_are_counted_with_reason`. A confirming live re-run remains an
optional owner-run; the categorization itself is now structural.

**Pre-flight items cleared:** both providers' usage-attribute names read correctly
(token/cost accounting populated); model revision pinned; curated synthetic data
only. Spend stayed far under the $5/side cap.
