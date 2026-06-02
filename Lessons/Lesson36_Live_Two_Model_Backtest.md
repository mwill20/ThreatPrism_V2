# 🤝 Lesson 36 — The Live Two-Model Backtest (and How to Read "100% Agreement" Honestly)

> **Goal:** Understand the Evolution 2 flagship — ThreatPrism's real Claude triage
> graded by an *independent* real OpenAI analyst — including how a cents-scale smoke
> run caught a real bug, why OpenAI JSON mode matters, and the single most important
> skill here: interpreting an evaluation result honestly instead of celebrating a
> green number.
> **Time:** ~30 min · **Prerequisites:** Lesson 31 (real-LLM governance), Lesson 28
> (end-to-end + feedback loop).

Implements the live run of Evolution 2. Findings: [docs/LIVE_BACKTEST_FINDINGS.md](../docs/LIVE_BACKTEST_FINDINGS.md).

---

## 1. 🎯 What the backtest measures

ThreatPrism triages a case (real Claude). An **independent** grader — a *different*
model, real OpenAI gpt-4o-mini — triages the same case from scratch and emits an
`AnalystFeedbackCreate`. The backtest aggregates where they **disagree**
(`DisagreementRecord`): determination mismatches, severity mismatches, and the
high-value signal "ThreatPrism flagged it, the analyst cleared it."

The **independence rule** is the whole point: the grader must be a different
provider/model than the triage brain, or the comparison is circular (a model
grading itself agrees with itself). `MockAnalyst.provider_name = "openai_mock_analyst"`
≠ `"anthropic_claude"`.

> SOC analogy: this is a **second-analyst review** of every alert disposition. The
> value isn't "did they agree" — it's surfacing the cases where two competent
> reviewers *disagree*, because those are where the triage logic needs tuning.

---

## 2. 💸 Cost-minimal staged runs — smoke before corpus

Live runs cost real money, so we never fire the full corpus blind. The `--limit N`
flag (and `DemoSeeder.seed(..., limit=N)` underneath) caps how many cases are
**seeded** — and since triage runs per seeded case, that caps the *paid triage
calls*, not just the grading:

```bash
# Smoke: ~2 cases, ~$0.01 — verify the live plumbing
PYTHONPATH=src python -m threatprism.demo.backtest --live --limit 2 --json
# Full corpus once smoke is clean
PYTHONPATH=src python -m threatprism.demo.backtest --live --json
```

The limit had to cap **seeding**, not just grading — a subtle point. The naive
version (limit only the grading loop) still triages all 32 cases at intake, paying
full triage cost. Always limit at the *first* expensive step.

---

## 3. 🐛 The smoke test that paid for itself (~$0.01)

Smoke run #1: both providers were reached (tokens + cost recorded), but
`graded_total: 0, grading_failures: 2` — **every grading failed.** The full corpus
would have wasted ~$1 producing 31 failures.

**Root cause:** `MockAnalyst._call()` didn't request OpenAI **JSON mode**. The
system prompt says "Return ONLY a JSON object," but a chat model without
`response_format={"type": "json_object"}` happily returns markdown-fenced JSON
(```` ```json … ``` ````) or a polite preamble. Then `json.loads()` in `evaluate()`
raises `ProviderResponseUnparseable` → fail closed, every case.

The fix is one line:

```python
response = client.chat.completions.create(
    model=self.model_id,
    response_format={"type": "json_object"},   # <- guarantees parseable JSON
    messages=[...],
)
```

JSON mode requires the word "json" somewhere in the prompt (the system prompt
already says it). With it on, the response is a guaranteed JSON object.

> Lesson: this is the **untrusted-LLM-output** rule (Lesson 04) applied to *format*,
> not just content. "The model will return JSON because I asked nicely" is the same
> mistake as "the model won't hallucinate because I told it not to." Constrain the
> output mechanically (JSON mode), then still validate it (Pydantic).

---

## 4. 🔍 Silent failures are a bug too

The smoke run also exposed a *diagnosability* gap: `run_backtest` counted failures
but **discarded the reason** (`grading_failures += 1; continue`). The report said
"2 failures" but not *why* — the root cause had to be read out of the code.

Fix: `BacktestReport.grading_failure_types` records `failure_type → count`. Now the
report is self-explaining: a future failure shows `{"response_unparseable": 2}` or
`{"provider_timeout": 1}` directly.

> A counter that increments on failure but drops the reason is a smoke detector that
> beeps without telling you which room. Always capture the *category* of a failure,
> not just the count — sanitized (no raw payload), but categorized.

---

## 5. 📊 Reading the result honestly — the most important section

Full corpus result: **27 graded, 100% agreement** (0 determination/severity
mismatches), ~$0.17.

A green 100% is exactly when you must be *most* skeptical. What it shows and doesn't:

| Claim | True? |
|---|---|
| The end-to-end live plumbing works (real triage → guardrails → independent real grader → disagreement metrics → spend accounting) | ✅ Yes — this is real, validated |
| Two strong models agree on **clear-cut** cases | ✅ Yes (20 benign, 7 suspicious, no malicious) |
| The **disagreement-detection** path works | ❌ **Not shown** — there was nothing to disagree about |
| ThreatPrism's triage is "accurate" | ❌ Not shown — agreement ≠ ground truth; both could be wrong together |

The curated corpus is unambiguous, so 100% agreement is the *expected* result, not
an impressive one. Tellingly, the **deterministic** `HeuristicDemoAnalyst` was
purpose-built to force divergence (so the disagreement machinery had something to
catch in tests); the **real** analyst agreed fully. The conclusion isn't "the system
is accurate" — it's "the pipeline is wired correctly, and we have not yet tested it
on anything hard." That honesty is the deliverable.

> Interview-grade framing: "A 100% agreement rate on a curated corpus validates my
> plumbing and tells me nothing about my detection quality. To evaluate the thing I
> actually care about — disagreement detection — I need ambiguous and adversarial
> cases. Reporting the 100% *without* that caveat would be misleading."

---

## 6. 🔭 The 27-vs-31 gap (an observation, not a conclusion)

The deterministic baseline grades 31; the live run graded 27. ~4 cases produced
**no report** under the real pipeline. The likely explanation is the guardrails
(prompt firewall / quarantine / evidence validation) firing on real-Claude output
where the canned demo output passed — i.e., the guardrails *working*. But this run
didn't capture the per-case reason, so it stays an **observation**. The follow-up
(count blocked-vs-failed in `run_backtest`) turns it into a fact — and is the next
slice after this lesson.

---

## 7. 🔐 The data-egress invariant under a real third party

Sending cases to OpenAI is real third-party egress. The invariant (Lesson 05 + the
gate-opening): the analyst grades the **stored, Stage-1-tokenized** case, so raw
PHI/PII/secrets never leave — only never-rehydrated tokens do. This is locked by
`tests/test_analyst_egress.py` (OT-L10). Opening a real-provider gate without that
guard would be the moment a demo turns into a breach.

---

## 8. 🎤 Interview talk track

> "Evolution 2 grades ThreatPrism's real Claude triage with an independent real
> OpenAI analyst — independent on purpose, or the comparison is circular. I run it
> staged: a ~$0.01 smoke first, which caught a real bug — the analyst wasn't using
> OpenAI JSON mode, so every grading failed to parse; the full run would have wasted
> ~$1. I fixed it and made the report record failure *categories* so failures can't
> be silent. The full run came back 100% agreement, and the important part is how I
> reported it: that validates the end-to-end plumbing and shows two models agree on
> clear cases, but it does NOT show disagreement detection works, because the corpus
> is unambiguous. The next step is an adversarial dataset to actually stress it.
> Throughout, raw PHI never egressed to OpenAI — the analyst only ever sees Stage-1
> tokens, and that's enforced by a test."

---

## 9. 🗂️ Quick reference card

| Thing | Value |
|---|---|
| Command | `PYTHONPATH=src python -m threatprism.demo.backtest --live [--limit N] --json` |
| Independence | grader (`openai_mock_analyst`) ≠ triage (`anthropic_claude`) |
| Smoke-caught bug | missing OpenAI JSON mode → `response_unparseable` on every case |
| Fix | `response_format={"type": "json_object"}` in `mock_analyst._call()` |
| Diagnosability | `BacktestReport.grading_failure_types` (category → count) |
| Full result | 27 graded, 100% agreement, ~$0.17 |
| The honest read | plumbing validated; detection quality + disagreement **not** tested |
| Egress guard | `tests/test_analyst_egress.py` — analyst sees Stage-1 tokens only |
| Next | ambiguous/adversarial dataset; no-report-reason counting |
