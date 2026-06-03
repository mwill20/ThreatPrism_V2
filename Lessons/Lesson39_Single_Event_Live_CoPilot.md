# Lesson 39 — The Single-Event Live Co-Pilot Cadence (Evolution 3) 🧑‍💻⚡

> Files: `src/threatprism/demo/run_copilot_demo.py`,
> `src/threatprism/cases/service.py` (`assign_case`, `submit_feedback`),
> `tests/test_copilot_demo.py`. Baseline: see
> [../docs/VALIDATION_BASELINE.md](../docs/VALIDATION_BASELINE.md).

## 1. 🎯 What Evolution 3 is

Three runtime evolutions reuse the same engine at different cadences:

- **Evolution 1** — batched benign auto-close (throughput + safety-net).
- **Evolution 2** — batch backtest vs. an independent analyst (tuning at scale).
- **Evolution 3** — **single event, live, human-in-the-loop**: an analyst self-assigns
  a case, pulls ThreatPrism's report, works it, and submits feedback — the *same*
  disagreement/tuning loop as Evolution 2, but one decision at a time, live.

This lesson is the headless driver for Evolution 3: `run_copilot_demo`. It walks one
case through `create -> triage -> self-assign -> analyst feedback -> disagreement
record`, so the live owner-run is repeatable, cost-capped (one case), and
regression-tested — the same role `backtest.py` plays for Evolution 2.

## 2. 🪤 The conflation trap: the analyst is an input, not an LLM

The tempting shortcut is to reuse Evolution 2's OpenAI `MockAnalyst` as the analyst
here. That is **wrong**, and naming the roles precisely is the lesson:

- In Evolution 2 the mock-analyst is an *independent second opinion* — a **different**
  model grading the case so ThreatPrism isn't grading itself.
- In Evolution 3 the analyst is **the human working the case**. A headless driver
  can't *be* the human, so it represents the verdict as an explicit input
  (`AnalystVerdict`), demonstrating the loop *mechanics* and the tuning signal — it
  never claims human judgment.

Using the Evolution-2 grader here would silently conflate "independent check" with
"the operator's decision." The driver therefore takes a parameterized verdict that
**defaults to mirroring the triage report** (agreement); override any field to
simulate the analyst diverging.

```python
@dataclass
class AnalystVerdict:
    determination: str | None = None   # None => mirror the report (agreement)
    severity: str | None = None
    disposition: str | None = None
    confidence: float | None = None
```

## 3. 🔗 The loop reuses existing seams

No new domain logic — the driver composes services already built and tested:

```
DemoSeeder(...).seed([CuratedDatasetSource()], limit=1)   # one real case through intake+triage
service.assign_case(case_id, actor_identity=..., actor_role="analyst")   # Evolution 3 ownership
service.submit_feedback(case_id, AnalystFeedbackCreate(...))             # -> DisagreementRecord
```

`assign_case` records ownership + an audit event (the caller can only assign *to
themselves* in this slice — no assigning others). `submit_feedback` returns the
`DisagreementRecord` — the tuning signal. Override the analyst determination and the
record flips `manager_review_required` to True with an explained reason. That is
Evolution 3's payoff: a live disagreement routes to manager review.

## 4. 💸 Verify before you spend

The driver is deterministic by default (demo provider) and `--live` swaps in the real
Claude provider. The discipline: **prove the loop deterministically (free) so the only
new variable in the paid run is the real model.** The whole loop was green in
`tests/test_copilot_demo.py` before a cent was spent, so the live run had exactly one
job — confirm real output flows through assign → feedback → disagreement.

## 5. 🔬 The live finding (≈ half a cent)

The live run (`--live`, one case, 1 call, 696 tokens, **$0.005**) surfaced the point of
the whole exercise — the **provider gap**:

| | determination | severity | confidence |
|---|---|---|---|
| Deterministic demo | benign | low | 0.64 |
| **Real Claude** | **suspicious** | low | **0.95** |

Same case (a prompt-injection fixture), same pipeline — the real model's security
judgment shows through where the keyword stub was naive. Agreement/disagreement only
*means* something once a real verdict is in the loop. (The failure log stayed empty —
the triage produced a schema-valid report, so nothing fell to the fail-closed path.)

## 6. 🧪 TDD checkpoints

- The full loop runs and self-assigns ownership (`owner == "copilot_analyst"`).
- Default analyst mirrors the report → no determination/severity mismatch.
- An overridden, divergent verdict → `determination_mismatch` True with a reason.
- The serialized result leaks no synthetic-but-forbidden tokens.

## 7. 🎤 Interview talk track

> "Evolution 3 is the live co-pilot: an analyst self-assigns a case, reads the triage
> report, and submits a verdict — feeding the same disagreement loop as the batch
> backtest, one decision at a time. I built a headless driver so the live run is
> repeatable and cost-capped, and I was careful *not* to reuse the batch's independent
> LLM grader as the analyst — those are different roles. I verified the loop
> deterministically, then spent half a cent live, which confirmed the cadence and
> surfaced the real point: the live Claude model rated an injection case suspicious/0.95
> where the deterministic stub said benign — the verdict quality only becomes real once
> a real model is in the loop."
