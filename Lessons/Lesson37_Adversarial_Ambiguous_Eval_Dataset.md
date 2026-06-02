# 🎭 Lesson 37 — Designing an Adversarial Dataset (An Eval Must Be Able to Fail)

> **Goal:** Understand why a clear-cut test corpus cannot evaluate disagreement
> detection, how to *engineer genuine ambiguity* across named axes, the trick for
> making the result divergence-capable deterministically (no paid model), and the
> synthetic-data discipline that keeps it safe.
> **Time:** ~25 min · **Prerequisites:** Lesson 36 (live two-model backtest),
> Lesson 16/27 (data strategy + fixture sources).

Implements [spec 37](../docs/specs/37_ADVERSARIAL_EVAL_DATASET.md).

---

## 1. 🎯 The problem an eval dataset has to solve

Lesson 36 ended on a sharp point: the live backtest returned **100% agreement**,
which validated the plumbing but told us nothing about *disagreement detection* —
because the curated corpus was unambiguous, there was nothing to disagree about.

The core principle: **an evaluation dataset must be capable of producing the signal
you're measuring, or a passing result is meaningless.** A disagreement-detection
test run on cases no one disagrees about is a fire alarm tested in a room with no
fire. This lesson builds the room with the fire.

> SOC analogy: you don't validate your escalation playbook against 50 textbook-clean
> benign alerts. You validate it against the messy, could-go-either-way cases —
> that's where triage logic actually gets exercised.

---

## 2. 🧭 Engineering ambiguity on purpose — the five axes

"Ambiguous" isn't "vague." Each case is built around a *specific* reason two
competent analysts could defensibly disagree:

| Axis | The genuine tension |
|------|--------------------|
| **Dual-use behavior** | Same action is normal admin OR attacker TTP (encoded PowerShell from a service account during a maintenance window) |
| **Conflicting evidence** | Two sources disagree (security log flags a mailbox rule; a change ticket says it was requested) |
| **Severity edge** | Clearly an event; *severity* is debatable (valid-credential login from a new ASN for a low-priv account) |
| **Disposition edge** | `monitor` vs `escalate` both defensible (low-signal periodic beacon timing, no second indicator) |
| **Benign-mimicking-malicious** | False-positive-prone living-off-the-land (`regsvr32` loading a DLL — loader OR installer) |

Each fixture line records its `ambiguity_axis` and `intended_disagreement` as
metadata. The case-authoring rule: write the evidence so *neither* call is obviously
wrong. If you can immediately tell the "right" answer, it's not ambiguous — rewrite
it.

> **Adversarial ≠ attack.** "Adversarial" here means *triage-ambiguous content*, not
> adversarial input to the guardrails. Prompt-injection / evasion is a different axis
> handled by the prompt firewall + semantic firewall. Conflating the two is a common
> mistake — keep the eval's purpose crisp.

---

## 3. 🎲 The divergence-capability trick (prove it deterministically)

Here's the subtle engineering problem: a *live* run (real Claude vs real OpenAI) is
the real test, but it's paid and non-deterministic. CI needs a **free, deterministic**
proof that the set is divergence-capable. How?

The deterministic backtest pairs `DeterministicDemoProvider` (triage) with
`HeuristicDemoAnalyst` (grader). The grader's rule (Lesson 36): it **clears
(downgrades to benign) odd-indexed non-benign cases**. And the demo triage marks a
case non-benign when its text contains a "high-tier" keyword (`powershell`,
`credential`, `mailbox rule`, `impossible travel`, `suspicious`, …).

So the cases are authored so the **odd-indexed** ones (`adv-ambiguous-0001/0003/...`)
contain a high-tier keyword → demo triage says *suspicious* → the heuristic grader
*clears* them → **guaranteed determination mismatch**, deterministically. Result:

```
deterministic backtest --dataset adversarial -> agreement 0.5  (4/8 mismatches)
```

vs. `1.0` on the curated set. The test asserts `determination_mismatches >= 1` and
`agreement_rate < 1.0`.

**Per-axis resolution.** A single agreement number hides *which* ambiguity is hard.
`BacktestReport.agreement_by_axis` (keyed on `ambiguity_axis`, carried through
`payload.source_metadata`) breaks it down: deterministically `disposition_edge`
agrees (0/1) while `dual_use_behavior`, `conflicting_evidence`, `severity_edge`, and
`benign_mimicking_malicious` each split. On a *live* run this is the real payoff —
you learn that two real models converge on, say, dual-use but diverge on
severity-edge, which is a concrete tuning signal, not just a score.

The important nuance: this keyword/odd-index trick makes the *deterministic pair*
diverge for CI, but the cases are **also** authored as genuine ambiguity for the live
models — we didn't fit the cases to the demo grader's quirk and call it a day. The
deterministic divergence is the *floor* (proves the set can produce the signal); the
live run is the real measurement.

---

## 4. 🧱 Where it lives — a dedicated dir, not the default set

Spec 37 originally suggested authoring into `fixtures/curated/`. At implementation we
chose a **dedicated `fixtures/curated_adversarial/`** dir + its own manifest, and an
`AdversarialCuratedSource` (a 6-line subclass of `CuratedFixtureSource` that just
overrides the root). Why: adding cases to the default curated set would change the
counts every existing curated-set consumer sees. A separate source keeps the default
backtest reproducible and the adversarial run opt-in via `--dataset adversarial`.

> Design reflex: when you extend a shared fixture set, ask "who else reads this set,
> and will my additions move their numbers?" If yes, isolate.

---

## 5. 🔒 Synthetic-data discipline (the non-negotiable part)

Every value is fake and the set passes `tools/check_demo_safety.py`:
- IPs use **RFC 5737** documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`) — reserved precisely so docs/tests never collide with real space.
- Domains use `.test`; hosts/accounts/tickets are obvious placeholders.
- Onboarded through the **manifest review gate** (safety/content review, no raw
  source, no downloads) — the same contract as every other curated fixture.

This is the dataset-onboarding gate from AGENTS.md doing its job: even an *internal*
synthetic dataset goes through review, so "it's just test data" never becomes the
crack that lets real data in.

---

## 5.5 🔬 The live result — when the eval taught us about the eval

Running the set live (real Claude triage vs. real OpenAI analyst) produced a
genuinely instructive surprise: **100% agreement** on all 8 cases / all 5 axes —
even though the deterministic pair split 0.5 on the same cases. Two takeaways:

- **Engineered rule-ambiguity ≠ reasoning-model ambiguity.** Cases built to split a
  keyword engine don't split two competent reasoning models — they resolve the same
  "dual-use" or "conflicting-evidence" tension the same way. Coarse 4-bucket
  determinations make convergence even likelier.
- **The eval revealed a flaw in the eval.** The most likely cause isn't "the cases
  are easy" — it's that the analyst is shown **ThreatPrism's report** alongside the
  case. The independence rule guarantees a *different model*, but a model shown the
  verdict it's meant to independently check is **anchored**. A true blind second
  opinion grades the *case only*. So the next slice isn't more cases — it's
  *removing the anchor*.

This is the lesson's whole thesis paying off: because the deterministic floor proved
the pipeline *can* detect disagreement, a live 100% is interpretable — it points at
the methodology (anchoring), not at "the feature is broken." An eval you can reason
about tells you where to look next.

**The fix: blind-analyst mode.** `MockAnalyst(blind=True)` / `backtest
--blind-analyst` withholds the ThreatPrism report from the analyst prompt — it
grades the *case only*. The system prompt was generalized so blind and anchored
differ by exactly one variable: the report's presence. That makes the next live run
a clean A/B — if blind agreement drops below anchored, anchoring was masking real
divergence; if it stays at 100%, the cases really are easy for reasoning models.
Bonus: withholding the verdict also *reduces* what egresses to the third-party
provider — a privacy win that falls out of better methodology.

**The A/B result — first pass, then a correction.** The first run returned **blind =
anchored = 1.0, identical**, and I wrote "anchoring ruled out." That was *wrong*, and
the way it was wrong is the real lesson. The "blind" mode stripped only the top-level
`threatprism_report` key from the prompt — but a triaged `CaseRecord` carries the
verdict on `case.triage_report`, and the prompt serialized the whole case. **The
report leaked into the "blind" prompt anyway**, so the "blind" run was just a second
anchored run. Of course it was identical.

The tell that caught it: even "blind," the analyst's confidence matched ThreatPrism's
to two decimals on every case, and tracked ThreatPrism's run-to-run wobble — which a
genuinely blind grader cannot do. After fixing `_build_prompt` to exclude
`triage_report` (regression test
`test_blind_analyst_does_not_leak_report_via_case_triage_report`), the corrected A/B:

| Analyst mode (post-fix) | Agreement | Det mismatch | Confidence delta |
|-------------------------|-----------|--------------|------------------|
| Anchored                | 1.0       | 0            | flat 0.0 (parrots the report) |
| **True blind**          | **0.833** | **1** (adv-0004) | varies, mean 0.042 |

**Blind ≠ anchored. Anchoring was the dominant cause of the 100%, not convergence.**
Once the leak closed, the disagreement pipeline fired on real models: `adv-0004`
split `benign` (ThreatPrism) vs `suspicious` (blind analyst) → a real
`DisagreementRecord`. *Caveats kept honest:* the confidence signal is weak (the blind
analyst sits near a constant 0.70), blind mode hit 2 schema-validation failures (6/8
graded), and N is small. The meta-lesson: **a "blind" claim is a data-flow claim** —
test it against a realistically-triaged case, not a hand-built stub whose
`triage_report` happens to be empty. The eval revealed a flaw in the eval; then a
*deeper* flaw in the fix to that flaw. Rigor is iterative.

**The schema-failure follow-up: the report was also a hidden *schema crutch*.** Why
did blind mode lose 2 of 8 gradings to `schema_validation_failure` when anchored lost
none? Same root cause as the leak, one layer down. `AnalystFeedbackCreate` requires
`analyst_final_disposition` to be a `Disposition` enum (`close|monitor|escalate|
needs_more_info`), but the analyst system prompt named the field *without listing its
allowed values*. Anchored mode got away with it because the report it was shown
contained a valid disposition — an accidental few-shot example. Blind, with no report,
the model free-styled a disposition that failed validation (fail-closed, so it was
counted, never fabricated). The fix derives every required enum's vocabulary straight
from the schema enums into the prompt (`_vocab()`), so the prompt can't drift from
`AnalystFeedbackCreate` and a blind analyst is told the exact closed vocabulary the
report used to leak. Lesson: **when you remove an information channel, audit what
*else* was silently riding on it** — here the report was carrying both the verdict
(anchoring) and the schema's allowed values (a structure crutch).

**Confidence-delta capture (the instrument that exposed the leak).** `BacktestReport`
records each `confidence_delta = |analyst_confidence − triage_confidence|` and a
summary (mean/max/count over 0.2). Two models can land in the same determination
bucket while being *very* differently confident — that gap is the soft-disagreement
signal the coarse bucket throws away. This metric is what *caught* the blind-mode bug:
an exact-0.0 delta on every "blind" case was too clean to be real, and pulling that
thread found the leak. Post-fix, the blind deltas go non-zero (though weak — the blind
analyst is near-constant ~0.70). The arc of this lesson is the method itself:
**measure → distrust a too-clean result → find the hidden channel → re-measure.** Each
step was cheap (cents) and each narrowed — or corrected — the question.

> Career framing: "My adversarial set hit 100% agreement live. Instead of declaring
> success, I asked *why* — and realized the 'independent' analyst was being shown the
> verdict it was grading. That's residual circularity even with a different model. The
> fix is a blind analyst, and I only knew to look there because the deterministic
> baseline had already proven the pipeline could detect disagreement."

## 6. 🎤 Interview talk track

> "Our first live backtest hit 100% agreement, which I reported as a plumbing
> validation, not a quality result — the corpus was too clear-cut to exercise
> disagreement detection. So I built an adversarial dataset: eight synthetic cases,
> each engineered around a specific ambiguity axis — dual-use, conflicting evidence,
> severity-edge, disposition-edge, benign-mimicking — where two competent analysts
> could defensibly disagree. The tricky part was proving it's divergence-capable
> *deterministically* in CI without paying for models: I authored the cases so the
> deterministic demo triage and the heuristic grader diverge, giving agreement 0.5
> vs. 1.0 on the clean set, while keeping the cases genuinely ambiguous for the real
> models. All synthetic — RFC 5737 IPs, .test domains, through the same manifest
> review gate. The principle: an eval that can't produce the signal you're measuring
> can't validate anything."

---

## 7. 🗂️ Quick reference card

| Thing | Value |
|---|---|
| Fixtures | `fixtures/curated_adversarial/` (8 synthetic cases + manifest) |
| Source | `AdversarialCuratedSource` (subclass of `CuratedFixtureSource`) |
| Run | `python -m threatprism.demo.backtest --dataset adversarial [--live]` |
| Axes | dual-use, conflicting-evidence, severity-edge, disposition-edge, benign-mimicking |
| Deterministic result | agreement **0.5** (4/8 mismatches) vs 1.0 on curated |
| Per-axis breakdown | `agreement_by_axis` (axis → graded/mismatches); `disposition_edge` agrees, other 4 split |
| Divergence trick | odd-indexed cases carry a high-tier keyword → grader clears → mismatch |
| Safety | RFC 5737 IPs, `.test` domains, manifest review gate, demo-safety clean |
| Tests | `tests/test_adversarial_dataset.py` (loads / divergence-capable / queue) |
| Principle | an eval dataset must be able to produce the signal it measures |
