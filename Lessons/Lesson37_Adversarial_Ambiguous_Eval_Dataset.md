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
