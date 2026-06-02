# Spec 37 — Adversarial / Ambiguous SOC Eval Dataset (Exercise Disagreement Detection)

Status: **proposed** (not implemented). Planned 2026-06-02 as the follow-up to the
first live two-model backtest ([docs/LIVE_BACKTEST_FINDINGS.md](../LIVE_BACKTEST_FINDINGS.md)).

## 1. Problem

The first live Evolution 2 backtest (real Claude triage vs. independent real OpenAI
analyst) returned **100% agreement** over the curated corpus. That validated the
end-to-end plumbing — but it did **not** exercise the feature the backtest exists to
support: **disagreement detection** (`DisagreementRecord` → `/queues/manager-review`).
The curated corpus is unambiguous (20 benign / 7 suspicious, no malicious), so two
competent models had nothing to disagree about.

We cannot conclude anything about triage quality, severity calibration, or the
disagreement pipeline until we run against cases where **two competent analysts could
reasonably disagree**. This spec plans a synthetic adversarial/ambiguous dataset to
create that divergence on purpose — without real data, downloads, or new attack
surface.

## 2. Goal and scope

**Goal.** A small, hand-authored, fully synthetic set of SOC cases engineered so that
independent triage of the same case can land on *different* determinations,
severities, or dispositions — populating `DisagreementRecord`s and the manager-review
queue so the disagreement path is actually tested (deterministically and, when gated,
live).

**In scope:**
- A new curated fixture set of ambiguity-engineered cases.
- A documented **ambiguity taxonomy** (each case targets one axis).
- A way to run the backtest over the adversarial set.
- Deterministic tests proving the set is *divergence-capable*.

**Out of scope / explicitly NOT this spec:**
- Real organization data, real IPs/hosts/domains/tenant IDs, real PHI, or dataset
  downloads (AGENTS.md hard rules — all cases are hand-authored synthetic).
- Prompt-injection *attacks* as the ambiguity axis (that is a guardrail-evasion
  concern already covered by the prompt-firewall + semantic firewall + the sanitized
  injection fixtures; this spec is about **triage ambiguity**, not injection).
- Establishing a "ground-truth correct" label per case. The point is *reasonable
  disagreement*, not a graded answer key (see §4).
- Any change to defaults, gates, or `ALLOW_REAL_ACTIONS`.

## 3. Ambiguity taxonomy (each case targets one axis)

A case is "adversarial/ambiguous" when the *evidence as presented* genuinely supports
more than one defensible triage call. Target axes:

| Axis | What makes it ambiguous | Example shape (synthetic) |
|------|-------------------------|---------------------------|
| **Dual-use behavior** | Same action is normal admin OR attacker TTP | Encoded PowerShell from a service account; `net user` enumeration during a known migration window |
| **Conflicting evidence** | Two sources disagree | Security log flags a new mailbox forwarding rule; a change ticket says it was requested (expand the existing single conflict case) |
| **Severity edge** | Clearly an event; severity debatable | Successful auth from a new ASN for a low-privilege vs. high-privilege account |
| **Disposition edge** | `monitor` vs. `escalate` both defensible | Low-signal beacon-like timing with no second indicator |
| **Benign-mimicking-malicious / vice-versa** | False-positive-prone living-off-the-land | `rundll32`/`regsvr32` with arguments that are common in both legit software and loaders |

Each fixture carries an `ambiguity_axis` and a short `intended_disagreement` note in
its metadata (documentation, not a label the grader sees).

## 4. Design

### 4.1 Fixtures
- Hand-authored synthetic cases (8–12 to start), one per axis with 1–2 variants.
- Authored into the **hand-authored curated contract** (`fixtures/curated/`), not the
  third-party-dataset-derivative contract (`fixtures/curated_datasets/`), because these
  are our own synthetic cases with no third-party license.
- Onboarded through the existing **manifest review gate** (`fixtures/curated/manifest.json`)
  — explicit review before any fixture is tracked, same as today's curated set.
- All values fake; `tools/check_demo_safety.py` must pass.

### 4.2 Running the backtest over the set
Two candidate mechanisms (decide at implementation):
- **(A) A selectable source:** add an `AdversarialCuratedSource` and a
  `backtest --dataset adversarial` option that seeds it instead of/alongside the
  default curated set.
- **(B) A tag filter:** tag adversarial fixtures in the existing manifest and let
  `--dataset` select by tag.

Preference: **(A)** — explicit, no coupling to the default corpus, and keeps the
default backtest reproducible. Reuses `DemoSeeder.seed(..., limit=N)` for cost-minimal
smoke runs.

### 4.3 Success signal
The backtest already computes `agreement_rate`, `determination_mismatches`,
`severity_mismatches`, and `threatprism_flagged_analyst_cleared`. On the adversarial
set we **expect** `agreement_rate < 1.0` and a populated manager-review queue. The
point is not "agreement is bad" — it is that the set is *capable* of producing
disagreement, so a future run that shows 100% agreement would be a real signal (the
models genuinely converge) rather than an artifact of a too-easy corpus.

## 5. Acceptance criteria

- **Deterministic (free, CI):** running the backtest with the `HeuristicDemoAnalyst`
  over the adversarial set produces **≥1 determination or severity mismatch** — i.e.,
  the set is divergence-capable without any live provider. A test asserts this.
- **Disagreement plumbing:** at least one case produces a `DisagreementRecord` that
  surfaces in `/queues/manager-review` (test via the service/API path).
- **Safety:** `tools/check_demo_safety.py` passes; no raw real values; fixtures pass
  the curated manifest review gate; full suite still green.
- **Gated (owner-run, paid):** a live `--live --dataset adversarial` run is documented
  in `LIVE_BACKTEST_FINDINGS.md` with the resulting agreement rate and any
  flagged-then-cleared cases. (Same "ask before paid run" + spend-cap discipline.)
- **Docs:** README dataset/policy section, `docs/DATASET.md`, the checklist, and a
  lesson updated; the ambiguity taxonomy documented.

## 6. Data and code touchpoints

- `fixtures/curated/` + `fixtures/curated/manifest.json` — new adversarial fixtures + review gate
- `src/threatprism/demo/seeding.py` — `AdversarialCuratedSource` (option A) or tag filter
- `src/threatprism/demo/backtest.py` — `--dataset` selection
- `tests/test_backtest.py` / a new `tests/test_adversarial_dataset.py` — divergence-capable + disagreement-surfaces tests
- `docs/DATASET.md`, `docs/LIVE_BACKTEST_FINDINGS.md`, `docs/WORKING_CHECKLIST.md`, Lessons

## 7. Threat-treatment considerations

No new trust boundary: the cases are synthetic and flow through the same intake +
guardrail pipeline as any case. The dataset-onboarding gate (AGENTS.md / curated
manifest review) is the relevant control and is satisfied by hand-authoring +
review. This spec does **not** re-open any Avoid/Gated decision in
[spec 21](21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md). Note: "adversarial" here
means *triage-ambiguous content*, not adversarial input to the guardrails — if a
fixture also carries injection-flavored text, the existing prompt-firewall /
quarantine path governs it unchanged.

## 8. Open questions (resolve at implementation)

1. Source-selection mechanism: (A) dedicated source vs. (B) manifest tag — §4.2 leans (A).
2. Set size: start 8–12 cases; expand per axis if divergence is too sparse.
3. Should the deterministic `HeuristicDemoAnalyst` be tuned to diverge on these axes,
   or do the cases need to be authored so *any* reasonable grader diverges? (Prefer
   the latter — author genuine ambiguity rather than fitting the demo grader.)
4. Do we want a per-axis agreement breakdown in `BacktestReport` (which axes converge
   vs. diverge)? Likely yes — pairs well with the no-report-reason counting follow-up.
