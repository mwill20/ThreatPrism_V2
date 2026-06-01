# 🎓 Lesson 28: The Proving Ground — Running End-to-End and What ThreatPrism Actually Produces

## 🛡️ Welcome Back, Security Analyst!

You've built and reviewed every component. But here's the question that matters
most: **when you point this thing at a SOC dataset, what comes out the other end,
and what do you do with it?** 🔍 Today we run the whole machine on its proving
ground — `src/threatprism/demo/run_soc_demo.py` — and trace exactly what a user
receives: the **triage report**, and the **analyst feedback loop** that turns
disagreement into tuning signal.

This is the lesson that answers "what is this tool *for*."

---

## 🎯 Learning Objectives

By the end of this lesson you will be able to:

- Run ThreatPrism end-to-end against a SOC dataset with one command
- Name every field of the triage report and what an analyst does with it
- Explain the analyst feedback loop and why it is the backbone of model tuning
- Read the end-to-end summary and tell "it works" from "it correctly did nothing"
- Map the three future runtime evolutions onto the existing pipeline

**Time estimate:** 30 minutes | **Prerequisites:** Lesson 02 (Schemas/Service), Lesson 06 (Triage/Reports), Lesson 27 (Dataset Onboarding)

---

## 🧠 What This Component Does — Plain English

`run_soc_demo` is a **proving ground**: it seeds all three reviewed
`fixtures/curated_datasets/` families (32 cases) through the *real*
`create_case` + `run_triage` pipeline, then queries the metrics and read-model
endpoints and prints a summary. No SOAR, no live LLM, no production environment —
just proof that realistic SOC data flows through intake, the four guardrail
layers, deterministic triage, persistence, and observability, and produces
coherent, role-safe output.

The output it summarizes is the thing the whole project exists to produce: a
**triage report** per case. That report is what an analyst consumes.

**Real-world analogy:** It's a flight test. You don't certify an aircraft by
reading the blueprints — you fly it through a profile and watch the instruments.
`run_soc_demo` flies a SOC dataset through the system and reads the instruments
back to you.

---

## 🔵🟡🔴 Career Lens — Three Perspectives on This Component

### 🔵 Analyst Lens — What a SOC Analyst Sees Here

The output is the difference between opening a raw SIEM alert and opening a SOAR
case that has already been enriched and drafted. ThreatPrism hands you a
determination, a severity, findings each tied to the evidence that supports them,
an ATT&CK mapping, competing hypotheses, and a list of what it *didn't* check. Your
job shifts from "produce the first analysis" to "verify, correct, decide." When you
disagree, you record it — and that disagreement is captured, not lost.

**SOC parallel:** It's a SOAR playbook that has run enrichment and drafted the case
narrative for you — except the draft is evidence-grounded and your correction
becomes a measurable tuning signal.

---

### 🟡 Engineer Lens — What a Cybersecurity Engineer Builds Here

The run harness is a thin **orchestration + observability** layer over components
that already exist: it calls `DemoSeeder.seed()`, then `get_operational_metrics()`
and `list_case_read_models()`, and shapes the result into a sanitized, serializable
`SocDemoRunSummary`. The engineering decision worth owning is that the *proof of
correctness is itself a typed, tested artifact* (`SocDemoRunSummary` + four
regression tests), not a one-off script — so "does it work" has a regression gate,
not a manual demo.

**Engineering decision to own:** Why the end-to-end summary is a Pydantic model
with an asserting test (`tests/test_soc_dataset_run.py`) rather than print
statements — because "it works on a dataset" is a claim that must survive
refactors, so it gets a test like any other invariant.

---

### 🔴 AI Security Engineer Lens — What an AI/ML Security Engineer Watches For

Two things. First, **the feedback loop is the tuning and drift-detection surface**:
`DisagreementRecord` is where human ground truth meets model output, and at scale
it is how you'd detect a model degrading or being gamed. Second, **the honest-scope
boundary**: the run proves the *pipeline* works, not the *model's judgment* —
conflating those is exactly the overreliance failure the guardrails exist to
prevent. An AI security engineer insists the summary says so explicitly (it does),
so no one mistakes "32 cases flowed through" for "the AI triages well."

**AI security surface:** Model drift / overreliance — the disagreement metric is
the instrument that would catch a real model going wrong, and the scope disclaimer
is the control against mistaking pipeline correctness for verdict quality.

---

## 🗺️ Where This Fits in the System

```
fixtures/curated_datasets/ (32 cases)
   → DemoSeeder.seed()  → create_case() + run_triage()  → 4 guardrail layers
                                                          → TriageReport (per case)
                                                          → SQLite
   → get_operational_metrics() + list_case_read_models()
   → SocDemoRunSummary  ──►  printed proof + JSON
                  ▲
          [THIS LESSON]
   ── later: POST /analyst-feedback → DisagreementRecord → tuning signal
```

Remove this harness and you lose the single command that demonstrates the whole
system works on real-shaped data — the answer to "show me it runs."

---

## 🔑 Key Concepts

### The Triage Report
The per-case deliverable (`TriageReport`, [cases/schemas.py:205](../src/threatprism/cases/schemas.py)): determination, severity, disposition, confidence, evidence-cited findings, ATT&CK mappings, hypotheses, simulated (never executed) actions, and an explicit `limitations` list. Every cited `evidence_id` must exist, or the report is rejected.

### The Analyst Feedback Loop
`POST /cases/{id}/analyst-feedback` → `submit_feedback()` ([cases/service.py:446](../src/threatprism/cases/service.py)) → `DisagreementRecord` ([cases/schemas.py:255](../src/threatprism/cases/schemas.py)) capturing `determination_mismatch`, `severity_mismatch`, `disposition_mismatch`, and `confidence_delta`. This is the tuning signal.

### "It works" vs "it correctly did nothing"
The run shows `blocked_by_guardrail=1` (the firewall fired on a real injection — proof of action) **and** empty review queues (already-tokenized PHI correctly didn't re-flag — proof of correct *inaction*). Both are success.

---

## 📝 Code Walkthrough

### The Run, End to End

```python
# src/threatprism/demo/run_soc_demo.py — run_soc_demo()
result = DemoSeeder(service).seed([CuratedDatasetSource()])      # seed + triage 32 cases
metrics = service.get_operational_metrics()                       # read the instruments
manager_queue = service.list_case_read_models(manager_review_required=True)
healthcare_queue = service.list_case_read_models(healthcare_review_required=True)
```

**Line-by-line breakdown:**

| Step | What it does | Why it matters |
|------|-------------|----------------|
| `DemoSeeder.seed([CuratedDatasetSource()])` | Replays all 3 families through the real intake + triage path | Proves the pipeline, not a mock |
| `get_operational_metrics()` | Aggregates triage status, severity, determination, guardrail blocks | The observable proof |
| `list_case_read_models(...)` | Role-safe per-case view with review flags | Shows the output is queryable and masked |

**Design pattern used:** Facade — one `run_soc_demo()` call composes seeding,
triage, and read endpoints into a single sanitized result object.

### The Proof Is a Typed, Tested Artifact

```python
# src/threatprism/demo/run_soc_demo.py — SocDemoRunSummary
class SocDemoRunSummary(BaseModel):
    seeded_total: int = 0
    by_family: dict[str, int] = Field(default_factory=dict)
    triage: dict[str, int] = Field(default_factory=dict)
    severity: dict[str, int] = Field(default_factory=dict)
    guardrails: dict[str, int] = Field(default_factory=dict)
    ...
```

> ⚠️ **Common pitfall:** Treating the summary as a demo print-out. It is a
> regression contract — `tests/test_soc_dataset_run.py` asserts the seeded counts,
> the terminal-status invariant, that the firewall fired, and that the summary
> leaks no raw identifiers. If a refactor breaks the end-to-end flow, a test fails.

---

## 🧪 Hands-On Exercises

> Before starting: `cd C:\Projects\ThreatPrismV2`; deps installed.

### 🔬 Exercise 1: Run the Whole System on a SOC Dataset

```powershell
$env:PYTHONPATH="src"
python -m threatprism.demo.run_soc_demo
```

📊 **Expected output (excerpt):**
```
Seeded 32 cases (skipped 0) through real intake + triage:
  - deepset_prompt_injection: 12
  - otrf_soc_telemetry: 8
  - synthea_healthcare: 12

Triage outcome (all terminal - nothing left pending):
  completed=31  blocked_by_guardrail=1  needs_review=0  failed=0  queued=0  running=0
```

✅ **You succeeded if:** 32 cases seed, 31 complete, and exactly the prompt-firewall block shows `blocked_by_guardrail=1`.

---

### 🔬 Exercise 2: Confirm the End-to-End Regression Gate

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest tests/test_soc_dataset_run.py -q -p no:cacheprovider
```

📊 **Expected output:**
```
....
4 passed
```

✅ **You succeeded if:** all 4 pass — including `test_prompt_firewall_fires_on_dataset_content`.

---

### 🔬 Exercise 3: Read "It Works" vs "It Correctly Did Nothing"

Run Exercise 1 again and find these two lines:

```
Guardrail blocks:      1 (prompt firewall fired on retained injection text)
Manager-review queue:  0    Healthcare-review queue: 0
```

✅ **You succeeded if:** you can explain why the empty queues are *correct* (curated
fixtures are post-sanitization snapshots, so already-tokenized PHI does not
re-flag) — not a bug.

---

## 📚 Interview Preparation

### 🟡 Cybersecurity Engineering Interview

**Q:** You built a system that triages SOC cases. How do you prove it actually
works end-to-end without a live SOAR or LLM, and how do you keep that proof from
rotting?

**A:** I replay a reviewed SOC dataset through the real intake + guardrail + triage
+ persistence path — not a mock — and read back the operational metrics: every case
reaches a terminal status, the prompt firewall demonstrably fires on retained
injection content, and the severity distribution is coherent. The proof is a typed
summary object with a regression test asserting the invariants, so a refactor that
breaks the flow fails CI. And I keep the scope honest: this proves pipeline
correctness, not model judgment, because the provider is deterministic.

*Why this answer works:* Shows you distinguish integration proof from unit tests and
treat "it works" as a maintained invariant, not a one-time demo.

---

### 🔴 AI Security Engineering Interview

**Q:** Where in this system would you detect a model that's silently degrading or
being manipulated, and what makes that signal trustworthy?

**A:** The analyst feedback loop. Every case the analyst reviews produces a
`DisagreementRecord` comparing the analyst's determination/severity/disposition to
the model's, aggregated into disagreement metrics. A rising disagreement rate — or a
spike concentrated in cases the model called benign — is the drift/manipulation
signal. It's trustworthy only if the human label is independent of the model, which
is exactly why the future analyst-mock evolution requires a *different* LLM to
generate the comparison verdict, never the triage provider grading itself.

*Why this answer works:* Identifies the human-in-the-loop disagreement metric as the
drift instrument and names the independence requirement that keeps it valid.

---

## ✅ Key Takeaways

- `run_soc_demo` is the one-command proof the system works end-to-end on real-shaped SOC data
- The per-case deliverable is the evidence-grounded `TriageReport` — what an analyst verifies and decides on
- The analyst feedback loop (`DisagreementRecord` → metrics) is the built-in tuning/drift signal
- Success includes both action (firewall fired) and correct inaction (no false re-flag)
- The three future evolutions are deployment patterns over this same core — gated on a real `TriageProvider`

---

## 📋 Quick Reference Card

| Item | Value |
|------|-------|
| File | `src/threatprism/demo/run_soc_demo.py` |
| Entry point | `run_soc_demo()` / `python -m threatprism.demo.run_soc_demo` |
| Output | `SocDemoRunSummary` (seeded counts, triage outcome, severity/determination, guardrail blocks, queue counts, samples) |
| Per-case deliverable | `TriageReport` ([cases/schemas.py:205](../src/threatprism/cases/schemas.py)) |
| Feedback loop | `submit_feedback()` → `DisagreementRecord` → `/metrics` |
| Test file | `tests/test_soc_dataset_run.py` |
| Runbook | `docs/runbooks/RUN_AGAINST_SOC_DATASET.md` |
| Value + roadmap | `docs/PRODUCT_VALUE_AND_ROADMAP.md` |

---

## 📌 Implemented vs. Recommended

### What This Project Implements ✅
- End-to-end SOC dataset run with a typed, tested summary — `run_soc_demo.py`, `tests/test_soc_dataset_run.py`
- Analyst feedback + disagreement metrics — `submit_feedback()` at [cases/service.py:446](../src/threatprism/cases/service.py)
- Evidence-grounded, guardrail-validated triage reports — `run_triage()` pipeline

### General Best Practices — Recommended but Not Implemented Here
- Real `TriageProvider` (LLM-backed) behind the existing `Protocol` — `Recommended (not implemented here; gated)`
- Analyst-mock harness using a *second, independent* LLM for batch backtesting (Evolution 2) — `Recommended (not implemented here; gated)`
- Drift dashboards over the disagreement metric — `Recommended (not implemented here)`

---

## 🚀 Where This Goes Next

The three runtime evolutions — batched benign (SOAR catch-all), batch over
analyst-handled cases (tuning loop), and single event-driven live co-pilot — are
documented in [`docs/PRODUCT_VALUE_AND_ROADMAP.md`](../docs/PRODUCT_VALUE_AND_ROADMAP.md).
All three are gated on opening the real-LLM gate; until then a curated SOC dataset
stands in for the SOAR feed.

### 🔁 Sibling proving grounds (same pipeline, different question)

`run_soc_demo` answers "does it work end to end?" Two siblings reuse the same real
intake + triage path to answer the *product* questions, runnable today on the demo
provider (`--live` for a real provider is owner-run):

- **Evolution 1 — auto-close delta** (`python -m threatprism.demo.auto_close_delta`):
  a naive SOAR rule auto-closes anything the *source* didn't mark high/critical
  (independent of ThreatPrism, so the comparison isn't circular); the **catch** =
  cases that rule would close but ThreatPrism flags non-benign — the false negatives
  a cheap auto-close would have buried. On the curated corpus: 31 triaged, all
  auto-closeable, **8 caught**. See `src/threatprism/demo/auto_close_delta.py` and the
  "Evolution 1" section of `docs/runbooks/RUN_AGAINST_SOC_DATASET.md`. The number that
  matters isn't the auto-close rate — it's the catch count.
- **Evolution 2 — backtest** (`python -m threatprism.demo.backtest`): grades triaged
  cases against an independent analyst and surfaces where they diverged (the tuning
  signal). Governed spend on both LLMs (Lesson 31).

**Modification challenge:** Add a `disposition` distribution to `SocDemoRunSummary`
(it already pulls `report_decisions`), update the human render, and extend
`tests/test_soc_dataset_run.py` to assert it. ~20 minutes, and you'll have traced
metrics → summary → test end to end.

*Remember: a triage report is a starting point for a human decision, never the decision itself.* 🛡️
```
