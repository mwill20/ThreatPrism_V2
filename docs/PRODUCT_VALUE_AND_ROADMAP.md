# What ThreatPrism Produces, How It's Used, and Where It's Going

This document answers three questions directly: **what is the output, what does
the tool provide to a user, and how is it usable** — then lays out the three
runtime evolutions toward a real-LLM, analyst-in-the-loop deployment.

---

## 1. What ThreatPrism is, in one sentence

ThreatPrism is a **SOC triage co-pilot**: it takes a raw case (an alert plus its
evidence, events, and entities) and produces a structured, evidence-grounded,
guardrail-validated **first-pass triage report** — so an analyst starts from a
completed first analysis instead of a blank alert, and a manager gets governance
and tuning signal without touching raw sensitive data.

It is **not** an autonomous responder. It never executes actions
(`ALLOW_REAL_ACTIONS=false`), every report is marked `analyst_review_required`,
and a human decision is always the authority.

---

## 2. What it produces — the concrete output

### 2.1 The Triage Report (the core deliverable)

For each case, `run_triage()` produces a `TriageReport`
([cases/schemas.py](../src/threatprism/cases/schemas.py)). The fields are the
output an analyst consumes:

| Field | What it gives the analyst |
|-------|---------------------------|
| `determination` | The verdict: benign / suspicious / malicious-class |
| `severity` | low / medium / high / critical |
| `disposition` | Recommended next step (e.g., escalate, close) |
| `confidence` | 0.0–1.0 — how sure the tool is |
| `findings[]` | Each a titled, severity-rated observation **with cited `evidence_ids`** — no claim without evidence |
| `mitre_mappings[]` | ATT&CK techniques, each evidence-cited and confidence-scored |
| `grc_controls[]` | Category alignment only — explicitly *"not a compliance determination"* |
| `hypotheses[]` | Alternative explanations with confidence, so the analyst sees competing reads |
| `recommended_actions[]` / `simulated_actions[]` | Suggested next steps — **simulated, never executed** |
| `limitations[]` | What the tool did **not** access or check — honesty about blind spots |
| `analyst_review_required` | Always `true` — the human is the decision-maker |

The discipline that makes this trustworthy: **every cited `evidence_id` must
exist** (`validate_report_evidence()`), the output is regex-scanned for
overclaiming/compliance/secret leakage (`scan_output_policy()`), and any claim of
a real action is blocked (`enforce_action_safety()`).

### 2.2 The platform layer (around the report)

- **Role-filtered views** — analysts/engineers see security telemetry; manager/GRC,
  legal/privacy, audit, and AI views get it masked. Same record, different lens.
- **Operational metrics** (`GET /metrics`) — volumes, severity/determination
  distributions, guardrail blocks, and **disagreement rates**.
- **Review queues** (`GET /queues/manager-review`, `/queues/healthcare-review`).
- **Audit events** — every authorization and guardrail decision is recorded.
- **The analyst feedback loop** — see §4. This is the tuning backbone.

### 2.3 The executive summary (per-event and batch)

Two executive-summary surfaces are designed:

- **Per-event:** the `TriageReport.summary` field. With the deterministic provider
  it is canned boilerplate; the LLM (gated) fills it with real synthesis.
- **Batch:** a `BatchExecutiveSummary` (in `run_soc_demo`) that ranks cases
  **most-critical-first** with per-case **provenance** (`sha256` source hash) and
  **evidence-ID traceability** — the artifact an auditor reviews quickly. Its
  ranking and provenance are deterministic and usable today; its `narrative` is
  filled (metered + output-policy validated) when a real provider is active
  (`--live`) and stays empty (`pending_real_llm_provider`) for the deterministic
  demo. Nothing fake ships.

### 2.4 See it now

`python -m threatprism.demo.run_soc_demo` runs 32 SOC cases end-to-end and prints
these outputs — including the ranked batch executive summary. Add `--show-reports N`
to read full per-case reports (see
[runbooks/RUN_AGAINST_SOC_DATASET.md](runbooks/RUN_AGAINST_SOC_DATASET.md)).

---

## 3. How an analyst uses it ("hit the ground running")

Without ThreatPrism, an analyst opens a raw alert and starts from zero: pivot the
logs, look up indicators, map to ATT&CK, decide severity, write it up.

With ThreatPrism, the analyst opens the case and already has: a determination and
severity to confirm or overturn, findings each tied to the exact evidence that
supports them, the ATT&CK mapping pre-drawn, competing hypotheses surfaced, a list
of what the tool did *not* check, and recommended next steps to accept or reject.
The analyst's job shifts from *produce the first analysis* to *verify, correct,
and decide* — faster, and with a documented starting point.

The SOC analogy: it is the difference between a SIEM alert firing raw versus a
SOAR playbook having already enriched, correlated, and drafted the case — except
the draft is an evidence-grounded triage report, and the analyst's disagreement is
captured as tuning signal.

---

## 4. The feedback / tuning loop (already built)

This is the mechanism the evolutions below depend on, and it exists today:

```
Analyst reviews the report
  -> POST /cases/{id}/analyst-feedback   (analyst_determination, severity,
                                          confidence, final_disposition)
  -> submit_feedback()                   (cases/service.py)
  -> DisagreementRecord                  (determination_mismatch, severity_mismatch,
                                          disposition_mismatch, confidence_delta)
  -> disagreement metrics                (GET /metrics)
```

When the analyst's verdict differs from ThreatPrism's, that disagreement is
recorded structurally and aggregated. **That is the "where did the analyst and the
tool differ" signal** your tuning loop needs — already wired, currently exercised
against the deterministic provider.

---

## 5. The three runtime evolutions (roadmap)

> **All three are gated on opening the real-LLM gate** (a real `TriageProvider`
> implementation + the semantic firewall in
> [specs/32](specs/32_SEMANTIC_PROMPT_INJECTION_LAYER.md), per the threat-model
> re-review). Until then they are design targets. Each "pretends" a curated SOC
> dataset is the SOAR feed — no live SOAR integration is required to prove value.

### Evolution 1 — Batched benign (SOAR catch-all auto-close)

**Pattern.** Feed the high-volume benign stream a SOAR would auto-close.
**Goal.** Show ThreatPrism agrees (benign/low) at volume, and — more valuable —
surface the rare case the catch-all would have auto-closed but ThreatPrism flags
suspicious. This is throughput + safety-net validation.
**Reuses today:** batch seeding via `DemoSeeder`, metrics distributions, the
`run_soc_demo` aggregate summary.
**Status — built (deterministic core):** `src/threatprism/demo/auto_close_delta.py`
(`python -m threatprism.demo.auto_close_delta`). A naive SOAR rule auto-closes
anything the *source* did not mark high/critical (independent of ThreatPrism, so
the comparison isn't circular); the **catch** = cases that rule would close but
ThreatPrism flags non-benign. Over the curated corpus with the demo provider: 31
triaged, all 31 auto-closeable (no high inbound severities), **8 caught** (the OTRF
telemetry cases triaging to suspicious/high). Tests in `tests/test_auto_close_delta.py`.
**Still gated (owner runs):** the *real* auto-close rate + catch count over a
benign-heavy feed under `--live` with a real provider. No volume is fabricated.

### Evolution 2 — Batch over analyst-handled cases (backtest + tuning)

**Pattern.** Replay cases that were already worked by analysts, where the analyst
outcome is the ground truth. Because real analyst labels may be unavailable, the
analyst can be **mocked by a *different* LLM** producing the "analyst" verdict, so
ThreatPrism is never grading itself.
**Goal.** Compare every case ThreatPrism marked suspicious/malicious against the
analyst (or mock-analyst) outcome, and measure where they diverged — the cases an
analyst worked longer or decided differently. This is the **tuning/feedback loop
at batch scale**.
**Reuses today:** the entire feedback loop in §4 (`submit_feedback` →
`DisagreementRecord` → disagreement metrics).
**Status:** the harness is **built and runnable now** —
`python -m threatprism.demo.backtest` (`src/threatprism/demo/backtest.py`) grades a
batch with a deterministic stand-in analyst and emits a `BacktestReport` (agreement
rate; the `threatprism_flagged_analyst_cleared` divergence set). The OpenAI
`MockAnalyst` (independent of the Claude triage brain) drops in at the gate.
**Independence rule:** the mock-analyst LLM must be a different model/prompt path
than the triage provider, or the comparison is circular.

### Evolution 3 — Single event-driven (live co-pilot, human-in-the-loop)

**Pattern.** An analyst self-assigns a case, immediately pulls ThreatPrism's report
and triage details, and works it with the human in the loop — then submits
feedback.
**Goal.** Real-time analyst acceleration, with the **same disagreement/tuning loop
as Evolution 2** running continuously on live decisions.
**Reuses today:** the per-case API (`POST /cases`, `GET /cases/{id}/triage-report`,
the detail routes, role views), and the feedback loop in §4.
**Status — sub-slice 1 built (case ownership):** `POST /cases/{id}/assign`
(self-assign; roles `analyst`/`engineer`/`admin` only) and `POST /cases/{id}/release`
(owner-or-admin only), with `assigned_to`/`assigned_at` on the case and an audit
event per decision. `tests/test_case_assignment.py`. **Remaining:** the dashboard
feedback UI (sub-slice 2) and the live cadence with a real provider (owner-run).

### The common thread

Evolutions 2 and 3 are the **same tuning loop** at different cadences (batch vs.
live). Evolution 1 is the throughput/safety-net proof. None of them require a live
SOAR — a curated SOC dataset stands in for the feed. The single missing
foundation under all three is the **real `TriageProvider`** (and its gated
semantic-firewall defense), which is why that gate is the next real decision.

---

## 6. Honest scope today

- The active provider is the inert `DeterministicDemoProvider` (keyword-based). The
  pipeline, guardrails, persistence, observability, and feedback loop are real and
  proven end-to-end ([run_soc_demo](../src/threatprism/demo/run_soc_demo.py)); the
  *quality of the verdict* is not, because no real model is wired.
- The **real-LLM seam is built and tested** with no network (spec 33 deterministic
  core): the failure taxonomy, batching, untrusted-output validation, the Claude
  triage provider + narrative skeleton, and the OpenAI mock-analyst. The **live
  calls are gated** — open them with [runbooks/OPEN_REAL_LLM_GATE.md](runbooks/OPEN_REAL_LLM_GATE.md).
- Opening the gate also requires the semantic firewall ([spec 32](specs/32_SEMANTIC_PROMPT_INJECTION_LAYER.md))
  and the threat-model re-review staged in [spec 21](specs/21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md)
  (classifier surface = OT-L11; provider DoS = OT-L3).
- Until the gate opens, "pretend the dataset is the SOAR feed" is the correct way
  to demonstrate every evolution without a live integration.
