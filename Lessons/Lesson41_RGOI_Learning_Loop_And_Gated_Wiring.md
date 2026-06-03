# Lesson 41 — The RGOI Learning Loop & "Build It, Don't Connect It" 🧠🔌🚫

> Files: `src/threatprism/csi/learning_loop.py`, `src/threatprism/csi/triage_context.py`,
> `src/threatprism/csi/schemas.py` (`KnowledgeProposal`, `TriageContextBundle`),
> `src/threatprism/demo/run_rgoi_learning_demo.py`, `tests/test_rgoi_learning_loop.py`,
> `tests/test_rgoi_triage_context.py`, design in
> [`docs/specs/38_...`](../docs/specs/38_RGOI_LEARNING_LOOP_AND_TRIAGE_CONTEXT.md).
> Baseline: see [../docs/VALIDATION_BASELINE.md](../docs/VALIDATION_BASELINE.md).

## 1. 🎯 What this builds

Two halves of the CSI/RGOI vision that the read-only foundation (Lesson 18 / spec 23)
deliberately left out:

- **(B) Write-back / learning loop** — the knowledge base can now *update*: an AI (or
  analyst) proposes a candidate, and a human promotes it into the `approved_knowledge`
  tier. The KB learns from feedback.
- **(A) Retrieval-into-triage context** — a builder that turns approved-tier cognition
  into sanitized, evidence-cited context *ready* to inject into a triage prompt.

…and the most important design decision: **(A) is built but deliberately not connected
to the triage model.**

## 2. 🚦 Two surfaces, two threats — why one ships and one stays gated

| Edge | Threat | Decision |
|------|--------|----------|
| KB **read into the model** (RAG) | **OT-L1** indirect prompt injection — a poisoned KB entry steers the LLM | **Avoid** (gated): built the builder, did NOT wire it |
| KB **written by the AI** (memory) | **OT-L8** unsafe write-back — a hallucination becomes "fact" | **Mitigate** (implemented, demo-only) with a human gate |

The owner authorized building the write-back surface (OT-L8) with controls, while
keeping the read-into-model surface (OT-L1) closed. Building one without the other is a
deliberate, defensible posture — and it's only credible because a test *enforces* it
(§5).

## 3. 🔒 The hinge: deterministic human gate over a probabilistic proposal

```python
# learning_loop.py — the AI proposes...
proposal = loop.propose(..., author_type="ai", proposed_by="ai_triage")   # review_status = proposed

# ...but only a human (allowed role) may promote. AI/unauthorized fails closed.
def _enforce_human_gate(self, approver_role, proposal_id):
    if approver_role not in self.approver_roles:   # {analyst, engineer, manager_grc, admin}
        ...audit deny...
        raise PermissionError("The AI proposes; a human promotes.")
```

This is the global rule made concrete: **a probabilistic model never gates a data
write.** The AI's proposal is non-authoritative; promotion to "approved knowledge" is a
deterministic, role-checked, audited human action. `test_ai_cannot_self_promote_fail_closed`
proves an AI caller is rejected and the proposal stays un-promoted.

Three more controls ride along, reusing existing primitives:
- **Reverse-deny:** `KnowledgeLearningLoop(enabled=False)` by default — `propose` raises
  until explicitly enabled. Disabled = no behavior.
- **Stage-1 tokenization before any write:** the proposal's title/summary/claims go
  through `safeguard_text`, so a fake MRN or `sk-…` secret is tokenized *before* it ever
  enters the KB (`test_proposal_created_non_authoritative_and_stage1_sanitized`).
- **Audit per action:** propose / approve / reject / *denied* each emit an `AuditEvent`
  (ready for the tamper-evident audit mirror from Lesson 38).

## 4. 🧱 Retrieval context reuses governance, then hard-filters

`build_triage_context` doesn't re-implement access control — it calls the existing
governed `CognitiveRetrievalService.search` (tenant isolation, role/zone policy,
quarantine + stale exclusion) and *then* hard-filters to `approved_knowledge` +
`review_status == approved` + `validation_state == valid`. Belt and suspenders: only
human-approved cognition can become context, and each snippet is sanitized again.

## 5. 🧪 The negative test is the feature

The single most important test asserts what the code does **not** do:

```python
def test_triage_pipeline_does_not_consume_rgoi_context():
    src = Path("src/threatprism/cases/service.py").read_text()
    assert "build_triage_context" not in src
    assert "learning_loop" not in src
    assert "KnowledgeLearningLoop" not in src
```

This converts "we chose not to wire it" from a comment into a **regression-guarded
invariant**. The day someone adds RGOI context to the triage prompt, this test fails —
forcing them to re-open the OT-L1 Avoid decision in spec 21 first. A negative test is
how you make a gating decision durable instead of a promise someone forgets.

## 6. 🎓 Career framing

> "I built a knowledge-base write-back loop where the AI proposes and only a human
> promotes — a deterministic gate over a probabilistic suggestion, with reverse-deny,
> Stage-1 PHI/secret tokenization before any write, and full audit. I also built the
> retrieval-into-triage context but **left it disconnected on purpose**, because feeding
> a KB to the model is indirect-prompt-injection surface (OWASP LLM01). The disconnection
> isn't a TODO — it's enforced by a test that fails if anyone wires it in without
> re-opening the threat treatment. That's how you ship one risky surface while honestly
> holding another closed."

## 7. 🔭 What's still gated (the actual future enhancement)

To make this a live feature, in order: re-open **OT-L1** (spec 21) → wire
`build_triage_context` into `_prepare_case_for_model` with the "Before RAG" controls →
add persistence, HTTP write routes, and multi-tenancy for production. Until then it is a
demo-only, in-memory, disconnected capability — see the README "Future Enhancements"
section and [spec 38](../docs/specs/38_RGOI_LEARNING_LOOP_AND_TRIAGE_CONTEXT.md).
