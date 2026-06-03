# Spec 38: RGOI Learning Loop & Triage-Context Integration (Design-Only, Gated)

## Status

**DESIGN-ONLY. NOT IMPLEMENTED. GATED.** No code, no routes, no provider calls, no
dependencies are added by this spec. It designs the two halves of the original CSI/RGOI
vision that [spec 23](23_CSI_RGOI_FOUNDATION.md) deliberately left out of scope:

- **(A) Retrieval-into-triage** — let governed CSI/RGOI cognition provide context to
  *both* the analyst (already possible via `/csi/*`) and the **ThreatPrism triage LLM**
  (not currently wired — `cases/service.py` has zero CSI references).
- **(B) Human-approved write-back / learning loop** — let the KB *update* from analyst
  and AI feedback, with humans owning truth (currently out of scope: spec 23 forbids
  autonomous memory writes, knowledge approval workflows, and trust mutation).

Both halves are **Avoid** decisions in
[spec 21 — Treatment & Risk Register](21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md)
(RAG = **OT-L1**, memory/write-back = **OT-L8**). **Implementing either requires
re-opening spec 21 and re-reviewing the [LLM/ATLAS threat model](../threat-models/llm-agent-threat-model.md)
first** (see §7). This spec is the design that re-open would consume.

## Goal

Extend ThreatPrism from "governed read-only cognition the analyst consults manually" to
"governed cognition that (A) informs the triage model under control and (B) learns from
human-approved feedback" — **without** becoming unrestricted AI memory or an
auto-poisoning RAG surface. Preserve the existing invariants: evidence-first,
analyst-controlled, demo-safe, fail-closed, and **human truth ownership**.

## Non-Negotiable Principles

1. **The AI proposes; only a human promotes.** AI-authored cognition is created as
   `external_unreviewed` / non-authoritative (`review_status != approved`) and can never
   self-promote into the `approved_knowledge` tier. Promotion is a **deterministic,
   human-gated** action — never a model decision (per the global rule: probabilistic
   models never gate a security decision or data write).
2. **Reverse-deny by default.** Both retrieval-into-triage and write-back are **off**
   unless explicitly enabled per role and per tenant. Disabled = byte-for-byte the
   current behavior.
3. **Retrieved content is untrusted input.** Every retrieved passage crosses the
   pre-model trust boundary and gets the *same* treatment as inbound case text:
   `sanitize_text()`, the prompt firewall, the semantic firewall, and healthcare
   safeguard scan — applied to the *passage*, not just the case.
4. **No raw sensitive data in the KB, ever.** Stage-1 tokenization
   (`_apply_healthcare_safeguards`) must run before any write; the write-back path
   inherits the permanent-redaction guarantee (PHI/PII/secrets never stored raw, never
   rehydrated).
5. **Everything is audited and tamper-evident.** Every retrieval call and every
   write/promotion is an `AuditEvent` mirrored to the hash-chained audit log
   (`persistence/hash_chain.py`).

## In Scope (design only)

- (A) A governed retrieval step inside `_prepare_case_for_model()` that injects
  approved-tier cognition into the triage prompt as **cited, sanitized context**.
- (A) Surfacing the same retrieval to the analyst alongside the report (extends the
  existing `/csi/*` read path; no new authority).
- (B) A `KnowledgeProposal` flow: AI- or analyst-authored candidate cognition created
  non-authoritative, routed to a **human approval queue**, promoted only by an
  authorized human into the `approved_knowledge` tier.
- (B) A learning signal from the existing disagreement loop (`DisagreementRecord`) and
  AI-vs-human divergence telemetry → *candidate* proposals (never auto-approved).
- The control set required by the threat model "Before RAG" and "Before Memory"
  preconditions (§7), mapped to existing ThreatPrism primitives.
- Poisoned-corpus and unsafe-write eval fixtures (design of the test surface).

## Out Of Scope (unchanged from spec 23, restated)

- Autonomous memory writes; any AI self-promotion of knowledge.
- Trust-score mutation by the model; suppression publication.
- Live external RAG / web-search providers (e.g., Exa.ai) — see
  [FUTURE_ENHANCEMENTS.md](../FUTURE_ENHANCEMENTS.md).
- Live LLM/SOAR/cloud calls beyond the already-gated triage provider.
- Production multi-tenancy, production IdP, real PHI/PII/credentials, real remediation.

## Architecture — the two new edges

The CSI/RGOI foundation already owns the four tiers, object model, retrieval governance,
trust scoring, evidence alignment, lineage, and `/csi/*` read routes. This spec adds two
edges to that foundation:

```text
(A) Retrieval-into-triage
    run_triage -> _prepare_case_for_model
       -> rgoi.retrieve(case, role, tenant, purpose="triage_context")   [read, governed]
          -> per-passage: sanitize_text + prompt firewall + semantic firewall + healthcare scan
          -> evidence-ID binding (retrieved passages get evidence_ids)
       -> prompt = case (Stage-1 + Stage-2 tokenized) + cited approved-tier context
       -> provider.generate_report()
       -> validate_report_evidence() now also covers retrieved evidence_ids

(B) Human-approved write-back / learning loop
    analyst feedback / AI divergence -> KnowledgeProposal (review_status=external_unreviewed)
       -> Stage-1 tokenize the proposal body (no raw PHI/PII/secrets)
       -> human approval queue (role-gated)
       -> [human] approve -> promote to approved_knowledge tier (deterministic, audited)
       -> [human] reject  -> archived with reason (audited)
    Only approved_knowledge is retrievable into triage context (closes the loop safely).
```

**Why these two edges are separate threats.** Reading a poisoned KB entry steers the
model (indirect prompt injection, **OT-L1**); writing model output into the KB lets a
hallucination become "fact" (**OT-L8**). The approval gate in (B) is what makes (A)
safe: only human-approved cognition is ever retrievable into the prompt.

## Object Model Additions (design)

Reuse `CognitiveObject` (spec 23). Add:

- `KnowledgeProposal` = a `CognitiveObject` candidate with `review_status` in
  `{external_unreviewed, pending_human_review, approved, rejected}`, plus
  `proposed_by` (`analyst` | `ai_divergence` | `ai_triage`), `proposal_reason`,
  `source_case_id`, `evidence_refs`, and `deletion_owner`.
- `RetrievalContext` = the sanitized, cited bundle injected into the triage prompt:
  `[(object_id, snippet_tokenized, evidence_id, trust_score, retrieval_zone)]`, capped
  per role.

## 7. Threat-Model Re-Open (mandatory before any implementation)

This spec **does not authorize code**. Before implementation:

1. **Re-open [spec 21](21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md):** convert the
   **Avoid** decisions for **OT-L1** (RAG) and **OT-L8** (memory/write-back) into
   **Gated Mitigations**, with owner sign-off, per the register's own "When an Avoid
   decision is at risk" procedure.
2. **Re-review the [LLM/ATLAS threat model](../threat-models/llm-agent-threat-model.md)**
   and satisfy both precondition checklists below.

### Before RAG / Retrieval (acceptance gates for half A) — from the LLM threat model

- [ ] Retrieval source registry with `(source_id, trust_level, sensitivity_class)` per corpus.
- [ ] `sanitize_text()` applied to **every retrieved passage** (not just inbound case text).
- [ ] Healthcare safeguard scan applied to every retrieved passage.
- [ ] Evidence-ID binding so `validate_report_evidence()` covers retrieved content.
- [ ] Role and case scoping **at retrieval time** (not at render time).
- [ ] Poisoned-corpus fixtures in `tests/evals/`: malicious instructions in retrieved
      content, false evidence citations, prompt-exfil through retrieval.
- [ ] Per-role retrieval limits and an audit event for every retrieval call.
- [ ] **Added control:** the semantic firewall ([spec 32](32_SEMANTIC_PROMPT_INJECTION_LAYER.md))
      scores each retrieved passage (detector-not-gate), since retrieval is a new
      injection surface (OT-L1 ↔ OT-L11).

### Before Memory / Write-Back (acceptance gates for half B) — from the LLM threat model

- [ ] Memory record schema with `(source_case_id, role, sensitivity_class, provenance, ttl, deletion_owner)`.
- [ ] **Human approval workflow before any write** (the deterministic promotion gate).
- [ ] No raw PHI/PII/secrets in memory — Stage-1 tokenization runs before any write.
- [ ] Reverse-deny default: write-back off unless explicitly enabled per role.
- [ ] Tests for: unsafe/auto writes, overwrite attempts, cross-case scope leakage, TTL
      expiry, deletion paths, and **AI self-promotion attempts (must fail closed)**.

## 8. Acceptance Criteria (when eventually built)

- Disabled-by-default produces byte-for-byte current behavior (a regression test like
  the semantic-firewall "disabled-byte-identical" test).
- With retrieval enabled, the triage prompt contains only **approved-tier**, sanitized,
  evidence-bound context; a poisoned/unapproved object never reaches the prompt.
- An AI-authored proposal is always `external_unreviewed` and **cannot** be promoted
  without an authorized human action; an automated promotion attempt fails closed and is
  audited.
- Every retrieval and every promotion emits an `AuditEvent` that appears in the
  tamper-evident audit log and passes `verify_logs`.
- Stage-1 tokens never appear raw in any stored proposal or retrieved snippet.

## 9. Dependencies / Sequencing

- Builds on: CSI/RGOI foundation (spec 23), real-LLM provider (spec 33, gate open),
  semantic firewall (spec 32), tamper-evident audit log (spec on `hash_chain.py`).
- Sequencing: half **A** (retrieval-into-triage) can be built first behind its gate;
  half **B** (write-back) depends on A's approved-tier being the only retrievable source.
- **Cost note:** retrieval-into-triage increases prompt token count → re-validate the
  spend cap and metering (specs 35/36) before any live run; ask-before-paid still applies.

## 10. Honest Scope Statement

This is the design ThreatPrism would consume *if* the owner decides to open the RAG and
write-back gates. Until then, CSI/RGOI remains read-only and unconnected to the triage
model, and the KB does not learn. That is the correct, safe default — the value of this
spec is that the two highest-risk LLM surfaces (indirect injection, unsafe memory) are
designed *before* a line of code, with the controls enumerated and tied to existing
primitives.
