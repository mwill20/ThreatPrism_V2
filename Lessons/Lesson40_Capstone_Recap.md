# Lesson 40 — Capstone Recap: ThreatPrism End to End 🧭🏁

> The synthesis lesson. Where the earlier lessons each dissect one component, this one
> steps back to the whole system: what ThreatPrism *is*, how a case flows through it,
> the defenses, the three runtime evolutions, the integrity subsystem, and the
> engineering principles that recur. Baseline: see
> [../docs/VALIDATION_BASELINE.md](../docs/VALIDATION_BASELINE.md).

## 1. 🎯 What ThreatPrism is

A **SOC triage co-pilot backend.** It accepts a SOAR case payload, runs it through a
multi-stage guardrail pipeline, generates a structured triage report (deterministic
demo provider, or a real LLM under the gate), and returns role-filtered views. It is
security-first by construction: untrusted input, untrusted model output, PHI/PII, and
authorization are all treated as adversarial surfaces.

## 2. 🔄 The request lifecycle (the spine)

```
POST /cases
  -> normalize_soar_payload()        # source-specific SOAR adapter
  -> _apply_healthcare_safeguards()  # Stage-1 PHI/PII/secret tokenization at intake
  -> repository.save_case()          # persist tokenized content
  -> 202 Accepted

BackgroundTask: run_triage()
  -> _prepare_case_for_model()       # prompt firewall + TokenVault (Stage-2)
  -> _apply_semantic_firewall()      # Prompt Guard 2 detector (default-off)
  -> provider.generate_report()      # deterministic demo OR real LLM (Protocol)
  -> scan_output_policy()            # regex guardrails on output
  -> validate_report_evidence()      # every evidence_id must exist
  -> enforce_action_safety()         # blocks real_action_executed: true
  -> _rehydrate_report()             # restore safe Stage-2 tokens; Stage-1 stays redacted
  -> repository.save_report()
```

Two ideas worth carrying:
- **Two tokenization stages.** Stage 1 (healthcare) is *permanent* — PHI/PII/secrets
  are tokenized at intake and never rehydrated. Stage 2 (TokenVault) tokenizes security
  telemetry that *is* safe to restore after the report passes validation.
- **Fail closed everywhere.** Any guardrail issue sets `blocked_by_guardrail` and stops
  triage; any provider/parse/schema failure becomes a structured `TriageFailureReport`,
  never a silent pass.

## 3. 🛡️ The four-layer guardrail pipeline

Not interchangeable — each catches a different class, in a fixed order:

1. **Prompt firewall** (`guardrails/prompt_firewall.py`) — regex detection/quarantine of
   injection in inbound text; quarantine blocks triage.
2. **Healthcare safeguards** (`guardrails/healthcare.py`) — context-aware PHI/PII/secret
   detection (Stage-1 tokens, never reversed).
3. **Output policy** (`guardrails/policy.py`) — `PROHIBITED_PATTERNS` over the serialized
   report (overclaiming, action-execution, leaked secrets, clinical language).
4. **Evidence validation** (`guardrails/evidence.py`) — every cited `evidence_id` must
   exist; no hallucinated citations.

Layered on top (default-off, gated): a **semantic** prompt-injection firewall
(Prompt Guard 2) that is a *detector, never a gate* — it can escalate to quarantine/
review but never de-escalates the deterministic firewall.

## 4. 🔐 Identity, roles, and least privilege

- Auth modes: `none` (local dev, ack-gated), `demo_key`, and `external_oidc` (production
  readiness; local fake-JWKS verifier). `validate_runtime()` blocks unsafe modes in prod.
- **`?role=` is never authority** — the effective role comes from the authenticated
  identity; role-views mask security telemetry for non-analyst roles at read time.
- **Every authorization decision (allow *and* deny) is an `AuditEvent`.** Mutating case
  endpoints (assign/release/feedback) share one authz bar; feedback attribution is
  server-set, not client-claimed.

## 5. 🧪 The real-LLM seam and governance

A swappable `TriageProvider` Protocol — only `DeterministicDemoProvider` runs by
default; `ClaudeTriageProvider` drops in under the gate. Around it:
- **Spend governance** — per-call metering, a `SpendLedger`, a fail-closed per-run cost
  cap, and a sanitized `llm_call` audit (token counts + content *hashes*, never raw).
- **Independent analyst** — the OpenAI `MockAnalyst` is a *different* model so the
  comparison is never circular; its prompt egresses only Stage-1-tokenized content.

## 6. 🚀 The three runtime evolutions (all demonstrated)

The same engine at three cadences (curated SOC dataset stands in for the SOAR feed):

| Evolution | Cadence | Driver | Live? |
|-----------|---------|--------|-------|
| 1 — auto-close delta | batched benign | `demo/auto_close_delta.py` | deterministic; live owner-run optional |
| 2 — backtest + tuning | batch vs. independent analyst | `demo/backtest.py` | **live-verified** (two real models) |
| 3 — live co-pilot | single event, human-in-loop | `demo/run_copilot_demo.py` | **live-verified** ($0.005) |

Evolutions 2 and 3 are the **same disagreement/tuning loop** (`submit_feedback` →
`DisagreementRecord` → manager-review queue) at different cadences.

## 7. 🧾 The integrity / observability subsystem

Built this arc, in three composable steps:
1. **`HashChainedLog`** (`persistence/hash_chain.py`) — generic append-only, tamper-
   evident JSONL (`record_hash = sha256(prev_hash + canonical(payload))`); `verify()`
   detects edits, deletions, reorders.
2. **Two consumers** — `FailureLog` (LLM/analyst validation failures, with the
   *sanitized* offending value) and the **case audit-trail mirror** (wired at the
   `save_case` chokepoint, deduped by `audit_event_id`).
3. **Operator tool** — `python -m threatprism.persistence.verify_logs` (verify +
   summarize + redaction-safe export; non-zero exit on tamper).

This took the gated **OT-8** from open to largely-mitigated and **OT-1** to tamper-
evident for audit events.

## 8. 💡 The engineering principles that recur

- **Verify before you spend.** Prove the loop deterministically (free); let the paid run
  test only the real model. This caught the JSON-mode bug ($0.01), the enum bug, and
  kept the whole arc under ~$0.49.
- **Distrust a too-clean result.** A flat `confidence_delta = 0.0` "blind" run exposed a
  leak that invalidated a committed "anchoring ruled out" conclusion. Correct the record
  (supersede, don't delete).
- **Block *and* log.** Validation that fails closed is necessary but not sufficient —
  you must also capture *what* was blocked (sanitized) to debug and tune it.
- **One primitive, many consumers.** The shared secret catalog, the hash chain, the
  enum-derived analyst prompt — single source of truth beats copies that drift.
- **Name roles precisely.** "Independent grader" ≠ "the analyst working the case";
  "blocked" ≠ "logged"; "enforcement" ≠ "observability." Most bugs this arc were a
  blurred distinction.

## 9. 🧱 Honest scope (what this is *not*)

Demo/POC with synthetic data only (RFC 5737 IPs, `.test` domains). No real remediation
(`ALLOW_REAL_ACTIONS=false`), no real PHI, no tools/function-calling, no memory
write-back, no multi-tenancy, no fine-tuning. These are explicitly gated in the threat
treatment register ([spec 21](../docs/specs/21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md)),
each with a re-open trigger.

## 10. 🎤 Capstone talk track

> "ThreatPrism is a SOC triage co-pilot built security-first: a four-layer guardrail
> pipeline, two-stage tokenization so the model never sees raw PHI, fail-closed
> handling of untrusted model output, and an authorization model where the requested
> role is never authority. It demonstrates three runtime evolutions on a curated SOC
> dataset — batched auto-close, a batch backtest against an independent second-opinion
> model, and a live human-in-the-loop co-pilot — all sharing one disagreement/tuning
> loop. I added a tamper-evident hash-chained audit/failure log with an operator verify
> tool. The throughline of the work is methodology: verify before you spend, distrust a
> too-clean result, block *and* log, and keep one source of truth per fact."
