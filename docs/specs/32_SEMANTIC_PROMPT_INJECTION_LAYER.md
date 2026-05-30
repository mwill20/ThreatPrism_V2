# Spec 32 — Semantic Prompt-Injection Layer (Design-Only, Gated)

Status: **design-only / forward-looking.** Not implemented. This spec is the
design for the **Gated Mitigation** recorded for `I4 / RR-I4 / OT-7` in
[`21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md`](21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md)
(line 105) and the semantic half of `RR-L1`. It MUST NOT be built while the
`DeterministicDemoProvider` is the only provider — it is warranted only when a
real LLM provider is introduced, and only after the threat-model re-review that
spec 21 already gates that work behind (see §9).

## 1. Purpose

The deterministic prompt firewall (`guardrails/prompt_firewall.py`) is six regex
rules. It is intentionally cheap — the "low-hanging-fruit blocker" for the
obvious script-kiddie patterns (`ignore previous instructions`, `system prompt`,
exfiltration phrasing). It does **not** understand intent, so it is bypassable by
paraphrase, encoding, language switching, and novel framings. The committed
`deepset/prompt-injections` corpus measures this empirically: of 12 promoted real
injection rows, the deterministic firewall recognizes only **6** (1 quarantine +
5 redact) and misses **6** (tagged `residual_risk=RR-L1`).

This spec defines a **semantic detection layer** that sits behind the
deterministic firewall and catches the bulk of what regex cannot: a fine-tuned
transformer classifier that scores inbound text for injection intent.

### Defense-in-depth framing (the analogy)

This mirrors a layered SOC detection stack: the deterministic firewall is a
**signature/IOC rule** (cheap, exact, catches known-bad), and the semantic layer
is the **behavioral/anomaly model** (more expensive, catches the variants the
signature misses). Neither replaces the other; the signature layer runs first
because it is free and explainable, and the model layer backstops it. As in a
SIEM, the model raises signal — it does not unilaterally execute response.

## 2. Non-negotiable constraint — detector, not gate

Per the global engineering standard: **a probabilistic model must never gate a
security decision, authorization check, data write, or irreversible action.**
This layer is a *detector*. The translation from its probabilistic score to an
action is a **deterministic** threshold + policy, and the existing deterministic
controls remain the authoritative safety net.

Concretely:

1. The classifier outputs a calibrated `injection_score ∈ [0, 1]` (deterministic
   for a fixed model revision in eval mode — see §6).
2. A deterministic rule maps the score to an action:
   `score ≥ QUARANTINE_THRESHOLD → quarantine` (fail-safe: blocks triage),
   `MID ≤ score < QUARANTINE_THRESHOLD → flag for manager review`,
   `score < MID → pass`.
3. **The model may only ever escalate, never de-escalate.** A *low* semantic
   score MUST NOT override or unblock a deterministic quarantine/redact. The
   final action is `max(deterministic_action, semantic_action)` on the
   severity ordering `pass < redact < quarantine`.
4. The downstream deterministic guardrails are unchanged and remain
   authoritative: output policy (`policy.py`), evidence validation
   (`evidence.py`), action safety (`enforce_action_safety()`), and the inert
   provider. The semantic layer adds coverage **before** the model; it removes
   nothing **after** it.

Quarantine-on-high-score is acceptable specifically because quarantine is the
*fail-safe* direction — a false positive blocks a legitimate case (annoying,
recoverable, surfaced to an analyst), never executes an unsafe action.

## 3. Model selection

### Chosen: `protectai/deberta-v3-base-prompt-injection-v2` (local, Apache-2.0)

> Verification required before implementation: confirm the exact model id,
> current revision SHA, license, and label schema on Hugging Face at build time.
> Models on the Hub are actively updated; pin a revision (§6). This spec records
> the selection rationale, not verified runtime code.

| Criterion | Why this model fits |
|---|---|
| **Specialized** | A DeBERTa-v3 classifier fine-tuned specifically for prompt-injection detection — the same class of tool (ProtectAI) used in the V1 project this V2 evolved from. Purpose-built beats a general LLM "judge" for this single task. |
| **Local / no egress** | Runs locally via `transformers` (CPU-viable for `base`). **No API, no cost, no data egress** — critical because inbound case text may contain PHI/PII even after Stage-1 tokenization. Sending case text to a third-party SaaS classifier would create a new trust boundary and a LINDDUN disclosure risk. |
| **OSS / cost** | Apache-2.0, free. Satisfies the free/OSS-first policy with no paid-dependency approval needed. |
| **Deterministic** | A classifier in eval mode with a pinned revision and no sampling produces a stable score for a given input — compatible with the "deterministic for production paths" rule, unlike a generative LLM judge. |
| **Wrappable** | ProtectAI's `llm-guard` library exposes this model as a `PromptInjection` scanner, which can be the integration path instead of raw `transformers` if its dependency surface is acceptable. |

### Considered and rejected

- **Lakera Guard (SaaS):** strong detector, but paid + sends text off-host →
  cost-approval required and a new data-egress/disclosure trust boundary.
  Rejected for the local POC; revisit only with explicit approval.
- **General LLM-as-judge (e.g., asking the provider "is this an injection?"):**
  probabilistic, non-deterministic, higher latency/cost, and circular (the thing
  we are defending could be attacked through the judge prompt itself). Rejected.
- **`deepset/deberta-v3-base-injection`:** viable alternative of the same shape;
  the ProtectAI v2 model has broader/more recent fine-tuning and direct V1
  continuity. Keep as a fallback if the primary becomes unavailable.
- **Rebuff:** combines heuristics + vector DB + canary tokens; heavier
  infrastructure than warranted for a single pre-model classification stage.

## 4. Pipeline placement

```text
POST /cases
  -> normalize_soar_payload()
  -> _apply_healthcare_safeguards()      # Stage 1 (unchanged)
  -> repository.save_case()

run_triage():
  -> _prepare_case_for_model():
       per field:
         1. deterministic prompt firewall  (sanitize_text)   # existing, runs first (cheap)
         2. *** NEW: semantic classifier scan ***            # this spec
         3. Stage-2 tokenization (TokenVault)                # existing
     -> final_action = max(deterministic_action, semantic_action)
     -> if final_action == quarantine: block triage (existing path), record audit
  -> provider.generate_report()          # only reached if not quarantined
  -> scan_output_policy() / validate_report_evidence() / enforce_action_safety()  # unchanged, authoritative
```

The semantic scan runs **after** the deterministic firewall (so the free layer
short-circuits the obvious cases and the model only scores what survives) and
**before** the provider (so a detected injection never reaches the model). It
reuses the existing quarantine machinery in `run_triage()` — a semantic
quarantine produces the same `triage_blocked_by_prompt_firewall`-style audit
event and `blocked_by_guardrail` status, with `metadata.detector="semantic"` and
the score recorded.

## 5. Components (proposed; names indicative)

- `guardrails/semantic_firewall.py` — loads the pinned model once, exposes
  `score_text(text) -> float` and `classify(text) -> SemanticAction`.
- A deterministic policy block: thresholds + the `max(...)` merge rule.
- A new `SanitizationRecord` operation/metadata variant so semantic detections
  are auditable and distinguishable from regex detections.
- Config in `config.py`: `SEMANTIC_FIREWALL_ENABLED` (default `false`),
  `SEMANTIC_FIREWALL_MODEL_REVISION` (pinned SHA), `QUARANTINE_THRESHOLD`,
  `REVIEW_THRESHOLD`. Disabled by default so the POC behavior is unchanged until
  the gated real-LLM work begins.

> The runtime integration (model load, tokenization, inference call) is **not**
> written here. When implemented, it must be verified against the installed
> `transformers` / `llm-guard` version — do not copy unverified inference code
> from this spec.

## 6. Determinism & supply-chain requirements

- **Pin the model revision** by commit SHA (not a moving tag); pin
  `transformers` (and `llm-guard` if used) to exact versions in
  `requirements.txt`.
- Load the model in **eval mode**, no dropout, no sampling — a fixed input must
  yield a fixed score, asserted by a test.
- The model weights are **not** committed to the repo. Document the fetch step;
  the model download is a build/deploy action, not an auto-download at runtime
  intake (consistent with the no-auto-download dataset rule).
- Record the model id + revision in the case audit trail on any semantic
  detection, for forensic reconstruction.

## 7. The deepset corpus as the measurable baseline

`fixtures/curated_datasets/deepset_prompt_injection.jsonl` already encodes the
"before" number. Each fixture's `expected_result` carries
`deterministic_firewall_action` and `residual_risk`. The 6 rows with
`residual_risk == "RR-L1"` are precisely the rows the deterministic layer misses
today. They are the acceptance target: **the semantic layer must recognize a
defined majority of them while not regressing the rows already caught.**

This is why the honest corpus was built before this layer — it converts "the
firewall is bypassable" from prose into a regression-tested metric.

## 8. Test plan (proposed `tests/test_semantic_prompt_firewall.py`)

1. **Recovers RR-L1 misses:** of the 6 `none`/RR-L1 deepset rows, the semantic
   layer flags ≥ a defined threshold (target set when measured; e.g., ≥ 4/6).
   Encodes the defense-in-depth win as a hard assertion.
2. **No regression on caught rows:** every row the deterministic layer
   quarantines/redacts is still at least as severe after the `max(...)` merge.
3. **Detector-not-gate invariant:** a deterministic quarantine with a *low*
   semantic score still results in quarantine (the model cannot de-escalate).
4. **False-positive bound:** benign rows (deepset `label == 0`, reviewed and
   promoted separately) are not quarantined above an acceptable rate.
5. **Determinism:** the same input yields the same score across two loads of the
   pinned revision.
6. **No-egress:** the scan performs no network call (assert via a blocked-socket
   or offline-mode fixture).
7. **Disabled-by-default:** with `SEMANTIC_FIREWALL_ENABLED=false`, behavior is
   byte-for-byte the current pipeline.

## 9. Gating & threat-model re-review

This layer is part of the real-LLM work that spec 21 (line 332) gates behind a
new spec and threat-model refresh. Before implementation:

1. Re-open spec 21's treatment for `I4 / RR-I4 / OT-7` and move it from **Gated
   Mitigation** toward **Mitigated** with this layer as the control.
2. Refresh `docs/threat-models/llm-agent-threat-model.md` (the model itself is a
   new attacker surface — adversarial inputs crafted to evade or to *trigger*
   false-positive DoS; pin/verify per MITRE ATLAS model-evasion tactics).
3. Update `docs/threat-models/mitigations-traceability.md`: change the I4/L1 row
   state from "Partial (RR-I4, RR-L1 semantic bypass only)" once the layer ships
   with passing tests, and link this spec.
4. Confirm no new data-egress boundary (local model, §3) so LINDDUN disclosure
   posture is unchanged.

## 10. Out of scope

- Indirect/second-order prompt injection from retrieved content (RAG) — separate
  threat `OT-L1`, separate future spec.
- Replacing or weakening any deterministic guardrail.
- Any SaaS/paid detector or off-host inference.
- Model fine-tuning or training in this repo.
- Auto-downloading the model at runtime intake.
