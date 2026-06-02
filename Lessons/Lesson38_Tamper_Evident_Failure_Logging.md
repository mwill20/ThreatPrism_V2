# Lesson 38 — Tamper-Evident Failure Logging (Observing the Fail-Closed Path) 🔒🧾

> Files: `src/threatprism/llm/failure_log.py`,
> `src/threatprism/llm/failures.py` (`TriageFailureReport.offending_values`,
> `failure_from_validation_error`), `src/threatprism/cases/service.py` (`run_triage`),
> `src/threatprism/demo/backtest.py` (`run_backtest`),
> `tests/test_failure_log.py`, `tests/test_real_llm_provider.py`,
> `tests/test_backtest.py`. Baseline: see
> [../docs/VALIDATION_BASELINE.md](../docs/VALIDATION_BASELINE.md).

## 1. 🎯 The gap this closes

A live backtest lost 2 of 8 analyst gradings to `schema_validation_failure`, and the
honest admission was: *"I can't confirm against the actual failing JSON."* The system
**blocked** the bad output correctly but **couldn't show you what it blocked**. That is
the difference between *enforcement* and *observability* — and a security tool needs
both.

The owner's requirement: failures must be **inspectable** (debugging, tuning, feedback)
and **immutable** (forensic trust). Plus: is there a guard against *any* arbitrary
output, not just this one field?

## 2. 🔍 The audit that comes first

Before building, answer the actual question. Every model output already routes through
Pydantic closed-vocabulary validation:

- Triage (Claude): `TriageReport.model_validate()` — `providers.py`.
- Analyst (OpenAI): `AnalystFeedbackCreate.model_validate()` — `mock_analyst.py`.

There is **no path** where a raw model string becomes a determination/severity/
disposition decision without validation, and every failure fails closed. So the
exposure was **never** "arbitrary output slips through." It was two narrower things:

1. **Visibility** — the failure record carried *why* (field path + error type) but, by
   design, **not the offending value**, so you couldn't see *what* the model emitted.
2. **Immutability** — triage failures landed in `case.audit_trail`, a **rewritable**
   JSON blob; the backtest **discarded** analyst failures entirely.

> Career framing: "I was asked to guard against arbitrary output. The audit showed the
> guard already existed and fails closed — the real gap was that we couldn't *see* or
> *trust* the record of what got blocked. I scoped the work to observability, not a
> redundant second gate."

## 3. 🧱 Tamper-evident, not just append-only

`FailureLog` is an append-only JSONL file where each line is:

```json
{"payload": {...}, "prev_hash": "<hex>", "record_hash": "<hex>"}
```

with `record_hash = sha256(prev_hash + canonical(payload))` and the first record's
`prev_hash = "0"*64`. Each record commits to the entire history before it, so editing
any past line changes every later `record_hash` — `verify()` catches **edits,
deletions, and reorders**. That hash chain is what upgrades "append-only by
convention" to "tamper-evident" — the same log-integrity primitive a SIEM uses.

Two details that matter:
- **Canonical JSON** (`sort_keys`, tight separators) — the hash must be reproducible
  from the stored payload regardless of key order, or `verify()` gives false positives.
- **`verify()` re-reads and recomputes** the whole chain; it never trusts the stored
  `record_hash` alone.

## 4. 🩹 Capturing the offending value — safely

`TriageFailureReport.offending_values` maps `field_path -> SANITIZED value`. Pydantic
v2 hands you the offending value directly (`err["input"]`), so capture is cheap. The
safety rule: it is **only populated when a sanitizer is injected**, and the injected
sanitizer is the existing `safeguard_text` (PHI/PII/secrets tokenized to
`[POTENTIAL_PHI:...]` / `[SECRET:...]`). Pure call sites that omit the sanitizer leak
nothing — the dependency on the heavy healthcare module is injected, not hard-wired, so
`failures.py` stays pure.

Result: the log shows `analyst_final_disposition = "investigate-further"` (the real
out-of-vocabulary value) while a smuggled `sk-…` secret in the same string is tokenized
away. You see what failed; you never leak what you shouldn't.

## 5. 🔌 Wiring: log at the orchestrator, sanitize at the source

Clean separation of concerns:
- **Sanitize** at the two `failure_from_validation_error` call sites (`governance.py`
  analyst, `runner.py` triage) — closest to where the bad value is born.
- **Log** at the orchestrators (`run_backtest`, `run_triage`) — they already inspect the
  returned `TriageFailureReport`, so they own the "persist it" decision. The backtest
  no longer discards; both append to the chain.

`build_failure_log(settings)` returns `None` when the path is empty (logging
disabled), keeping the demo/test posture unchanged unless a real failure occurs.

## 6. 🧪 TDD checkpoints

- Hash chain links and `verify()` passes on an intact log.
- `verify()` returns `False` after an edit, a deletion, and (implicitly) a reorder.
- Offending value is captured *and* sanitized (raw secret absent, field name present).
- Without a sanitizer, `offending_values` is empty (purity / no accidental leak).
- The backtest writes one verifiable record per failure instead of discarding.

## 7. 🎤 Interview talk track

> "A live run failed silently — counted, not captured — so I couldn't debug it. I built
> a tamper-evident failure log: an append-only JSONL hash chain where each record hashes
> the previous one, so any later edit fails `verify()`. It records the *sanitized*
> offending value, so we can see the model emitted an out-of-enum disposition without
> leaking any PHI that rode along. Crucially, I audited first and found the validation
> guard already existed and failed closed — the gap was observability and immutability,
> not a missing gate. I scoped to that, and noted it partially addresses our gated
> append-only-audit threat (OT-8)."
