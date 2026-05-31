# Spec 35 — Meter Failed-After-Call LLM Cost

Status: **design-only.** Focused correctness fix surfaced during the live run.

## 1. Problem

`metered_generate` / `metered_narrative` record usage into the `SpendLedger` **only
on success** (when the result is a `TriageReport` / a narrative string). But an LLM
call that *completes the API round-trip and then fails downstream* still costs
money — e.g. `provider_response_unparseable` (the model replied but not as JSON) or
`schema_validation_failure` (replied, but the JSON didn't validate). Today those
tokens are spent but never ledgered, so `/metrics` and the spend cap **undercount**
real cost. Observed live: the first run's unparseable response cost tokens that
showed as `usd 0`.

## 2. Fix

Record usage whenever a **call actually happened**, regardless of whether parsing /
validation later failed.

- **Reset before call:** the provider sets `self.last_usage = None` at the start of
  `generate_report` / `generate_narrative`, and populates it only after a real API
  response. So a non-`None` `last_usage` after the attempt means a call occurred.
- **Ledger on attempt, not just success:** in `metered_generate` /
  `metered_narrative`, after `safe_generate_report` / `build_batch_narrative`
  returns — **success or failure** — if `provider.last_usage` is a fresh
  `UsageRecord`, price it and add it to the ledger (tagging `call_kind` and, for
  failures, the `failure_type`). This must run on the failure path too.
- **Audit:** still emit the sanitized `llm_call` audit on a failed-after-call (so
  the cost is attributable), with the failure type in metadata.

## 3. Invariants

- Spend cap still counts toward exhaustion using *attempted* spend (so repeated
  failures can't silently blow the budget).
- No double-counting: `last_usage` is reset per attempt so a stale record is never
  re-ledgered.
- Pre-call failures (`provider_unreachable`, `provider_auth_error`, `budget_exceeded`,
  `prompt_quarantine`) have **no** `last_usage` → nothing ledgered (correct — no
  call was made).

## 4. Tests (no network)

- Fake provider that sets `last_usage` then raises `ProviderResponseUnparseable` →
  ledger records the usage; result is a `TriageFailureReport`.
- Fake provider that returns schema-invalid JSON (after setting `last_usage`) →
  usage ledgered + `schema_validation_failure`.
- Pre-call failure (no `last_usage`) → ledger unchanged.
- `last_usage` reset prevents double-count across two attempts.

## 5. Scope

`src/threatprism/llm/governance.py` (`metered_generate`, `metered_narrative`),
`src/threatprism/llm/providers.py` (reset `last_usage`/`last_prompt`/`last_response`
per attempt), `tests/test_llm_governance.py`. No runtime/product behavior change for
the deterministic demo (it never sets `last_usage`).
