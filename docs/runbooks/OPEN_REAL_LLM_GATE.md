# Runbook: Open the Real-LLM Gate

**Purpose.** Switch ThreatPrism from the deterministic demo provider to the real
Anthropic Claude triage brain (and the OpenAI mock-analyst for backtesting). This
is the one architectural boundary the project deliberately gates — the
deterministic core is built and tested; this runbook turns on the paid, live calls.

**Prerequisite reading:**
[`docs/specs/33_REAL_LLM_PROVIDER_AND_EXECUTIVE_SUMMARY.md`](../specs/33_REAL_LLM_PROVIDER_AND_EXECUTIVE_SUMMARY.md)
(the contract) and the threat-model gate in
[`docs/specs/21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md`](../specs/21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md).

> This involves paid API calls and a third-party data-egress boundary. Case text
> reaches the API only **after** Stage-1 tokenization, so the model never receives
> raw PHI/PII/secrets — confirm that invariant holds before enabling.

---

## 1. Install the gated SDKs

```bash
pip install -r requirements-llm.txt
```

Then **pin exact versions** you verified, and re-confirm the SDK call shapes in
`src/threatprism/llm/providers.py` (`ClaudeTriageProvider._call`) and
`src/threatprism/llm/mock_analyst.py` (`MockAnalyst._call`) match the installed
versions. Both files mark the call with `VERIFY` comments. Map the SDK exception
classes to the structured failures in `_classify_anthropic_error`.

## 2. Configure (env only — never commit keys)

```bash
export LLM_PROVIDER=anthropic_claude
export ANTHROPIC_API_KEY=...           # triage brain
export LLM_MODEL_ID=claude-sonnet-4-5  # pin the model you verified
export OPENAI_API_KEY=...              # mock-analyst (Evolution 2)
export MOCK_ANALYST_MODEL_ID=gpt-4o-mini
# Optional tuning: LLM_TEMPERATURE, LLM_CALL_TIMEOUT_SECONDS, LLM_MAX_RETRIES,
# BATCH_MAX_EVENTS, BATCH_MAX_INPUT_TOKENS, SUMMARY_MAX_CHARS.
```

`validate_runtime()` fails closed if `LLM_PROVIDER=anthropic_claude` without
`ANTHROPIC_API_KEY`.

## 3. Verify on a small batch first

Run the SOC dataset (or a small subset) and inspect the output before trusting it:

```bash
PYTHONPATH=src python -m threatprism.demo.run_soc_demo --show-reports 3
```

Check that: the per-event `summary` now reads as real analysis (not boilerplate);
the batch `narrative` is populated and leads with the most critical cases; nothing
overclaims compliance or leaks tokens (the output policy will block and record a
failure if it does); and any provider error produces a `TriageFailureReport` with
a fail-closed status rather than a crash.

## 4. What the guardrails still enforce (do not weaken)

- LLM output passes `scan_output_policy` + `validate_report_evidence` +
  `enforce_action_safety` before persistence — unchanged.
- `ALLOW_REAL_ACTIONS=false` — no remediation is executed.
- Every cited `evidence_id` must exist, or the report is blocked.
- Failures are structured and fail closed; guardrail rejections are never retried.

## 5. Before relying on it in any shared setting

- Implement and ship the semantic prompt-injection firewall
  ([spec 32](../specs/32_SEMANTIC_PROMPT_INJECTION_LAYER.md)) — now warranted once
  the LLM acts on case text.
- Re-open the spec 21 `I4/RR-I4/OT-7` treatment to **Mitigated** with the firewall
  as the control, and activate `OT-L3` (provider-side rate/cost caps) and `OT-L7`.
- Re-confirm the egress boundary in the LLM and healthcare threat-model lenses.

---

## Validation

The deterministic seam is regression-tested with no network:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

See `tests/test_real_llm_provider.py`. CI never makes live calls — the real
provider is not constructed under default test settings.
