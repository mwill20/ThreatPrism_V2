# ThreatPrism Working Checklist

Use this checklist to keep current work aligned with the live repository state.
Trust files and validation results over older chat summaries.

## Current Truths

- [x] Product name is `ThreatPrism`.
- [x] Canonical local path is `C:\Projects\ThreatPrismV2`.
- [x] Destination repository is `mwill20/ThreatPrism_V2`.
- [x] V2 uses a clean architecture with selective V1 concept porting.
- [x] Do not full-copy V1 into this repository.
- [x] Demo data must stay fake.
- [x] Real remediation remains disabled by default with `ALLOW_REAL_ACTIONS=false`.
- [x] HITRUST language is category/alignment mapping only, not compliance or certification.
- [x] The original docs-only baseline is stale; implementation has begun.
- [x] The previous final response leaked drafting/debug text; trust files and validation results instead.

## Active Target

Build and harden the first ThreatPrism backend slice:

- [x] Generic SOAR webhook payload intake.
- [x] Case normalization.
- [x] Prompt firewall, sanitization, and tokenization before model processing.
- [x] Deterministic demo LLM provider.
- [x] Structured triage report schema.
- [x] Output policy, evidence-grounding, and action-safety checks.
- [x] Controlled rehydration after validation.
- [x] Deterministic report rendering.
- [x] SQLite demo persistence.
- [x] FastAPI endpoints for health, cases, triage report, and analyst feedback.
- [x] Analyst feedback and disagreement tracking.
- [x] Fake SOAR demo payloads.
- [x] Initial API and guardrail tests.

## Immediate Next Checklist

- [x] Initialize or sync `C:\Projects\ThreatPrismV2` as the local checkout for `mwill20/ThreatPrism_V2`.
- [x] Commit and push the current validated baseline to `main`.
- [x] Add or update a user-facing `README.md` with setup, validation, and demo workflow.
- [x] Add a concise local runbook for starting the FastAPI service.
- [x] Review docs/specs against the implemented slice and remove remaining stale no-code wording.
- [x] Add targeted tests for guardrail-blocked triage output.
- [x] Add targeted tests for unsupported evidence IDs in generated reports.
- [x] Add targeted tests that real actions fail closed if a report claims `real_action_executed=true`.
- [x] Add threat intelligence stub interfaces that return structured `not_configured` results.
- [x] Add Microsoft-friendly adapter examples without hardwiring Microsoft into the core model.
- [x] Decide whether the next async step stays with in-process FastAPI background tasks or moves to a worker/queue.
- [x] Decide the demo API auth model before using anything beyond fake demo data.

## Validation

Use safe local validation first:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_verify
```

Current known result:

```text
13 passed
```

If a reused pytest temp directory fails with Windows `WinError 5`, rerun with a
fresh ignored base temp directory.

## Out Of Scope Until Explicitly Requested

- [ ] Real remediation or containment.
- [ ] Live LLM calls.
- [ ] Live SOAR calls.
- [ ] Live cloud or enrichment provider calls.
- [ ] Production credentials.
- [ ] Real workplace, tenant, user, host, domain, IP, or secret data.
- [ ] Frontend dashboard implementation.
- [ ] Strict CI gates that fail before the inherited baseline is ready.

## Definition Of Done For The Current Slice

- [x] Local workspace is connected to `mwill20/ThreatPrism_V2`.
- [x] Current baseline is committed and pushed.
- [x] README explains setup, test, and demo flow.
- [x] Guardrail and action-safety test coverage covers failure paths.
- [x] Specs, limitations, and handoff docs agree with the implemented state.
- [x] Validation passes from a clean command.
- [x] Remaining gaps are documented as next-phase work, not hidden as completed.

## Published Baseline

- Initial baseline commit: `2ece6dd Build ThreatPrism V2 baseline`.
- Pushed to `origin/main` for `mwill20/ThreatPrism_V2`.
