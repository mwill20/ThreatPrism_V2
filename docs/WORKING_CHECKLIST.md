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
- [x] `docs/ARCHITECTURAL_NORTH_STAR.md` is the directional architecture guide
  for new slices, workarounds, and major enhancements.

## Active Target

The first ThreatPrism backend slice is complete:

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
- [x] Add a dedicated Architectural North Star so future slices stay aligned.
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

## Completed Slice

Healthcare Safeguard & Evidence Alignment Guardrails v0.1:

- [x] Add spec for context-aware healthcare safeguard guardrails.
- [x] Add top-level healthcare safeguard guardrail doc.
- [x] Record decision that identifiers are not PHI/ePHI by themselves.
- [x] Record decision to use safeguard/evidence-alignment language, not
  compliance-certification language.
- [x] Implement context-aware detector taxonomy for potential PHI/ePHI, PII,
  secrets, and security telemetry.
- [x] Add typed replacement tokens such as `[POTENTIAL_PHI:MRN:phi_0001]` and
  `[SECRET:API_KEY:secret_0001]`.
- [x] Add pre-persistence scanning before model-visible payload creation,
  report rendering, logging, or role-based display.
- [x] Add role-based rendering policies for AI, analyst, engineer, manager/GRC,
  legal/privacy, and audit/debug views.
- [x] Add compliance-language scanner for HIPAA/HITRUST compliance,
  certification, audit-ready, control-satisfied, and evidence-proves-compliance
  claims.
- [x] Record audit events for tokenization, rehydration approval or denial,
  guardrail blocks, role-view policy application, and report validation.
- [x] Add fake fixtures for potential PHI/ePHI contamination, normal security
  telemetry, PII, and secrets.
- [x] Add tests proving raw potential PHI/ePHI does not appear in model-visible
  payloads, reports, logs, manager/GRC views, or audit/debug views.
- [x] Add tests proving security telemetry remains usable for analyst/engineer
  response when it is not tied to health context.
- [x] Add tests proving secrets are never rehydrated.
- [x] Add tests proving compliance/certification/audit-ready claims are blocked.
- [x] Add tests proving GRC mappings still cite evidence IDs.

## Prepped Follow-On Slice

Operational Read Models & Metrics API v0.1:

- [x] Add implementation-ready spec for operational read models and metrics.
- [ ] Add Pydantic response models for metrics, case-list envelopes, detail
  route envelopes, and safe audit summaries.
- [ ] Add `GET /metrics` with case, triage, guardrail, healthcare safeguard,
  disagreement, timing, and GRC aggregates.
- [ ] Add dashboard-ready case list filtering for source, status,
  triage_status, severity, determination, manager review, healthcare review,
  guardrail block, and created time windows.
- [ ] Add manager-review queue behavior through filters or a dedicated route.
- [ ] Add healthcare-review queue behavior through filters or a dedicated
  route.
- [ ] Add detail routes for evidence, timeline, MITRE mappings, GRC mappings,
  and audit events.
- [ ] Apply role-safe rendering to detail/read-model routes where case content
  or security telemetry can appear.
- [ ] Ensure metrics and read-model routes never expose raw potential PHI/ePHI,
  secrets, or token vault mappings.
- [ ] Add tests for metrics aggregation, filtering, manager-review queue,
  healthcare-review queue, detail routes, role-safe views, and no sensitive
  value leakage.
- [ ] Keep `ALLOW_REAL_ACTIONS=false`, fake fixtures only, and no live LLM,
  SOAR, enrichment, cloud, or remediation calls.

This slice remains queued, but the architect review identified access control
as the stronger immediate prerequisite because role-based views are not
security controls until identity and authorization enforce them.

## Next Active Slice

Access Control & Audit Integrity v0.1:

- [ ] Check `docs/ARCHITECTURAL_NORTH_STAR.md` before implementation and record
  any intentional architecture changes in `DECISIONS.md`.
- [x] Document why this slice supersedes metrics/read models as the next
  implementation target.
- [x] Add implementation-ready spec for demo authentication, authorization,
  and audit integrity.
- [ ] Add demo authentication middleware or dependency using fake/demo
  credentials only.
- [ ] Map authenticated callers to effective roles.
- [ ] Stop treating `?role=` as authority outside explicit demo/test override
  behavior.
- [ ] Deny role escalation attempts and fail closed for missing, unknown, or
  unauthorized roles.
- [ ] Harden role-view policy so manager/GRC, legal/privacy, audit/debug, and
  AI views cannot receive analyst/engineer-only data.
- [ ] Record authorization audit events for allow and deny decisions.
- [ ] Ensure authorization audit events include caller identity, requested role,
  effective role, endpoint, case/report ID, decision, reason, timestamp, and a
  redacted request metadata hash.
- [ ] Ensure authorization audit events never store raw potential PHI/ePHI,
  secrets, full credentials, raw payload bodies, or token vault mappings.
- [ ] Add tests for unauthenticated denial when demo auth is enabled.
- [ ] Add tests proving manager/GRC cannot force analyst or engineer views.
- [ ] Add tests proving invalid role escalation fails closed.
- [ ] Add tests proving allow and deny decisions create audit events.
- [ ] Add tests proving healthcare leakage protections still pass.
- [ ] Keep `ALLOW_REAL_ACTIONS=false`, fake fixtures only, and no live LLM,
  SOAR, enrichment, cloud, dashboard, production IdP, or remediation work.

## Validation

Use safe local validation first:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_verify
```

Current known result:

```text
22 passed
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
- Healthcare safeguard guardrails commit: `f251d28 Implement healthcare safeguard guardrails`.
- Operational metrics prep commit: `3a4dd84 Prep operational metrics read-model slice`.
- Pushed to `origin/main` for `mwill20/ThreatPrism_V2`.
