# Changelog

All notable repository-level changes should be recorded here.

## Unreleased

- **Confirming live A/B (~$0.10): enum fix verified + anchoring confirmed at full N.**
  Re-ran blind + anchored on the adversarial set with both fixes in place. Both graded
  **8/8 with zero schema failures** (prior corrected blind run lost 2/8 to an
  out-of-enum disposition) — the enum-contract fix is verified on real data. Clean A/B:
  anchored 1.0 agreement / flat 0.0 confidence delta vs **true blind 0.875, 1
  determination split (adv-0004), uniform 0.05 delta** — anchoring is material at full
  N, and the disagreement signal (adv-0004) reproduces across runs. The tamper-evident
  failure log stayed empty (0 failures = correct). Docs only; see
  `docs/LIVE_BACKTEST_FINDINGS.md`.
- **Tamper-evident failure log + sanitized offending-value capture** (owner
  requirement). Every LLM/analyst validation failure is now inspectable AND immutable.
  Audit finding first: all model output is already gated by Pydantic closed-vocabulary
  validation and fails closed — no arbitrary output slips through — but the offending
  value wasn't captured and the backtest *discarded* analyst failures. New
  `src/threatprism/llm/failure_log.py`: `FailureLog`, an append-only JSONL **hash
  chain** (`record_hash = sha256(prev_hash + canonical(payload))`) with `verify()`
  that detects edits, deletions, and reorders. `TriageFailureReport.offending_values`
  captures `field_path -> SANITIZED value` (PHI/secrets tokenized via the existing
  safeguard before they reach the log; only populated when a sanitizer is injected, so
  pure call sites leak nothing). Sanitizer threaded into both
  `failure_from_validation_error` call sites (analyst + triage); the log is wired into
  `run_backtest` (no longer discards) and `run_triage`. Config: `FAILURE_LOG_PATH`
  (gitignored `data/audit/`, empty disables). TDD: `tests/test_failure_log.py` +
  offending-value + backtest-integration tests. Baseline `284 -> 291 passed`.
  Partially addresses the gated OT-8 (append-only audit) — see
  `docs/threat-models/mitigations-traceability.md`.
- **Single source of truth for the validation baseline** (cleanup). The pass/skip
  count lived hand-maintained in ~6 files and drifted each slice; it now lives once in
  `docs/VALIDATION_BASELINE.md`, and README / RUNBOOK / START_HERE / Lessons index /
  WORKING_CHECKLIST reference it instead of restating the number.
- **Hardened the analyst prompt's enum contract** (`mock_analyst.py`) to fix the 2/8
  blind-mode `schema_validation_failure`s from the corrected A/B. The system prompt
  named `analyst_final_disposition` but never stated its allowed values; a blind
  analyst (no report to copy valid values from) free-styled an out-of-enum
  disposition that failed `AnalystFeedbackCreate`. Anchored runs masked it because
  the report supplied valid enum values as an implicit example. The closed
  vocabularies for all three required enum fields (determination/severity/
  disposition) are now derived from the schema enums (`_vocab()`), so the prompt
  can't drift from `AnalystFeedbackCreate`, plus an explicit "use exactly one of the
  listed values" instruction. TDD regression:
  `test_analyst_prompt_enumerates_all_required_enum_vocabularies`. Baseline
  `283 -> 284 passed`. Decisive confirmation (8/8 graded blind) is a paid blind
  re-run — pending owner go-ahead.
- **Fixed: blind analyst was not blind** (`mock_analyst.py`). `_build_prompt`
  stripped only the top-level `threatprism_report` key, but a triaged `CaseRecord`
  carries the verdict on `case.triage_report`, so the report (determination/severity/
  confidence/findings) reached the analyst in both modes — the "blind" run was a
  second anchored run. Now excludes `triage_report` from the case payload, making the
  report's presence the only blind-vs-anchored variable. Found by a paid live run
  (confidence_delta flat 0.0 even "blind"). TDD regression:
  `test_blind_analyst_does_not_leak_report_via_case_triage_report`. Baseline
  `282 -> 283 passed`.
- **CORRECTION — anchoring is NOT ruled out.** Re-ran the corrected A/B (~$0.10, real
  Claude triage + real OpenAI analyst, adversarial set): anchored = 1.0 agreement /
  flat 0.0 confidence delta; **true blind = 0.833 agreement, 1 determination mismatch
  (adv-0004), 2 severity mismatches, confidence deltas mean 0.042**. Blind ≠ anchored
  → anchoring was the dominant cause of the prior 100%, and the disagreement pipeline
  fires on real models once the leak is closed. Caveats: weak confidence signal
  (blind analyst ~constant 0.70), 2 schema-validation failures in blind mode (6/8
  graded), small N. This supersedes the "anchoring ruled out" entry below. See
  `docs/LIVE_BACKTEST_FINDINGS.md`.
- Added confidence-delta capture to the backtest:
  `BacktestCaseResult.{threatprism_confidence,analyst_confidence,confidence_delta}` +
  `BacktestReport.confidence_delta_summary` (mean/max/count ≥0.2). Surfaces the soft
  disagreement the 4-bucket determination hides — the lever the blind A/B promoted.
  Deterministic demo gives a flat 0.22 (fixed analyst confidence); the real per-case
  spread needs a live run. Test: `test_confidence_deltas_are_captured`. Baseline
  `281 -> 282 passed`.
- Ran the blind-vs-anchored live comparison (~$0.05): blind (case-only) and anchored
  analyst both returned **1.0 agreement**, identical — **anchoring ruled out.** The
  100% on engineered-ambiguous cases is real convergence, not circularity; the cause
  is that rule-ambiguity isn't reasoning-ambiguity at the determination bucket. Next
  lever promoted to signal granularity (capture confidence deltas) over harder cases.
  Docs only. See `docs/LIVE_BACKTEST_FINDINGS.md`.
  **[SUPERSEDED 2026-06-02 — the blind path leaked the report via `case.triage_report`,
  so this comparison was not actually blind; anchoring is NOT ruled out. See the
  CORRECTION entry at the top of Unreleased.]**
- Added blind-analyst mode (`MockAnalyst(blind=True)` / `backtest --blind-analyst`):
  grades the case ONLY, withholding ThreatPrism's report from the analyst prompt —
  the fix for the anchoring/residual-circularity finding from the live adversarial
  run, and a true independent second opinion that also egresses less to the
  provider. The analyst system prompt was generalized so blind vs. anchored differ
  only by the report's presence. Test:
  `test_blind_analyst_withholds_report_reducing_egress`. The blind-vs-anchored live
  comparison is the next paid owner-run. Baseline `280 -> 281 passed`.
- Ran the adversarial set live (~$0.05): real Claude triage + real OpenAI analyst
  **agreed 100%** on all 8 engineered-ambiguous cases / all 5 axes, despite the
  deterministic pair splitting 0.5. Finding: engineered rule-ambiguity does not
  split reasoning models, and the analyst is shown ThreatPrism's report (anchoring /
  residual circularity) — a blind case-only analyst is the recommended follow-up.
  Analysis in `docs/LIVE_BACKTEST_FINDINGS.md`; no code change (docs only).
- Implemented the adversarial/ambiguous eval dataset (spec 37): 8 hand-authored,
  fully synthetic *triage-ambiguous* SOC cases in `fixtures/curated_adversarial/`
  (dual-use / conflicting-evidence / severity-edge / disposition-edge /
  benign-mimicking axes), an `AdversarialCuratedSource`, and a
  `backtest --dataset adversarial` flag. Engineered to exercise disagreement
  detection that a clear-cut corpus cannot: deterministic baseline is **agreement
  0.5** (4/8 mismatches, 4 flagged-then-cleared) vs. 1.0 on the curated set.
  Synthetic only (RFC 5737 IPs, `.test` domains), manifest review gate, demo-safety
  clean. Tests: `tests/test_adversarial_dataset.py`. Also added a **per-axis
  agreement breakdown** (`BacktestReport.agreement_by_axis`, spec 37 Q4) keyed on
  `ambiguity_axis` (carried in `payload.source_metadata`), so a run shows *which*
  kinds of ambiguity drive divergence (deterministic: `disposition_edge` agrees;
  the other four axes split). Baseline `276 -> 280 passed`.
- Ran the first live two-model backtest (real Claude triage + independent OpenAI
  analyst) over the curated synthetic SOC corpus: 27 graded, 0 failures, 100%
  determination/severity agreement, ~$0.17. A cents-scale smoke run first caught a
  real bug (the analyst lacked OpenAI JSON mode → every grading failed
  unparseable); fixed with `response_format=json_object`, and `BacktestReport`
  gained `grading_failure_types` so failures are no longer silent. Added a
  `--limit`/seed-`limit` flag for cost-minimal smoke runs. Findings + honest
  caveats (corpus too clear-cut to exercise disagreement detection; 27-vs-31 graded
  gap) in `docs/LIVE_BACKTEST_FINDINGS.md`. Followed up by adding
  `no_report_total`/`no_report_reasons` (keyed on `triage_status`) so the graded-gap
  is categorized (blocked vs failed) instead of silently skipped, and planned the
  adversarial/ambiguous eval dataset (`docs/specs/37_ADVERSARIAL_EVAL_DATASET.md`)
  to actually exercise disagreement detection. Baseline `272 -> 276 passed`.
- Opened the real-LLM gates (owner-authorized 2026-06-01): live Anthropic triage,
  OpenAI independent analyst, and the local Prompt Guard 2 semantic firewall. Spec
  21 threat-treatment register updated — re-opened L1/RR-L1, L5/OT-L3, L7/OT-L7
  with current-mitigation evidence; added new trust-boundary threats OT-L10
  (analyst data egress), OT-L11a/b/c (triage egress, local-model supply chain,
  detector-not-gate); logged residual-risk acceptances with owner-signature
  placeholders and a pre-flight checklist. Added `tests/test_analyst_egress.py`
  guarding that the OpenAI analyst prompt carries only Stage-1 tokens, never raw
  PHI/secrets. Tools/function-calling, memory write-back, multi-tenancy,
  fine-tuning, non-demo data, and real PHI remain Avoid/Gated. Baseline
  `271 -> 272 passed`.
- Unified secret-pattern detection into a single shared catalog
  (`src/threatprism/guardrails/secret_catalog.py`, spec 34 §3). The product
  detectors (`healthcare.py` `SECRET_RULES`, `tokenization.py` `secret_like`,
  `policy.py`) and the standalone dev-workflow hook (`tools/hooks/_common.py`,
  loaded by file path) now derive every secret-shaped regex from one source, so
  product and dev-workflow secret detection stay in sync under one quarterly
  refresh. Healthcare/tokenization detection is byte-for-byte unchanged; policy
  and the hook broadened only in the safe direction. Added
  `tests/test_secret_catalog.py` and Lesson 35. Baseline `267 -> 271 passed`.
- Fixed an in-memory SQLite concurrency bug: the shared `:memory:` connection
  returned HTTP 500 under FastAPI threadpool concurrency (the dashboard's
  parallel per-case detail fetches). Added a `threading.Lock` and a
  `_transaction()` context manager serializing access to the shared connection;
  file-backed mode keeps connection-per-op. Added a barrier-synchronized
  concurrency regression test and Lesson 34. Baseline `266 -> 267 passed`.
- Added Production Token Verifier Design v0.1 with the future `external_oidc`
  verifier contract, claim-to-role mapping rules, JWKS/cache boundaries,
  fail-closed semantics, sanitized audit requirements, no-network validation
  rules, docs, runbook, lesson, and threat-model notes.
- Added Production Identity Readiness v0.1 with static `external_oidc`
  configuration validation, unknown-auth-mode rejection, live-verifier
  rejection, fail-closed protected-route behavior, docs, runbook, and tests.
- Expanded the curated fixture set to four tiny hand-reviewed fake fixtures
  covering SOC, healthcare-context exposure, sanitized prompt-injection, and
  evidence-conflict/GRC review, with stronger manifest and scenario tests.
- Added Curated Generated-Fixture Promotion v0.1 with a tracked fake SOC
  fixture, manifest review gate, path-safe promotion loader, tests, and docs
  while keeping `fixtures/generated/` ignored and out of automatic scans.
- Documented Exa.ai or equivalent public-web research providers as optional
  future enhancement candidates only, outside the current CSI/RGOI, validation,
  demo, RAG, memory write-back, fixture-promotion, and source-of-truth paths.
- Added production-style hardening for the local dashboard: CSP/framing/
  referrer/permission headers, same-origin request enforcement, API request
  timeouts, keyboard persona navigation, tests, docs, and threat-model updates.
- Added local fake-data-only dashboard UI at `GET /dashboard`, same-origin
  static assets, dashboard UI tests, and Browser verification notes.
- Added CSI/RGOI read-only governed cognition foundation with schemas,
  retrieval governance, trust scoring, evidence alignment, lineage, replay,
  observability, divergence telemetry, fake fixtures, docs, and tests.
- Added dashboard UI preparation docs, fake persona response fixtures,
  dashboard-readiness runbook, and CSI route contract tests without building a
  frontend dashboard.
- Added repository standards readiness audit and reviewer-focused docs.
- Documented usage, evaluation, dataset, model/provider, deployment,
  monitoring, and troubleshooting entry points.
- Clarified license status, support path, and demo-only production boundaries.

## Current Baseline

- Implemented fake-data FastAPI backend with case intake, triage reports,
  guardrails, role-aware reads, operational metrics, eval harness, demo
  scenario pack, Docker Compose local packaging, and synthetic fixture factory.
- Current safe validation baseline is tracked in README.md, RUNBOOK.md,
  START_HERE.md, LIMITATIONS.md, and docs/WORKING_CHECKLIST.md.
