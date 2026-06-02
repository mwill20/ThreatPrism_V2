# Pattern Refresh Runbook

ThreatPrism uses small, explicit pattern lists for healthcare safeguard
detection and unsafe output-language blocking. This runbook keeps those lists
reviewable without turning the POC into an unbounded classifier project.

## Scope

Review these pattern surfaces together:

- **Secret patterns: `src/threatprism/guardrails/secret_catalog.py` is the single
  source of truth (spec 34 §3).** Every secret-shaped regex is defined there once.
  `guardrails/healthcare.py` (`SECRET_RULES`), `guardrails/tokenization.py`
  (`secret_like`), `guardrails/policy.py`, and the standalone dev-workflow hook
  (`tools/hooks/_common.py`) all reference it — edit secret patterns **here only**,
  never in a consumer.
- `PROHIBITED_PATTERNS` (non-secret overclaim/clinical rules) in
  `src/threatprism/guardrails/policy.py`.
- `PHI_RULES`, `CONTEXT_IDENTIFIER_RULES`, and `PII_RULES` in
  `src/threatprism/guardrails/healthcare.py`.
- Regression fixture catalogs in `tests/test_overclaim_regression.py`,
  `tests/test_phi_detector_coverage.py`, and `tests/test_secret_catalog.py`
  (the latter asserts the product and dev-hook secret catalogs stay identical).

## Quarterly Review Steps

1. Review recent eval failures and guardrail-blocked cases for missed unsafe
   compliance, remediation, clinical, PHI/PII, or secret wording.
2. Review recent product and security notes for new overclaim phrasing or
   healthcare identifier formats that are relevant to fake SOAR data.
3. Decide whether the gap belongs in the current pattern list, a future
   semantic classifier, or an out-of-scope production gate.
4. Add or update a regression fixture first.
5. Add or update the pattern only after the fixture proves the current gap.
6. Run focused pattern tests, then the safe validation wrapper.

## Acceptance Rules

- Every current `PROHIBITED_PATTERNS` regex must have at least one fixture in
  `tests/test_overclaim_regression.py`.
- Every current healthcare detector rule must have at least one fixture in
  `tests/test_phi_detector_coverage.py`.
- Do not add real organization names, patient names, workplace names, real IPs,
  real domains, tenant IDs, or live-looking secrets.
- Do not claim HIPAA compliance, HITRUST certification, audit readiness, or
  legal de-identification from these patterns.

## Next Review

First scheduled review: 2026-08-24.

Reviewer role: Security Reviewer plus Healthcare Safeguard Reviewer. For POC
scope, the project owner can accept or defer proposed pattern changes. Before
MVP, production, real LLM, real PHI, RAG, memory, or multi-tenant work, re-open
the threat model treatment register instead of treating this runbook as enough.
