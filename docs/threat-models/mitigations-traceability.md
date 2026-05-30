# Mitigations Traceability

**Version:** 2026-05-24 (v0.2 refresh)
**Status:** POC owner decision pass recorded; Slices A, B, D, E, F, and G reconciled
**Purpose:** Map every enumerated threat to its mitigation (with `file:function` reference) and its test coverage. Surface gaps where threats exist but tests do not.

For threat enumeration, see [`stride-threat-model.md`](stride-threat-model.md), [`llm-agent-threat-model.md`](llm-agent-threat-model.md), and [`healthcare-data-threat-model.md`](healthcare-data-threat-model.md).

---

## How to Read This Document

- **Threat ID** — refers to a specific entry in one of the three lens files:
  - `S1, S2, T1-T3, R1, I1-I4, D1-D3, E1, E2` → STRIDE
  - `L1-L13` → LLM Top 10
  - `LD1-LD2, ID1-ID2, DT1-DT2, DI1-DI6, NC1-NC3` → LINDDUN
  - `OT-X, OT-LD-X, OT-L-X` → open threats (unmitigated; no current test)
  - `RR-X` → residual risk (partially mitigated; gaps noted)
- **State** — `Mitigated` / `Partial` / `Unmitigated` / `N/A` / `Accepted` (design tradeoff)
- **Test File** — the test that exercises the mitigation. `Proposed:` means the test does not exist yet and is required before the corresponding feature ships.

---

## Implemented Mitigations

### Authentication and Authorization

| Threat ID | Mitigation | Code Reference | State | Test File |
|-----------|------------|----------------|-------|-----------|
| S1 | Demo API-key auth maps credentials to effective roles; missing/unknown credentials denied; `demo_key` mode requires explicit `DEMO_API_KEYS` | `authorize_role_view()` at [auth/demo.py:73](../../src/threatprism/auth/demo.py); `_extract_credential()` at [auth/demo.py:192](../../src/threatprism/auth/demo.py); `validate_runtime()` at [config.py:38](../../src/threatprism/config.py) | Mitigated for POC scope | `tests/test_access_control.py`, `tests/test_ops_safety.py` |
| S2 | Disabled auth requires explicit local-development acknowledgement; production env rejects `none` / `demo_key` auth modes | `validate_runtime()` at [config.py:38](../../src/threatprism/config.py); called from `create_app()` at [api/app.py:28](../../src/threatprism/api/app.py) | Mitigated for POC scope | `tests/test_ops_safety.py` |
| E1 | `ROLE_VIEW_POLICY` enforces requested-role ⊆ caller's-allowed-set; escalation raises 403 | `ROLE_VIEW_POLICY` at [auth/demo.py:24-31](../../src/threatprism/auth/demo.py); enforcement at [auth/demo.py:158-170](../../src/threatprism/auth/demo.py) | Mitigated | `tests/test_access_control.py`, `tests/test_operational_read_models.py` |
| R1 / DI4 | Authorization decisions (allow and deny) emit `AuditEvent` with hashed metadata (no raw credential) | `_authorization_event()` at [auth/demo.py:232](../../src/threatprism/auth/demo.py); `_request_metadata_hash()` (SHA-256) at [auth/demo.py:263](../../src/threatprism/auth/demo.py) | Mitigated | `tests/test_access_control.py`, `tests/test_healthcare_guardrails.py`, `tests/test_operational_read_models.py` |
| S3 | Production identity readiness requires static `external_oidc` config and keeps protected routes fail-closed until a token verifier exists | `evaluate_production_identity_readiness()` in [auth/production.py](../../src/threatprism/auth/production.py); `validate_runtime()` in [config.py](../../src/threatprism/config.py); startup warning in [api/app.py](../../src/threatprism/api/app.py) | Mitigated for readiness scope | `tests/test_production_identity_readiness.py`, `tests/test_ops_safety.py` |
| S4 | Local production token verifier validates signature, issuer, audience, time, tenant, and role claims before claims become authority | `verify_production_bearer_token()` in [auth/production.py](../../src/threatprism/auth/production.py); production integration in [auth/demo.py](../../src/threatprism/auth/demo.py) | Mitigated for local no-network verifier scope; live JWKS/IdP gated | `tests/test_production_token_verifier.py` |

### API Resource Controls

| Threat ID | Mitigation | Code Reference | State | Test File |
|-----------|------------|----------------|-------|-----------|
| D1 / OT-2 | `/cases` rejects request bodies over `MAX_REQUEST_BODY_BYTES` with HTTP 413 before route validation | `case_ingress_limits()` middleware in [api/app.py](../../src/threatprism/api/app.py); `Settings.max_request_body_bytes` in [config.py](../../src/threatprism/config.py) | Mitigated for POC scope | `tests/test_api_limits.py` |
| D2 / OT-3 | `/cases` has an in-process per-client rate limiter and background triage semaphore | `InMemoryRateLimiter` and `_run_triage_with_limit()` in [api/app.py](../../src/threatprism/api/app.py); `Settings.case_post_rate_limit_per_minute`; `Settings.triage_concurrency_limit` | Mitigated for POC scope | `tests/test_api_limits.py` |

### Dependency Hardening

| Threat ID | Mitigation | Code Reference | State | Test File |
|-----------|------------|----------------|-------|-----------|
| L6 / RR-L2 / OT-L6 | Direct dependencies exact-pinned; transitive lock file present; advisory `pip-audit` hook in validation wrapper | `requirements.txt`; `requirements-lock.txt`; `tools/validate-threatprism.ps1`; `tools/check_demo_safety.py` | Mitigated for POC scope | `tests/test_ops_safety.py` |

### Output Validation (LLM Guardrail Pipeline)

| Threat ID | Mitigation | Code Reference | State | Test File |
|-----------|------------|----------------|-------|-----------|
| T2 / L12 | Evidence IDs cited in findings, MITRE, GRC, hypotheses must exist in case evidence set | `validate_report_evidence()` at [evidence.py:6](../../src/threatprism/guardrails/evidence.py); called in `run_triage()` at [cases/service.py:151](../../src/threatprism/cases/service.py) | Mitigated | `tests/test_guardrail_failures.py`, `tests/test_healthcare_guardrails.py` |
| T3 / L13 / NC1 | Output regex blocks 10 prohibited patterns and every current pattern has a regression fixture plus a quarterly refresh runbook | `scan_output_policy()` at [policy.py:22](../../src/threatprism/guardrails/policy.py); `PROHIBITED_PATTERNS` at [policy.py:8-19](../../src/threatprism/guardrails/policy.py); [PATTERN_REFRESH.md](../runbooks/PATTERN_REFRESH.md) | Mitigated + process-backed | `tests/test_guardrail_failures.py`, `tests/test_healthcare_guardrails.py`, `tests/test_eval_harness.py`, `tests/test_overclaim_regression.py` |
| E2 / L9 | `"real_action_executed": true` blocked in serialized report | `enforce_action_safety()` at [policy.py:31](../../src/threatprism/guardrails/policy.py); called in `run_triage()` at [cases/service.py:152](../../src/threatprism/cases/service.py); `ALLOW_REAL_ACTIONS=false` default at [config.py:23](../../src/threatprism/config.py) | Mitigated | `tests/test_guardrail_failures.py`, `tests/test_eval_harness.py`, `tests/test_ops_safety.py` |
| L3 / L10 | Three-layer deterministic validation in `run_triage()`; failure sets `triage_status=blocked_by_guardrail` and skips persistence | `run_triage()` at [cases/service.py:135-167](../../src/threatprism/cases/service.py) | Mitigated | `tests/test_guardrail_failures.py`, `tests/test_eval_harness.py` |

### Prompt Firewall (Pre-Model Sanitization)

| Threat ID | Mitigation | Code Reference | State | Test File |
|-----------|------------|----------------|-------|-----------|
| I4 / L1 | 6 regex rules detect prompt injection in inbound text; `ignore_previous`, `system_prompt_request`, `prompt_exfil` trigger quarantine and block provider execution before triage generation. RR-L1 bypass rate measured against a real third-party corpus (deepset/prompt-injections): 1 quarantine, 5 redact, 6 unrecognized — the unrecognized rows reach the inert provider but never leak into reports/audit. | `sanitize_text()` at [prompt_firewall.py:26](../../src/threatprism/guardrails/prompt_firewall.py); `PROMPT_INJECTION_RULES` at [prompt_firewall.py:8-15](../../src/threatprism/guardrails/prompt_firewall.py); `sanitize_value()` at [prompt_firewall.py:39](../../src/threatprism/guardrails/prompt_firewall.py); quarantine enforcement in `run_triage()` at [cases/service.py:145](../../src/threatprism/cases/service.py) | Partial (RR-I4, RR-L1 semantic bypass only) | `tests/test_guardrails.py`, `tests/test_eval_harness.py`, `tests/test_quarantine_enforcement.py`, `tests/test_deepset_injection_corpus.py` |

### Healthcare Safeguard (Stage 1 Tokenization)

| Threat ID | Mitigation | Code Reference | State | Test File |
|-----------|------------|----------------|-------|-----------|
| I1 / L7 / DI1 | Detects and tokenizes PHI (MRN, patient ID, encounter ID, member ID, claim ID, appointment ID, DOB, clinical paths), PII (SSN, phone, address), secrets (API keys, passwords), and context-aware identifiers (email/IP/URL when healthcare context present) | `safeguard_value()` at [healthcare.py:219](../../src/threatprism/guardrails/healthcare.py); rule lists at [healthcare.py:107-216](../../src/threatprism/guardrails/healthcare.py); `_value_has_health_context()` at [healthcare.py:311](../../src/threatprism/guardrails/healthcare.py); `_apply_healthcare_safeguards()` at [cases/service.py:99](../../src/threatprism/cases/service.py) | Mitigated | `tests/test_healthcare_guardrails.py`, `tests/test_eval_harness.py`, `tests/test_ops_safety.py` |
| DI2 | Stage 1 tokens have `rehydration_allowed=False` permanently; `role_rehydration_allowed` all-False | `HealthcareTokenVault.token_for()` at [healthcare.py:53-97](../../src/threatprism/guardrails/healthcare.py); architectural - Stage 1 vault not carried into `_rehydrate_report()` | Mitigated + tested | `tests/test_stage1_no_rehydration.py` |

### Security Telemetry Tokenization (Stage 2)

| Threat ID | Mitigation | Code Reference | State | Test File |
|-----------|------------|----------------|-------|-----------|
| I3 | `TokenVault` is in-memory `@dataclass`, not serialized; `secret_like` returns `[REDACTED_SECRET]` even on rehydration | `TokenVault` at [tokenization.py:23](../../src/threatprism/guardrails/tokenization.py); `display_value()` at [tokenization.py:52](../../src/threatprism/guardrails/tokenization.py); `REHYDRATABLE_TYPES` at [tokenization.py:19](../../src/threatprism/guardrails/tokenization.py) excludes `secret_like` | Mitigated + tested | Eval category `token_vault_mapping_exposure` at [evals/runner.py:206](../../src/threatprism/evals/runner.py); `tests/test_token_vault_isolation.py` |

### Role-View Masking

| Threat ID | Mitigation | Code Reference | State | Test File |
|-----------|------------|----------------|-------|-----------|
| I2 / DI3 / NC3 | Security telemetry (IPs, URLs, emails, hashes) masked for all non-analyst/engineer roles | `render_role_view()` at [views.py:32](../../src/threatprism/guardrails/views.py); `_render_text()` at [views.py:67](../../src/threatprism/guardrails/views.py); `SECURITY_TELEMETRY_PATTERNS` at [views.py:13-18](../../src/threatprism/guardrails/views.py) | Mitigated | `tests/test_access_control.py`, `tests/test_operational_read_models.py`, `tests/test_healthcare_guardrails.py` |
| DT2 | Role-view access generates `role_view_policy_applied` and `rehydration_denied` audit events | `render_role_view()` at [views.py:32-52](../../src/threatprism/guardrails/views.py); `_record_role_view_audit()` at [cases/service.py:593](../../src/threatprism/cases/service.py) | Mitigated | `tests/test_access_control.py`, `tests/test_operational_read_models.py` |

### Dashboard Static Surface

| Threat ID | Mitigation | Code Reference | State | Test File |
|-----------|------------|----------------|-------|-----------|
| T4 / I5 | Dashboard route and assets include CSP, frame denial, no-sniff, no-referrer, permissions, same-origin resource policy, and no-store cache headers | `DASHBOARD_SECURITY_HEADERS` and `_apply_dashboard_security_headers()` in [api/app.py](../../src/threatprism/api/app.py) | Mitigated for local dashboard scope | `tests/test_dashboard_ui.py` |
| T4 / I5 | Dashboard JavaScript rejects non-same-origin request targets and bounds API calls with `AbortController` timeouts | `sameOriginUrl()` and `dashboardFetch()` in [dashboard/static/app.js](../../src/threatprism/dashboard/static/app.js) | Mitigated for local dashboard scope | `tests/test_dashboard_ui.py` |

### Eval Harness

| Threat ID | Mitigation | Code Reference | State | Test File |
|-----------|------------|----------------|-------|-----------|
| D3 | Fixture and output paths sandboxed under `tests/evals/` and `.eval_runs/` only | `_resolve_under_approved_dir()` at [evals/runner.py:334](../../src/threatprism/evals/runner.py); `_candidate_path()` at [evals/runner.py:350](../../src/threatprism/evals/runner.py) (rejects Windows absolute paths) | Mitigated | `tests/test_eval_harness.py` |
| DI5 | Eval artifacts sanitized through prompt firewall → healthcare safeguard → role-view masking before write; 16 sensitive keys stripped | `_safe_preview()` at [evals/runner.py:262](../../src/threatprism/evals/runner.py); `_strip_eval_metadata()` at [evals/runner.py:276](../../src/threatprism/evals/runner.py) | Mitigated | `tests/test_eval_harness.py`, `tests/test_ops_safety.py` |
| D3 (malformed fixture) | Malformed JSON lines or invalid fixtures handled without crash, reported as passed for `malformed_json_handling` category | `_iter_results()` at [evals/runner.py:97-115](../../src/threatprism/evals/runner.py) | Mitigated | `tests/test_eval_harness.py` |

### SOAR Adapter Layer

| Threat ID | Mitigation | Code Reference | State | Test File |
|-----------|------------|----------------|-------|-----------|
| I4 / L1 (via SOAR) | SOAR payload normalized to canonical `CaseCreate` before sanitization; source hash preserved | `normalize_soar_payload()` in `soar/generic.py`; `_payload_hash()` at [cases/service.py:714](../../src/threatprism/cases/service.py) | Mitigated | `tests/test_soar_adapters.py`, `tests/test_healthcare_guardrails.py`, `tests/test_guardrails.py` |

### Demo Seeder (Curated Fixture Replay)

| Threat ID | Mitigation | Code Reference | State | Test File |
|-----------|------------|----------------|-------|-----------|
| T (unreviewed/unsafe fixture seeded) | Seeds only manifest entries approved for `demo_review` with `approved_demo_safe` / `approved_for_tests` status; generated folder never auto-scanned | `CuratedFixtureSource._is_demo_seedable()` in [demo/seeding.py](../../src/threatprism/demo/seeding.py) | Mitigated | `tests/test_demo_seeding.py` |
| I/T (path traversal to non-fixture file) | Path sandbox rejects absolute, drive, traversal, non-`.jsonl`, and escaping paths before read | `CuratedFixtureSource._resolve_curated_path()` in [demo/seeding.py](../../src/threatprism/demo/seeding.py) | Mitigated | `tests/test_demo_seeding.py` |
| Bypassing guardrails via seed path | Seeder replays through real `create_case` + `run_triage`; full four-layer pipeline runs; `ALLOW_REAL_ACTIONS` unchanged | `DemoSeeder.seed()` in [demo/seeding.py](../../src/threatprism/demo/seeding.py); `create_case()` / `run_triage()` in [cases/service.py](../../src/threatprism/cases/service.py) | Mitigated | `tests/test_demo_seeding.py` |
| Demo seeding enabled in production | Startup hook defaults off; `validate_runtime()` refuses `THREATPRISM_DEMO_SEED` in prod | `Settings.validate_runtime()` in [config.py](../../src/threatprism/config.py); startup hook in [api/app.py](../../src/threatprism/api/app.py) | Mitigated | `tests/test_demo_seeding.py` |

### Third-Party Dataset Onboarding (Curated Datasets)

These controls govern the **second** fixture contract (`fixtures/curated_datasets/`),
which admits sanitized derivatives of reviewed third-party datasets (Synthea +
deepset, Apache-2.0 synthetic; OTRF, MIT lab telemetry). Onboarding a non-synthetic
third-party source is a new **supply-chain / data-provenance** trust boundary layered
on top of the hand-authored curated path above. The accepted-license decision is
anchored in code, not in the manifest the data ships with.

| Threat ID | Mitigation | Code Reference | State | Test File |
|-----------|------------|----------------|-------|-----------|
| L5 / T (tampered manifest self-certifies a license) | Accepted `license_review_status` values are a code-authoritative `frozenset`, not a manifest field; a tampered manifest cannot grant a license the code never allowed ("data describes, code decides") | `DATASET_ALLOWED_LICENSE_REVIEW` and `CuratedDatasetSource._is_dataset_seedable()` in [demo/seeding.py](../../src/threatprism/demo/seeding.py) | Mitigated | `tests/test_curated_dataset_seeding.py` |
| I1 / I2 / DI1 / LD1 (identifier disclosure from third-party lab telemetry) | OTRF lab events pass a fail-closed `SAFE_FIELDS` allowlist that **drops** every identifier (host, Hostname, UserID/SID, AccountName, Domain, port, `*Guid`, `TargetObject`) rather than tokenizing it; `Image` reduced to basename; SID and user-profile-path scrubbers as defense-in-depth | `SAFE_FIELDS`, `_project_safe()`, `_scrub_identifiers()` in [tools/fixture_factory/adapters/otrf_adapter.py](../../tools/fixture_factory/adapters/otrf_adapter.py) | Mitigated | `tests/test_otrf_telemetry_corpus.py` |
| L4 / OT-L2 (provenance — partial) | Each promoted fixture carries source id, source file, record index, and a `sha256` of the sanitized row; raw third-party rows are never committed (gitignored `external_datasets/`) | `source_metadata()` in [tools/fixture_factory/adapters/shared.py](../../tools/fixture_factory/adapters/shared.py); manifest provenance in `fixtures/curated_datasets/manifest.json` | Partial — provenance for the demo/eval corpus; full training-data curation remains gated to fine-tuning (OT-L2) | `tests/test_curated_dataset_seeding.py`, `tests/test_otrf_telemetry_corpus.py` |
| Bypassing guardrails via dataset seed path | `CuratedDatasetSource` replays through real `create_case` + `run_triage` (full four-layer pipeline) and reuses the same `.jsonl` path sandbox as the curated path | `CuratedDatasetSource` and `DemoSeeder.seed()` in [demo/seeding.py](../../src/threatprism/demo/seeding.py) | Mitigated | `tests/test_curated_dataset_seeding.py`, `tests/test_otrf_telemetry_corpus.py` |
| T (unreviewed local data implicitly seeded) | `LocalDatasetSource` (gitignored `external_datasets/` replay) is off by default — never the default `--source`, excluded from `--source all`, never in the startup hook, and refused in production | `LocalDatasetSource` in [demo/seeding.py](../../src/threatprism/demo/seeding.py); `_ensure_source_allowed()` in [demo/seed_cli.py](../../src/threatprism/demo/seed_cli.py) | Mitigated | `tests/test_local_dataset_seeding.py` |

### Enrichment Stubs

| Threat ID | Mitigation | Code Reference | State | Test File |
|-----------|------------|----------------|-------|-----------|
| Missing enrichment API keys | Provider stubs return structured `{"status": "not_configured"}` instead of crashing | `enrichment/` stub modules | Mitigated | `tests/test_enrichment_stubs.py` |

### API Contract

| Threat ID | Mitigation | Code Reference | State | Test File |
|-----------|------------|----------------|-------|-----------|
| OpenAPI route drift | API contract freeze tests assert current route and response-model surface | (test asserts shape via `app.openapi()`) | Mitigated | `tests/test_demo_scenarios_and_api_contract.py` |

### Operational Safety

| Threat ID | Mitigation | Code Reference | State | Test File |
|-----------|------------|----------------|-------|-----------|
| Live-provider credentials used during safe validation | Validation wrapper clears live-provider env vars; demo safety checker rejects unsafe posture | `tools/validate-threatprism.ps1`; `tools/check_demo_safety.py` | Mitigated | `tests/test_ops_safety.py` |

---

## Open Threats — No Current Mitigation

These threats have been identified in the three lens files but no code-level control exists in current POC scope. Each links back to the owner-signed treatment register in `docs/specs/21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md`.

| Threat ID | Description | Severity | Required Before | Proposed Test |
|-----------|-------------|----------|------------------|---------------|
| OT-1 | T1 — SQLite blob tampering not detectable | Medium | Non-demo data | `Proposed: tests/test_audit_integrity.py` |
| OT-7 | I4 — No semantic prompt-injection classifier | High (post real-LLM) | Real LLM rollout | `Proposed: tests/test_semantic_prompt_firewall.py` |
| OT-8 | R1 — No append-only audit log, no export, no retention | High | Non-demo data | `Proposed: tests/test_audit_integrity.py` |
| OT-L1 | L2 — No indirect prompt injection defenses | High | RAG implementation | `Proposed: tests/test_retrieval_guardrails.py` |
| OT-L2 | L4 — No training-data curation / provenance | High | Fine-tuning | `Proposed: tests/test_training_curation.py` |
| OT-L3 | L5 — No LLM-layer DoS protection | High | Real LLM rollout | `Proposed: tests/test_llm_dos.py` |
| OT-L4 | L8 — No tool/plugin design (allowlist, validation, approval) | Critical | Tool/function-calling | `Proposed: tests/test_tool_safety.py` |
| OT-L7 | L7 — No general data-regurgitation detection in output | High (post real-LLM) | Real LLM rollout | `Proposed: tests/test_output_regurgitation.py` |
| OT-L8 | Memory/write-back unspecified | High | Memory implementation | `Proposed: tests/test_memory_guardrails.py` |
| OT-L9 | Cross-tenant isolation unspecified | High | Multi-tenancy | `Proposed: tests/test_tenant_isolation.py` |
| OT-LD1 | NC2 — System not HIPAA-compliant for real PHI | Critical (real PHI) | Real PHI handling | External compliance review |
| OT-LD2 | RR-LD1 — `raw_value_hash` unsalted | Medium | Non-demo data | `Proposed: tests/test_hash_salting.py` |
| OT-LD5 | NC3 — Minimum-necessary policy review | Medium | Non-demo deployment | Review only |
| OT-LD6 | NC2 — No breach-notification workflow | High | Non-demo data | Runbook + review |

---

## Residual Risk Index

For tracking purposes only. Full details in the source files.

| Residual Risk | Source File | Summary |
|---------------|-------------|---------|
| RR-R1 | STRIDE | Audit events not tamper-evident (stored in same blob they describe) |
| RR-I4 | STRIDE | Prompt firewall is pattern-based, bypassable |
| RR-L1 | LLM | Pattern firewall is bypassable by semantic prompt injection; detected quarantine patterns now block provider execution. Bypass rate measured against deepset/prompt-injections corpus (6 of 12 promoted rows unrecognized); semantic layer specified in `docs/specs/32_SEMANTIC_PROMPT_INJECTION_LAYER.md` |
| RR-L3 | LLM | Output regex catches only known credential shapes |
| RR-LD1 | LINDDUN | `raw_value_hash` is unsalted SHA-256 |
| RR-LD2 | LINDDUN | Role-view masking is regex-based; novel formats may leak |

---

## Coverage Gaps (Threats Without Tests)

No cheap current-scope coverage gaps remain from the v0.2 treatment pass. The
remaining proposed tests are gated to future features such as real LLM, RAG,
memory, tools, multi-tenancy, non-demo persistence, or real PHI handling.

---

## Review Log

| Date | Reviewer | Verdict | Notes |
|------|----------|---------|-------|
| 2026-05-30 | Claude (auto-generated, awaiting human review) | Third-party dataset onboarding traceability added | OTRF Security-Datasets (MIT lab telemetry) onboarding introduced a supply-chain / data-provenance trust boundary. Added a "Third-Party Dataset Onboarding (Curated Datasets)" section mapping the code-authoritative license allowlist, fail-closed identifier-drop projection, `sha256` provenance, real-intake replay, and off-by-default `LocalDatasetSource` to `tests/test_curated_dataset_seeding.py`, `tests/test_otrf_telemetry_corpus.py`, and `tests/test_local_dataset_seeding.py`. OT-L2 (full training-data curation) remains gated to fine-tuning; a dedicated lens-level supply-chain threat ID (currently mapped descriptively to L4/L5) is recommended before any non-demo dataset is onboarded. |
| 2026-05-26 | Codex | Production token verifier implementation traceability updated | Closed S4 for local no-network verifier scope with fake JWKS tests. Live JWKS fetch and live IdP integration remain gated. |
| 2026-05-26 | Codex | Production token verifier design traceability updated | Added S4 design-only verifier entry and proposed future implementation tests. Runtime token verification remains gated. |
| 2026-05-26 | Codex | Production identity readiness traceability updated | Added S3 readiness control references and mapped them to `tests/test_production_identity_readiness.py` plus runtime guard checks. |
| 2026-05-26 | Codex | Production dashboard hardening traceability updated | Added T4/I5 dashboard static-surface controls and mapped them to `tests/test_dashboard_ui.py`. |
| 2026-05-24 | Codex | Slices A, B, D, E, and F traceability updated | Closed fail-closed auth, API resource controls, token-vault isolation tests, Stage 1 non-rehydration tests, pattern refresh fixtures, and dependency pinning entries for POC scope. |
| 2026-05-24 | Codex | Slice G traceability updated | Added `tests/test_quarantine_enforcement.py` as coverage for prompt-firewall quarantine enforcement and removed OT-L5 from open threats. |
| 2026-05-29 | Claude (auto-generated, awaiting human review) | Slice 6 traceability updated | Promoted deepset/prompt-injections corpus (12 fixtures) gives RR-L1 a measured bypass baseline; added `tests/test_deepset_injection_corpus.py` coverage and referenced the proposed semantic layer spec (`docs/specs/32_SEMANTIC_PROMPT_INJECTION_LAYER.md`). |
| 2026-05-24 | Claude (auto-generated, awaiting human review) | Draft — needs review | Refreshed from v0.1 to v0.2. Threat IDs now reference the STRIDE / LLM / LINDDUN files directly. Code references updated to `file:function` granularity verified against commit `fea5f9f`. Added Open Threats section with proposed test names for each unmitigated threat. Added Coverage Gaps section surfacing 2 mitigated-but-untested threats. |
