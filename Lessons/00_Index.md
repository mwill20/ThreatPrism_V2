# 📚 ThreatPrism Lessons Index

## Assumptions And Missing Context

- These lessons describe the code that exists now in `C:\Projects\ThreatPrismV2`.
- The current validated baseline is `282 passed` (3 skipped: opt-in live Prompt Guard 2 tests).
- Lessons use emojis because the lesson brief requested visual scanning markers.
- Line references are based on the live files at lesson creation time.
- This curriculum teaches implemented behavior first, then labels future guidance as `Recommended (not implemented here)`.

## How To Use These Lessons

Start at Lesson 00 and move in order. Each lesson includes:

- Goal, time estimate, and prerequisites.
- Pipeline context.
- Code walkthroughs with file and line references.
- Hands-on commands for PowerShell and bash where practical.
- Interview prep talk tracks.
- A quick reference card.

## Current ThreatPrism Pipeline

```text
Fake SOAR payload
  -> SOAR adapter normalization
  -> Case schema validation
  -> Healthcare safeguard scan
  -> Prompt firewall and tokenization
  -> Deterministic demo triage provider
  -> Schema, policy, evidence, and action-safety checks
  -> Controlled rehydration and role view rendering
  -> Deterministic report
  -> SQLite persistence
  -> Operational metrics and read models
  -> Dry-run eval harness and regression defense labs
  -> Safe validation wrapper and fake-data-only CI
  -> Threat model treatment register and demo hardening tests
  -> Demo scenario pack and API contract freeze tests
  -> Docker Compose local demo packaging
  -> Synthetic fixture factory for ignored reviewed source-shape conversion
  -> Curated generated-fixture promotion and expansion with manifest review
  -> Repository standards audit and reviewer-readiness docs
  -> CSI/RGOI read-only governed cognition and retrieval policy
  -> Dashboard data contract and fake persona response fixtures
  -> Dashboard UI hardening headers, same-origin request controls, and keyboard navigation
  -> Production identity readiness static config and fail-closed external_oidc boundary
  -> Production token verifier design for external_oidc verification
  -> Production token verifier implementation with local fake-JWKS verification
  -> Dataset-backed demo seeder replaying curated fixtures through real intake
  -> API responses and tests
```

## Lesson Plan

| Required | Lesson | Title | Primary Files |
|---|---|---|---|
| ✅ | [Lesson 00](Lesson00_System_Overview.md) | System Overview And North Star | `README.md`, `docs/ARCHITECTURAL_NORTH_STAR.md`, `docs/WORKING_CHECKLIST.md` |
| ✅ | [Lesson 01](Lesson01_API_Command_Center.md) | API Command Center | `src/threatprism/api/app.py`, `src/threatprism/cli/main.py`, `tests/test_api_flow.py` |
| ✅ | [Lesson 02](Lesson02_Case_Schemas_And_Service.md) | Case Schemas And Service Orchestration | `src/threatprism/cases/schemas.py`, `src/threatprism/cases/service.py` |
| ✅ | [Lesson 03](Lesson03_SOAR_Intake_Translator.md) | SOAR Intake Translator | `src/threatprism/soar/generic.py`, `examples/soar_payloads/*.json`, `tests/test_soar_adapters.py` |
| ✅ | [Lesson 04](Lesson04_Guardrail_Gatekeepers.md) | Prompt, Policy, Evidence, And Action Guardrails | `src/threatprism/guardrails/*.py`, `src/threatprism/actions/safety.py`, `tests/test_guardrails.py`, `tests/test_guardrail_failures.py` |
| ✅ | [Lesson 05](Lesson05_Healthcare_Safeguards_And_Role_Views.md) | Healthcare Safeguards And Role Views | `src/threatprism/guardrails/healthcare.py`, `src/threatprism/guardrails/views.py`, `tests/test_healthcare_guardrails.py` |
| ✅ | [Lesson 06](Lesson06_Deterministic_Triage_Mapping_And_Reports.md) | Deterministic Triage, Mapping, Enrichment, And Reports | `src/threatprism/llm/providers.py`, `src/threatprism/mitre/mapping.py`, `src/threatprism/grc/mapping.py`, `src/threatprism/enrichment/stubs.py`, `src/threatprism/reports/render.py` |
| ✅ | [Lesson 07](Lesson07_SQLite_Config_And_Identifiers.md) | SQLite, Config, And Identifiers | `src/threatprism/persistence/sqlite.py`, `src/threatprism/config.py`, `src/threatprism/ids.py`, `.env.example` |
| ✅ | [Lesson 08](Lesson08_Testing_Defense_Labs_And_Next_Slices.md) | Testing, Defense Labs, And Next Slices | `tests/*.py`, `docs/specs/16_*`, `docs/specs/17_*` |
| ✅ | [Lesson 09](Lesson09_Access_Control_And_Audit_Integrity.md) | Access Control And Audit Integrity | `src/threatprism/auth/demo.py`, `tests/test_access_control.py`, `.env.example` |
| ✅ | [Lesson 10](Lesson10_Operational_Read_Models_And_Metrics.md) | Operational Read Models And Metrics | `src/threatprism/cases/read_models.py`, `src/threatprism/api/app.py`, `tests/test_operational_read_models.py` |
| ✅ | [Lesson 11](Lesson11_Evaluation_Harness_And_Regression_Defense_Labs.md) | Evaluation Harness And Regression Defense Labs | `src/threatprism/evals/*.py`, `tests/evals/*.jsonl`, `tests/test_eval_harness.py` |
| ✅ | [Lesson 12](Lesson12_Demo_Operations_And_CI_Hardening.md) | Demo Operations And CI Hardening | `tools/*.py`, `tools/*.ps1`, `.github/workflows/safe-validation.yml`, `tests/test_ops_safety.py` |
| ✅ | [Lesson 13](Lesson13_Demo_Scenarios_And_API_Contract.md) | Demo Scenarios And API Contract | `src/threatprism/demo/scenarios.py`, `examples/demo_scenarios/*.json`, `tests/test_demo_scenarios_and_api_contract.py` |
| ✅ | [Lesson 14](Lesson14_Docker_Compose_Local_Demo_Packaging.md) | Docker Compose Local Demo Packaging | `Dockerfile`, `docker-compose.yml`, `.dockerignore`, `tests/test_docker_packaging.py` |
| ✅ | [Lesson 15](Lesson15_Threat_Model_Treatment_And_Demo_Hardening.md) | Threat Model Treatment And Demo Hardening | `docs/threat-models/*.md`, `docs/specs/21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md`, `docs/runbooks/PATTERN_REFRESH.md`, hardening tests |
| ✅ | [Lesson 16](Lesson16_Data_Strategy_And_Synthetic_Fixture_Factory.md) | Data Strategy And Synthetic Fixture Factory | `data_sources/registry.json`, `tools/fixture_factory/*.py`, `tests/test_fixture_factory.py` |
| yes | [Lesson 17](Lesson17_Repo_Standards_Readiness_Pass.md) | Repo Standards Readiness Pass | `REPO_AUDIT.md`, `README.md`, `docs/USAGE.md`, `docs/EVALUATION.md`, `docs/DEPLOYMENT.md` |
| yes | [Lesson 18](Lesson18_CSI_RGOI_Foundation.md) | CSI/RGOI Foundation | `src/threatprism/csi/*.py`, `tests/test_csi_rgoi.py`, `docs/CSI_RGOI_ARCHITECTURE.md` |
| yes | [Lesson 19](Lesson19_Dashboard_UI_Preparation.md) | Dashboard UI Preparation | `docs/DASHBOARD_DATA_CONTRACT.md`, `examples/dashboard_contract/*.json`, API contract tests |
| yes | [Lesson 20](Lesson20_Dashboard_UI_Implementation.md) | Dashboard UI Implementation | `src/threatprism/dashboard/static/*`, `tests/test_dashboard_ui.py`, `docs/DASHBOARD_UI_IMPLEMENTATION.md` |
| yes | [Lesson 21](Lesson21_Production_Dashboard_Hardening.md) | Production Dashboard Hardening | `src/threatprism/api/app.py`, `src/threatprism/dashboard/static/*`, `tests/test_dashboard_ui.py`, `docs/DASHBOARD_PRODUCTION_HARDENING.md` |
| yes | [Lesson 22](Lesson22_Curated_Generated_Fixture_Promotion.md) | Curated Generated-Fixture Promotion And Expansion | `fixtures/curated/*`, `tools/fixture_factory/promotions.py`, `tests/test_curated_fixture_promotion.py` |
| yes | [Lesson 23](Lesson23_Production_Identity_Readiness.md) | Production Identity Readiness | `src/threatprism/auth/production.py`, `src/threatprism/config.py`, `tests/test_production_identity_readiness.py` |
| yes | [Lesson 24](Lesson24_Production_Token_Verifier_Design.md) | Production Token Verifier Design | `docs/PRODUCTION_TOKEN_VERIFIER_DESIGN.md`, `docs/specs/29_PRODUCTION_TOKEN_VERIFIER_DESIGN.md`, `docs/runbooks/PRODUCTION_TOKEN_VERIFIER_DESIGN_REVIEW.md` |
| yes | [Lesson 25](Lesson25_Production_Token_Verifier_Implementation.md) | Production Token Verifier Implementation | `src/threatprism/auth/production.py`, `src/threatprism/auth/demo.py`, `tests/test_production_token_verifier.py` |
| yes | [Lesson 26](Lesson26_Dataset_Backed_Demo_Seeder.md) | Dataset-Backed Demo Seeder | `src/threatprism/demo/seeding.py`, `src/threatprism/demo/seed_cli.py`, `tests/test_demo_seeding.py`, `docs/specs/31_DATASET_BACKED_DEMO_SEEDER.md` |
| ✅ | [Lesson 27](Lesson27_Dataset_Onboarding_And_Fixture_Sources.md) | Dataset Onboarding And Fixture Source Contracts | `src/threatprism/demo/seeding.py`, `src/threatprism/demo/seed_cli.py`, `tools/fixture_factory/adapters/{synthea,deepset,otrf}_adapter.py`, `fixtures/curated_datasets/*`, `tests/test_curated_dataset_seeding.py`, `tests/test_otrf_telemetry_corpus.py`, `tests/test_local_dataset_seeding.py` |
| ✅ | [Lesson 28](Lesson28_Running_End_To_End_And_The_Feedback_Loop.md) | Running End-to-End And The Analyst Feedback Loop | `src/threatprism/demo/run_soc_demo.py`, `tests/test_soc_dataset_run.py`, `docs/PRODUCT_VALUE_AND_ROADMAP.md`, `docs/runbooks/RUN_AGAINST_SOC_DATASET.md` |
| ✅ | [Lesson 30](Lesson30_Semantic_Prompt_Injection_Firewall.md) | Semantic Prompt-Injection Firewall (Detector, Not Gate) | `src/threatprism/guardrails/semantic_firewall.py`, `src/threatprism/cases/service.py`, `src/threatprism/config.py`, `tests/test_semantic_prompt_firewall.py`, `docs/specs/32_SEMANTIC_PROMPT_INJECTION_LAYER.md` |
| ✅ | [Lesson 31](Lesson31_Real_LLM_Governance.md) | Real-LLM Governance: Spend Caps, Metering & Dual-Provider Accounting | `src/threatprism/llm/governance.py`, `src/threatprism/llm/providers.py`, `src/threatprism/llm/mock_analyst.py`, `src/threatprism/cases/read_models.py`, `tests/test_llm_governance.py`, `docs/specs/33_REAL_LLM_PROVIDER_AND_EXECUTIVE_SUMMARY.md`, `docs/specs/35_FAILED_CALL_COST_METERING.md`, `docs/specs/36_GOVERNED_BACKTEST_ANALYST_SPEND.md` |
| ✅ | [Lesson 32](Lesson32_Case_Ownership_And_Authorization.md) | Case Ownership & Authorization (Authn vs Authz vs Object-Level) | `src/threatprism/cases/service.py` (`assign_case`/`release_case`), `src/threatprism/api/app.py` (`_authorized_principal`, assign/release routes), `src/threatprism/cases/schemas.py`, `tests/test_case_assignment.py` |
| ✅ | [Lesson 33](Lesson33_Operating_The_Dashboard.md) | Operating the Dashboard (Analyst Co-Pilot Walkthrough) — how-to | `src/threatprism/dashboard/static/*`, `docs/runbooks/DASHBOARD_READINESS.md` |
| ✅ | [Lesson 29](Lesson29_Dev_Workflow_AI_Governance_Hooks.md) | Dev-Workflow AI Governance Hooks (Claude Code) | `docs/specs/34_DEV_WORKFLOW_AI_GOVERNANCE_HOOKS.md`, `.claude/settings.json`, `tools/hooks/*`, `tests/test_dev_workflow_hooks.py` |
| ✅ | [Lesson 34](Lesson34_In_Memory_SQLite_Concurrency.md) | In-Memory SQLite Concurrency 500 (Shared State Needs a Lock) | `src/threatprism/persistence/sqlite.py`, `tests/test_persistence_concurrency.py` |
| ✅ | [Lesson 35](Lesson35_Shared_Secret_Pattern_Catalog.md) | One Secret-Pattern Catalog, Many Consumers (DRY Without Coupling) | `src/threatprism/guardrails/secret_catalog.py`, `guardrails/{healthcare,tokenization,policy}.py`, `tools/hooks/_common.py`, `tests/test_secret_catalog.py` |
| ✅ | [Lesson 36](Lesson36_Live_Two_Model_Backtest.md) | The Live Two-Model Backtest (Reading "100% Agreement" Honestly) | `src/threatprism/demo/backtest.py`, `src/threatprism/llm/mock_analyst.py`, `src/threatprism/demo/seeding.py`, `tests/test_backtest.py`, `docs/LIVE_BACKTEST_FINDINGS.md` |
| ✅ | [Lesson 37](Lesson37_Adversarial_Ambiguous_Eval_Dataset.md) | Designing an Adversarial Dataset (An Eval Must Be Able to Fail) | `fixtures/curated_adversarial/*`, `src/threatprism/demo/seeding.py` (`AdversarialCuratedSource`), `src/threatprism/demo/backtest.py` (`--dataset`), `tests/test_adversarial_dataset.py`, `docs/specs/37_ADVERSARIAL_EVAL_DATASET.md` |

## File Coverage Map

### Source Files

- `C:\Projects\ThreatPrismV2\src\threatprism\__init__.py` -> Lesson 00
- `C:\Projects\ThreatPrismV2\src\threatprism\api\app.py` -> Lessons 01 and 21
- `C:\Projects\ThreatPrismV2\src\threatprism\auth\demo.py` -> Lesson 09
- `C:\Projects\ThreatPrismV2\src\threatprism\auth\production.py` -> Lesson 23
- `C:\Projects\ThreatPrismV2\src\threatprism\auth\__init__.py` -> Lesson 09
- `C:\Projects\ThreatPrismV2\src\threatprism\cli\main.py` -> Lesson 01
- `C:\Projects\ThreatPrismV2\src\threatprism\cases\schemas.py` -> Lesson 02
- `C:\Projects\ThreatPrismV2\src\threatprism\cases\service.py` -> Lesson 02
- `C:\Projects\ThreatPrismV2\src\threatprism\cases\read_models.py` -> Lesson 10
- `C:\Projects\ThreatPrismV2\src\threatprism\soar\generic.py` -> Lesson 03
- `C:\Projects\ThreatPrismV2\src\threatprism\guardrails\prompt_firewall.py` -> Lessons 04 and 30
- `C:\Projects\ThreatPrismV2\src\threatprism\guardrails\semantic_firewall.py` -> Lesson 30
- `C:\Projects\ThreatPrismV2\src\threatprism\guardrails\tokenization.py` -> Lessons 04 and 35
- `C:\Projects\ThreatPrismV2\src\threatprism\guardrails\policy.py` -> Lessons 04 and 35
- `C:\Projects\ThreatPrismV2\src\threatprism\guardrails\secret_catalog.py` -> Lesson 35
- `C:\Projects\ThreatPrismV2\src\threatprism\guardrails\evidence.py` -> Lesson 04
- `C:\Projects\ThreatPrismV2\src\threatprism\actions\safety.py` -> Lesson 04
- `C:\Projects\ThreatPrismV2\src\threatprism\guardrails\healthcare.py` -> Lessons 05 and 35
- `C:\Projects\ThreatPrismV2\src\threatprism\guardrails\views.py` -> Lesson 05
- `C:\Projects\ThreatPrismV2\src\threatprism\llm\providers.py` -> Lesson 06
- `C:\Projects\ThreatPrismV2\src\threatprism\mitre\mapping.py` -> Lesson 06
- `C:\Projects\ThreatPrismV2\src\threatprism\grc\mapping.py` -> Lesson 06
- `C:\Projects\ThreatPrismV2\src\threatprism\enrichment\stubs.py` -> Lesson 06
- `C:\Projects\ThreatPrismV2\src\threatprism\reports\render.py` -> Lesson 06
- `C:\Projects\ThreatPrismV2\src\threatprism\persistence\sqlite.py` -> Lessons 07 and 34
- `C:\Projects\ThreatPrismV2\src\threatprism\config.py` -> Lesson 07
- `C:\Projects\ThreatPrismV2\src\threatprism\ids.py` -> Lesson 07
- `C:\Projects\ThreatPrismV2\src\threatprism\evals\schemas.py` -> Lesson 11
- `C:\Projects\ThreatPrismV2\src\threatprism\evals\runner.py` -> Lesson 11
- `C:\Projects\ThreatPrismV2\src\threatprism\evals\cli.py` -> Lesson 11
- `C:\Projects\ThreatPrismV2\src\threatprism\demo\scenarios.py` -> Lesson 13
- `C:\Projects\ThreatPrismV2\src\threatprism\demo\seeding.py` -> Lessons 26 and 27
- `C:\Projects\ThreatPrismV2\src\threatprism\demo\seed_cli.py` -> Lessons 26 and 27
- `C:\Projects\ThreatPrismV2\tools\fixture_factory\adapters\*_adapter.py` -> Lessons 16 and 27
- `C:\Projects\ThreatPrismV2\fixtures\curated_datasets\*` -> Lesson 27
- `C:\Projects\ThreatPrismV2\src\threatprism\demo\run_soc_demo.py` -> Lesson 28
- `C:\Projects\ThreatPrismV2\tests\test_soc_dataset_run.py` -> Lesson 28
- `C:\Projects\ThreatPrismV2\docs\PRODUCT_VALUE_AND_ROADMAP.md` -> Lesson 28
- `C:\Projects\ThreatPrismV2\src\threatprism\dashboard\static\*` -> Lessons 20, 21, and 33
- `C:\Projects\ThreatPrismV2\src\threatprism\demo\auto_close_delta.py` -> Lesson 28
- `C:\Projects\ThreatPrismV2\tools\check_demo_safety.py` -> Lesson 12
- `C:\Projects\ThreatPrismV2\tools\validate-threatprism.ps1` -> Lesson 12
- `C:\Projects\ThreatPrismV2\.github\workflows\safe-validation.yml` -> Lesson 12
- `C:\Projects\ThreatPrismV2\tools\fixture_factory\*.py` -> Lesson 16
- `C:\Projects\ThreatPrismV2\tools\fixture_factory\promotions.py` -> Lesson 22
- `C:\Projects\ThreatPrismV2\fixtures\curated\*` -> Lesson 22
- `C:\Projects\ThreatPrismV2\src\threatprism\csi\*.py` -> Lesson 18
- `C:\Projects\ThreatPrismV2\data_sources\registry.json` -> Lesson 16
- `C:\Projects\ThreatPrismV2\external_datasets\README.md` -> Lesson 16
- `C:\Projects\ThreatPrismV2\REPO_AUDIT.md` -> Lesson 17
- `C:\Projects\ThreatPrismV2\docs\USAGE.md` -> Lesson 17
- `C:\Projects\ThreatPrismV2\docs\EVALUATION.md` -> Lesson 17
- `C:\Projects\ThreatPrismV2\docs\DATASET.md` -> Lesson 17
- `C:\Projects\ThreatPrismV2\docs\MODEL_CARD.md` -> Lesson 17
- `C:\Projects\ThreatPrismV2\docs\DEPLOYMENT.md` -> Lesson 17
- `C:\Projects\ThreatPrismV2\docs\MONITORING.md` -> Lesson 17
- `C:\Projects\ThreatPrismV2\docs\TROUBLESHOOTING.md` -> Lesson 17
- `C:\Projects\ThreatPrismV2\docs\CSI_RGOI_ARCHITECTURE.md` -> Lesson 18
- `C:\Projects\ThreatPrismV2\docs\CSI_RGOI_WORKFLOWS.md` -> Lesson 18
- `C:\Projects\ThreatPrismV2\docs\specs\23_CSI_RGOI_FOUNDATION.md` -> Lesson 18
- `C:\Projects\ThreatPrismV2\docs\DASHBOARD_DATA_CONTRACT.md` -> Lesson 19
- `C:\Projects\ThreatPrismV2\docs\specs\24_DASHBOARD_UI_PREPARATION.md` -> Lesson 19
- `C:\Projects\ThreatPrismV2\docs\runbooks\DASHBOARD_READINESS.md` -> Lesson 19
- `C:\Projects\ThreatPrismV2\docs\DASHBOARD_PRODUCTION_HARDENING.md` -> Lesson 21
- `C:\Projects\ThreatPrismV2\docs\specs\26_PRODUCTION_DASHBOARD_HARDENING.md` -> Lesson 21
- `C:\Projects\ThreatPrismV2\docs\PRODUCTION_IDENTITY_READINESS.md` -> Lesson 23
- `C:\Projects\ThreatPrismV2\docs\specs\28_PRODUCTION_IDENTITY_READINESS.md` -> Lesson 23
- `C:\Projects\ThreatPrismV2\docs\runbooks\PRODUCTION_IDENTITY_READINESS.md` -> Lesson 23
- `C:\Projects\ThreatPrismV2\docs\PRODUCTION_TOKEN_VERIFIER_DESIGN.md` -> Lesson 24
- `C:\Projects\ThreatPrismV2\docs\specs\29_PRODUCTION_TOKEN_VERIFIER_DESIGN.md` -> Lesson 24
- `C:\Projects\ThreatPrismV2\docs\runbooks\PRODUCTION_TOKEN_VERIFIER_DESIGN_REVIEW.md` -> Lesson 24
- `C:\Projects\ThreatPrismV2\docs\PRODUCTION_TOKEN_VERIFIER_IMPLEMENTATION.md` -> Lesson 25
- `C:\Projects\ThreatPrismV2\docs\specs\30_PRODUCTION_TOKEN_VERIFIER_IMPLEMENTATION.md` -> Lesson 25
- `C:\Projects\ThreatPrismV2\docs\runbooks\PRODUCTION_TOKEN_VERIFIER_LOCAL_VALIDATION.md` -> Lesson 25
- `C:\Projects\ThreatPrismV2\Dockerfile` -> Lesson 14
- `C:\Projects\ThreatPrismV2\docker-compose.yml` -> Lesson 14
- `C:\Projects\ThreatPrismV2\.dockerignore` -> Lesson 14

### Threat Model And Security Docs

- `C:\Projects\ThreatPrismV2\docs\threat-models\*.md` -> Lesson 15
- `C:\Projects\ThreatPrismV2\docs\specs\21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md` -> Lesson 15
- `C:\Projects\ThreatPrismV2\docs\runbooks\PATTERN_REFRESH.md` -> Lesson 15

### Tests And Fixtures

- `C:\Projects\ThreatPrismV2\tests\test_api_flow.py` -> Lessons 01 and 08
- `C:\Projects\ThreatPrismV2\tests\test_access_control.py` -> Lessons 08 and 09
- `C:\Projects\ThreatPrismV2\tests\test_operational_read_models.py` -> Lessons 08 and 10
- `C:\Projects\ThreatPrismV2\tests\test_eval_harness.py` -> Lessons 08 and 11
- `C:\Projects\ThreatPrismV2\tests\test_ops_safety.py` -> Lessons 08 and 12
- `C:\Projects\ThreatPrismV2\tests\test_demo_scenarios_and_api_contract.py` -> Lessons 08 and 13
- `C:\Projects\ThreatPrismV2\tests\test_docker_packaging.py` -> Lessons 08 and 14
- `C:\Projects\ThreatPrismV2\tests\test_quarantine_enforcement.py` -> Lessons 04, 08, and 15
- `C:\Projects\ThreatPrismV2\tests\test_api_limits.py` -> Lessons 01, 08, and 15
- `C:\Projects\ThreatPrismV2\tests\test_overclaim_regression.py` -> Lessons 04, 08, and 15
- `C:\Projects\ThreatPrismV2\tests\test_phi_detector_coverage.py` -> Lessons 05, 08, and 15
- `C:\Projects\ThreatPrismV2\tests\test_stage1_no_rehydration.py` -> Lessons 05, 08, and 15
- `C:\Projects\ThreatPrismV2\tests\test_token_vault_isolation.py` -> Lessons 05, 08, and 15
- `C:\Projects\ThreatPrismV2\tests\test_fixture_factory.py` -> Lessons 08 and 16
- `C:\Projects\ThreatPrismV2\tests\test_csi_rgoi.py` -> Lessons 08 and 18
- `C:\Projects\ThreatPrismV2\examples\dashboard_contract\*.json` -> Lesson 19
- `C:\Projects\ThreatPrismV2\tests\test_dashboard_ui.py` -> Lessons 08, 20, and 21
- `C:\Projects\ThreatPrismV2\tests\test_production_identity_readiness.py` -> Lessons 08, 23, and 24
- `C:\Projects\ThreatPrismV2\tests\test_production_token_verifier.py` -> Lessons 08 and 25
- `C:\Projects\ThreatPrismV2\tests\test_demo_seeding.py` -> Lessons 08 and 26
- `C:\Projects\ThreatPrismV2\tests\test_curated_dataset_seeding.py` -> Lesson 27
- `C:\Projects\ThreatPrismV2\tests\test_otrf_telemetry_corpus.py` -> Lesson 27
- `C:\Projects\ThreatPrismV2\tests\test_local_dataset_seeding.py` -> Lesson 27
- `C:\Projects\ThreatPrismV2\tests\test_semantic_prompt_firewall.py` -> Lesson 30
- `C:\Projects\ThreatPrismV2\tools\hooks\*.py` -> Lessons 29 and 35
- `C:\Projects\ThreatPrismV2\tests\test_dev_workflow_hooks.py` -> Lesson 29
- `C:\Projects\ThreatPrismV2\tests\test_secret_catalog.py` -> Lesson 35
- `C:\Projects\ThreatPrismV2\src\threatprism\llm\governance.py` -> Lesson 31
- `C:\Projects\ThreatPrismV2\src\threatprism\llm\mock_analyst.py` -> Lessons 31 and 36
- `C:\Projects\ThreatPrismV2\src\threatprism\demo\backtest.py` -> Lesson 36
- `C:\Projects\ThreatPrismV2\tests\test_backtest.py` -> Lesson 36
- `C:\Projects\ThreatPrismV2\fixtures\curated_adversarial\*` -> Lesson 37
- `C:\Projects\ThreatPrismV2\tests\test_adversarial_dataset.py` -> Lesson 37
- `C:\Projects\ThreatPrismV2\tests\test_llm_governance.py` -> Lesson 31
- `C:\Projects\ThreatPrismV2\tests\test_case_assignment.py` -> Lesson 32
- `C:\Projects\ThreatPrismV2\tests\test_persistence_concurrency.py` -> Lesson 34
- `C:\Projects\ThreatPrismV2\tests\evals\*.jsonl` -> Lesson 11
- `C:\Projects\ThreatPrismV2\tests\test_soar_adapters.py` -> Lessons 03 and 08
- `C:\Projects\ThreatPrismV2\tests\test_guardrails.py` -> Lessons 04 and 08
- `C:\Projects\ThreatPrismV2\tests\test_guardrail_failures.py` -> Lessons 04 and 08
- `C:\Projects\ThreatPrismV2\tests\test_healthcare_guardrails.py` -> Lessons 05 and 08
- `C:\Projects\ThreatPrismV2\tests\test_enrichment_stubs.py` -> Lessons 06 and 08
- `C:\Projects\ThreatPrismV2\examples\soar_payloads\*.json` -> Lesson 03
- `C:\Projects\ThreatPrismV2\examples\demo_scenarios\*.json` -> Lesson 13

## Fast Validation Commands

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

Bash:

```bash
cd /c/Projects/ThreatPrismV2
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_lessons
```

Expected output:

```text
282 passed
```

## What To Study Next

After Lesson 26, use the working checklist to choose the next requested slice:

- `C:\Projects\ThreatPrismV2\docs\WORKING_CHECKLIST.md`
- `C:\Projects\ThreatPrismV2\docs\ARCHITECTURAL_NORTH_STAR.md`
- `C:\Projects\ThreatPrismV2\docs\DATA_STRATEGY_AND_FIXTURE_FACTORY.md`
  when the next request involves datasets, synthetic fixtures, or data realism
