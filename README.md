# ThreatPrism

ThreatPrism is a demo-safe SOC migration accelerator for organizations moving
from outsourced SOC operations toward an internal SOC model.

It demonstrates a case-centric security backend that ingests fake SOAR-style
payloads, normalizes evidence, applies deterministic guardrails, produces
structured triage/GRC outputs, and exposes role-safe API views for local review.

## Purpose

ThreatPrism helps reviewers evaluate how a SOC migration assistant can combine
case intake, provenance, AI guardrails, analyst feedback, operational metrics,
and healthcare-adjacent data safeguards without using live providers or real
organizational data.

## What ThreatPrism Produces (and how it's used)

ThreatPrism is a **SOC triage co-pilot**. Given a raw case (an alert plus its
evidence, events, and entities), it produces a structured, evidence-grounded
**triage report**: a determination (benign/suspicious/malicious-class), severity,
disposition, confidence, findings that each cite the exact evidence supporting
them, ATT&CK mappings, competing hypotheses, recommended (simulated, never
executed) next steps, and an explicit list of what it did **not** check.

So instead of starting from a blank alert, an analyst starts from a completed
first-pass analysis to **verify, correct, and decide** — and every disagreement
they record (`POST /cases/{id}/analyst-feedback`) becomes structured tuning signal
(`DisagreementRecord` → `/metrics`). Managers get role-masked metrics, review
queues, and disagreement rates without touching raw sensitive data.

It is not an autonomous responder: `ALLOW_REAL_ACTIONS=false`, every report is
`analyst_review_required`, and the human is always the decision authority.

**Full explanation, the output anatomy, and the roadmap toward real-LLM,
analyst-in-the-loop deployment:**
[`docs/PRODUCT_VALUE_AND_ROADMAP.md`](docs/PRODUCT_VALUE_AND_ROADMAP.md). **See it
run:** `python -m threatprism.demo.run_soc_demo`.

## Intended Audience

This repository is intended for:

- security engineering and SOC workflow reviewers
- AI safety and guardrail reviewers
- GRC and healthcare safeguard reviewers
- engineering reviewers evaluating local reproducibility

Expected background:

- Python 3.11+
- basic FastAPI and pytest usage
- defensive security and SOC workflow concepts

## Project Status

Current status: demo-safe proof-of-concept backend with a local hardened
dashboard surface.

ThreatPrism is not production-ready. It does not process real organization
data, run live SOAR/cloud providers, or execute remediation.

The real-LLM gate (Claude triage + an independent OpenAI analyst + local Prompt
Guard 2) is **owner-opened and live-validated**, and **all three runtime evolutions
have been demonstrated** — Evolution 1 deterministically, Evolutions 2 and 3 with real
models. Highlights: the two-model backtest reproduces a real determination split on a
true-**blind** analyst (anchoring shown material, not circular), and the single-event
co-pilot run had real Claude rate an injection fixture `suspicious/0.95` where the demo
stub said `benign` — for ~$0.005. Full findings:
[docs/LIVE_BACKTEST_FINDINGS.md](docs/LIVE_BACKTEST_FINDINGS.md). Defaults remain
demo-safe — live providers run only under explicit gated config, the whole
investigation arc cost ~$0.49 under a fail-closed cap, and `ALLOW_REAL_ACTIONS=false`
still blocks all real actions.

The current repository contains the V2 spec pack plus the first backend slice:
generic SOAR case intake, case normalization, guardrails, deterministic demo
triage, SQLite persistence, FastAPI routes, fake SOAR payloads, and initial
tests.

The latest implemented guardrail slice also includes context-aware healthcare
safeguards, typed sensitive-data tokens, role-based rendering helpers, and
compliance-language scanning for healthcare/GRC claims.

The latest backend security slice adds demo API-key authentication,
identity-to-role mapping, role-view authorization, and safe authorization audit
events for role-aware case and report reads.

The latest operational slice adds safe metrics, dashboard-ready case-list read
models, manager-review and healthcare-review queue routes, filters, and
role-aware detail routes for evidence, timeline, MITRE, GRC, and audit events.

The latest regression slice adds a local dry-run evaluation harness with fake
JSONL fixtures, sanitized eval artifacts, path traversal protection, and tests
for prompt injection, unsafe action claims, healthcare leakage, auth
escalation, read-model leakage, audit leakage, and compliance-language
overclaims.

The latest operations slice adds a safe validation wrapper, a fake-data-only CI
workflow, a demo safety scanner, eval artifact hygiene checks, and runbook
updates for repeatable local and CI validation.

The latest demo slice adds a repeatable fake scenario pack for analyst,
manager/GRC, legal/privacy, audit/debug, and engineer workflows, plus OpenAPI
contract tests for the current backend routes.

The latest packaging slice adds Docker Compose local demo packaging for the
existing fake-data FastAPI backend, with deterministic demo defaults and no
live providers.

The latest data-realism slice adds a safe, deterministic synthetic fixture
factory that converts explicit local, manually reviewed source-shape samples
into sanitized ThreatPrism-native JSONL fixtures without downloads, live
providers, raw dataset commits, or baseline test auto-scanning.

The latest fixture-promotion slice expands the tracked curated fixture set to
four tiny hand-reviewed fake fixtures covering SOC, healthcare-context
exposure, prompt-injection, and evidence-conflict/GRC review scenarios.
Generated fixture output remains ignored and does not auto-feed tests or evals.

The latest CSI/RGOI slice adds read-only retrieval-governed organizational
cognition with cognitive object schemas, evidence alignment, trust scoring,
tenant namespace filtering, retrieval-zone policy, lineage, replay
scaffolding, observability, AI-vs-human divergence telemetry, fake fixtures,
and tests.

The latest dashboard slice adds a same-origin, fake-data-only dashboard served
by FastAPI at `GET /dashboard`. It consumes the documented role-safe API
contract without adding live providers, external frontend dependencies, real
data, live production token verification, or remediation.

The latest dashboard-hardening slice adds dashboard-specific security headers,
same-origin request enforcement, timeout-bounded API calls, and keyboard
persona navigation. It does not add live production token verification, live
providers, production deployment, or real data handling.

The latest production-identity-readiness slice adds a static
`API_AUTH_MODE=external_oidc` readiness boundary, production auth-mode
validation, OIDC-shaped configuration checks, and fail-closed protected-route
behavior. It does not add live JWKS fetch, OAuth flows, Entra calls, or real
credentials.

The latest production-token-verifier slice implements local no-network
`external_oidc` bearer-token verification against fake local JWKS JSON,
including asymmetric signature checks, issuer/audience/time checks,
claim-to-role mapping, role-view policy integration, fail-closed errors, and
sanitized audit telemetry. It does not implement live JWKS fetch, OIDC
discovery, Entra calls, real credentials, or production tenant administration.

Optional external research providers, such as Exa.ai, are documented only as a
deferred future enhancement. They are not needed for the current build and are
not part of CSI/RGOI memory, live RAG, validation, demos, or fixture promotion.

## Current Boundaries

- Demo data only.
- No real remediation or containment.
- `ALLOW_REAL_ACTIONS=false` by default.
- No live LLM, SOAR, cloud, or enrichment calls are required for the current
  slice.
- HITRUST output is category/alignment mapping only, not compliance or
  certification.
- V2 uses a clean architecture with selective V1 concept porting. Do not
  full-copy V1 into this repository.

## Requirements

| Requirement | Version / Notes |
|---|---|
| Python | 3.11 or later |
| Package manager | `pip` |
| OS | Developed and validated with Windows PowerShell commands; code is Python/FastAPI and should remain platform-portable. |
| External services | None for current local validation and demos |
| Docker | Optional, for Docker Compose local demo packaging |
| GPU | Not required |
| Live credentials | Not required and should not be used for current validation |

## Project Layout

```text
src/threatprism/
  api/            FastAPI application factory and routes
  auth/           Demo authentication, role-view authorization, and production identity readiness
  cases/          Case, triage report, feedback, read models, and service orchestration
  dashboard/      Static fake-data dashboard UI served by FastAPI
  evals/          Local dry-run regression evaluation harness
  csi/            Read-only governed cognition, trust, lineage, replay, and retrieval policy
  demo/           Typed fake scenario-pack loading
  guardrails/     Prompt firewall, tokenization, policy, and evidence checks
  llm/            Provider interface and deterministic demo provider
  persistence/    SQLite demo repository
  reports/        Deterministic report rendering
  soar/           SOAR payload normalization
  enrichment/     Demo enrichment stubs
docs/specs/       Product, architecture, API, data, security, and demo specs
examples/         Fake demo SOAR payloads and scenario packs
examples/csi/     Tiny fake CSI/RGOI cognitive object fixture descriptions
examples/dashboard_contract/
                  Fake dashboard response fixtures for persona contract review
tests/            API, guardrail, read-model, eval, and safety tests
tools/            Safe local validation and demo safety checks
tools/fixture_factory/
                  Local-only synthetic fixture factory
data_sources/     Review-required source registry
external_datasets/
                  Ignored local-only reviewed source sample staging
fixtures/generated/
                  Ignored generated fixture output
fixtures/curated/
                  Tracked, manually reviewed tiny synthetic fixtures
.github/          Fake-data-only CI workflow
Dockerfile        Local demo backend image
docker-compose.yml Local demo backend service
```

## Documentation Map

| Need | Start Here |
|---|---|
| **What the tool produces + roadmap** | [docs/PRODUCT_VALUE_AND_ROADMAP.md](docs/PRODUCT_VALUE_AND_ROADMAP.md) |
| Run end-to-end on a SOC dataset | [docs/runbooks/RUN_AGAINST_SOC_DATASET.md](docs/runbooks/RUN_AGAINST_SOC_DATASET.md) |
| Open the real-LLM gate (Claude/OpenAI) | [docs/specs/33_REAL_LLM_PROVIDER_AND_EXECUTIVE_SUMMARY.md](docs/specs/33_REAL_LLM_PROVIDER_AND_EXECUTIVE_SUMMARY.md), [docs/runbooks/OPEN_REAL_LLM_GATE.md](docs/runbooks/OPEN_REAL_LLM_GATE.md) |
| Live two-model backtest results + analysis | [docs/LIVE_BACKTEST_FINDINGS.md](docs/LIVE_BACKTEST_FINDINGS.md) |
| AI governance posture (Control/Audit/Safety) | [docs/AI_GOVERNANCE_ASSESSMENT.md](docs/AI_GOVERNANCE_ASSESSMENT.md) |
| Dev-workflow AI governance hooks (audit + secret-block + dashboard) | [docs/runbooks/DEV_WORKFLOW_HOOKS.md](docs/runbooks/DEV_WORKFLOW_HOOKS.md) (operate/disable/dashboard), [docs/specs/34_DEV_WORKFLOW_AI_GOVERNANCE_HOOKS.md](docs/specs/34_DEV_WORKFLOW_AI_GOVERNANCE_HOOKS.md) (design) |
| Setup | [docs/INSTALLATION.md](docs/INSTALLATION.md) |
| Usage examples | [docs/USAGE.md](docs/USAGE.md) |
| Architecture and data flow | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/ARCHITECTURAL_NORTH_STAR.md](docs/ARCHITECTURAL_NORTH_STAR.md) |
| Dashboard | [docs/DASHBOARD_UI_IMPLEMENTATION.md](docs/DASHBOARD_UI_IMPLEMENTATION.md), [docs/DASHBOARD_PRODUCTION_HARDENING.md](docs/DASHBOARD_PRODUCTION_HARDENING.md), [docs/DASHBOARD_DATA_CONTRACT.md](docs/DASHBOARD_DATA_CONTRACT.md), [docs/runbooks/DASHBOARD_READINESS.md](docs/runbooks/DASHBOARD_READINESS.md) |
| Production identity readiness | [docs/PRODUCTION_IDENTITY_READINESS.md](docs/PRODUCTION_IDENTITY_READINESS.md), [docs/PRODUCTION_TOKEN_VERIFIER_DESIGN.md](docs/PRODUCTION_TOKEN_VERIFIER_DESIGN.md), [docs/PRODUCTION_TOKEN_VERIFIER_IMPLEMENTATION.md](docs/PRODUCTION_TOKEN_VERIFIER_IMPLEMENTATION.md), [docs/specs/28_PRODUCTION_IDENTITY_READINESS.md](docs/specs/28_PRODUCTION_IDENTITY_READINESS.md), [docs/specs/29_PRODUCTION_TOKEN_VERIFIER_DESIGN.md](docs/specs/29_PRODUCTION_TOKEN_VERIFIER_DESIGN.md), [docs/specs/30_PRODUCTION_TOKEN_VERIFIER_IMPLEMENTATION.md](docs/specs/30_PRODUCTION_TOKEN_VERIFIER_IMPLEMENTATION.md), [docs/runbooks/PRODUCTION_IDENTITY_READINESS.md](docs/runbooks/PRODUCTION_IDENTITY_READINESS.md), [docs/runbooks/PRODUCTION_TOKEN_VERIFIER_LOCAL_VALIDATION.md](docs/runbooks/PRODUCTION_TOKEN_VERIFIER_LOCAL_VALIDATION.md) |
| Governed cognition | [docs/CSI_RGOI_ARCHITECTURE.md](docs/CSI_RGOI_ARCHITECTURE.md), [docs/CSI_RGOI_WORKFLOWS.md](docs/CSI_RGOI_WORKFLOWS.md), [docs/specs/23_CSI_RGOI_FOUNDATION.md](docs/specs/23_CSI_RGOI_FOUNDATION.md) |
| Future enhancement options | [docs/FUTURE_ENHANCEMENTS.md](docs/FUTURE_ENHANCEMENTS.md) |
| Evaluation evidence | [docs/EVALUATION.md](docs/EVALUATION.md), [docs/EVALUATION_HARNESS_AND_REGRESSION_DEFENSE_LABS.md](docs/EVALUATION_HARNESS_AND_REGRESSION_DEFENSE_LABS.md) |
| Dataset and fixture policy | [docs/DATASET.md](docs/DATASET.md), [docs/DATA_STRATEGY_AND_FIXTURE_FACTORY.md](docs/DATA_STRATEGY_AND_FIXTURE_FACTORY.md), [docs/CURATED_GENERATED_FIXTURE_PROMOTION.md](docs/CURATED_GENERATED_FIXTURE_PROMOTION.md) |
| Adversarial/ambiguous eval dataset (exercise disagreement detection) | [docs/specs/37_ADVERSARIAL_EVAL_DATASET.md](docs/specs/37_ADVERSARIAL_EVAL_DATASET.md), [fixtures/curated_adversarial/README.md](fixtures/curated_adversarial/README.md) |
| Model/provider behavior | [docs/MODEL_CARD.md](docs/MODEL_CARD.md) |
| Deployment boundary | [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) |
| Monitoring and maintenance | [docs/MONITORING.md](docs/MONITORING.md) |
| Security policy | [SECURITY.md](SECURITY.md) |
| Limitations | [LIMITATIONS.md](LIMITATIONS.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md), [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |
| Troubleshooting | [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) |
| Repository audit | [REPO_AUDIT.md](REPO_AUDIT.md) |

## Setup

From PowerShell:

```powershell
git clone https://github.com/mwill20/ThreatPrism_V2.git C:\Projects\ThreatPrismV2
Set-Location C:\Projects\ThreatPrismV2
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If you do not use a virtual environment, run the same install command from the
project root.

## Start A New AI Chat

Do not paste long handoff docs into a new chat. Use the compact startup file:

```powershell
Set-Location C:\Projects\ThreatPrismV2
Get-Content .\START_HERE.md
```

Generate a fresh compact handoff prompt:

```powershell
Set-Location C:\Projects\ThreatPrismV2
powershell -ExecutionPolicy Bypass -File .\tools\generate-compact-handoff.ps1
```

Claude Code users can run `/compact-handoff`. Codex users can ask for
`compact handoff` to trigger the global handoff skill.

## Validate

Use the safe local validation wrapper:

```powershell
Set-Location C:\Projects\ThreatPrismV2
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

The wrapper runs:

- Demo safety checks.
- Pytest with plugin autoload disabled and a fresh temp directory.
- The dry-run eval harness against fake fixtures.
- Eval artifact hygiene checks.

Current known result: see [docs/VALIDATION_BASELINE.md](docs/VALIDATION_BASELINE.md)
(canonical pass/skip count + eval result).

The underlying pytest command remains:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_ops_ci
```

Run only the safety checker:

```powershell
python tools\check_demo_safety.py --include-untracked
```

If Windows locks a reused pytest temp directory, rerun with a fresh ignored
`--basetemp` value.

## Generate Synthetic Fixtures

The fixture factory is local-only and requires explicit reviewed source samples
under `external_datasets/`. It does not download datasets and does not promote
generated fixtures into baseline tests automatically.

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -m tools.fixture_factory.factory --source synthea_sample_data --input external_datasets/synthea_sample --output fixtures/generated/synthea_healthcare.jsonl --limit 10
```

Output is written under `fixtures/generated/`, which is ignored by git except
for the placeholder file. Review generated fixtures manually before promoting
any curated sample into tracked tests or eval fixtures.

The tracked curated fixture set is under `fixtures/curated/` and is gated by
`fixtures/curated/manifest.json`. It currently contains four tiny
hand-reviewed fake fixtures for SOC, healthcare-context exposure,
prompt-injection, and evidence-conflict/GRC review.

Sanitized derivatives of reviewed third-party datasets live under
`fixtures/curated_datasets/` (a separate trust gate that accepts only an in-code
license allowlist): 12 column-projected Synthea healthcare fixtures (Apache-2.0),
12 `deepset/prompt-injections` fixtures (Apache-2.0), and 8 OTRF
Security-Datasets SOC-telemetry fixtures (MIT lab telemetry — identifiers such as
host, SID, account, and domain are dropped by a fail-closed field allowlist, not
just tokenized). The deepset set deliberately retains attacker-controlled
injection text un-redacted so the runtime prompt firewall is exercised on replay;
its bucket mix (1 quarantine, 5 redact, 6 unrecognized) gives RR-L1 a measured
baseline for the semantic layer
(`docs/specs/32_SEMANTIC_PROMPT_INJECTION_LAYER.md`), now **implemented and wired
as a default-off detector-not-gate** (local Prompt Guard 2 encoder; enable only
under the real-LLM gate, see `src/threatprism/guardrails/semantic_firewall.py`).
See `docs/DATASET.md` and
`Lessons/Lesson27_Dataset_Onboarding_And_Fixture_Sources.md`.

Run only the demo scenario and API contract checks:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest tests\test_demo_scenarios_and_api_contract.py -p no:cacheprovider --basetemp .pytest_tmp_run_demo_contract_focus
```

Expected focused result:

```text
4 passed
```

## Run The Dashboard

The local dashboard is served by the FastAPI backend and uses fake demo
credentials only:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
$env:THREATPRISM_ENV='demo'
$env:API_AUTH_MODE='demo_key'
$env:DEMO_API_KEYS='demo-analyst-key:demo_analyst:analyst,demo-engineer-key:demo_engineer:engineer,demo-manager-key:demo_manager:manager_grc,demo-legal-key:demo_legal:legal_privacy,demo-audit-key:demo_audit:audit_debug,demo-admin-key:demo_admin:admin'
$env:THREATPRISM_AUTH_REQUIRED='true'
$env:LLM_PROVIDER='deterministic_demo'
$env:ALLOW_REAL_ACTIONS='false'
$env:DATABASE_URL='sqlite:///:memory:'
python -m uvicorn threatprism.api.app:create_app --factory --host 127.0.0.1 --port 8765
```

Open:

```text
http://127.0.0.1:8765/dashboard
```

Use `Load demo case` to create a synthetic case through the existing fake-data
API flow.

The dashboard route and assets include security headers for CSP, frame
blocking, no-sniff, referrer policy, browser permissions, same-origin resource
policy, and no-store caching. The browser code rejects non-same-origin request
targets and bounds API calls with timeouts.

## Run The API

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
$env:API_AUTH_MODE='none'
$env:THREATPRISM_LOCAL_DEV_ACK='true'
$env:ALLOW_REAL_ACTIONS='false'
python -m uvicorn threatprism.api.app:create_app --factory --reload
```

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

## Run With Docker Compose

```powershell
Set-Location C:\Projects\ThreatPrismV2
docker compose up --build
```

The Compose service runs the same backend at `http://127.0.0.1:8000` with
`API_AUTH_MODE=demo_key`, fake demo credentials,
`LLM_PROVIDER=deterministic_demo`, and `ALLOW_REAL_ACTIONS=false`.

Stop the container:

```powershell
docker compose down
```

## Seed The Demo Database

Populate a fresh demo database with hand-reviewed curated fixtures by replaying
them through the real intake path. Local/demo only; refused in production.

Seed from the CLI:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
$env:API_AUTH_MODE='none'
$env:THREATPRISM_LOCAL_DEV_ACK='true'
python -m threatprism.demo.seed_cli
```

Or seed automatically at API startup:

```powershell
$env:THREATPRISM_DEMO_SEED='true'
python -m uvicorn threatprism.api.app:create_app --factory
```

## Run Against A SOC Dataset (End-to-End)

Prove the system works end-to-end on a realistic SOC dataset — no SOAR, no live
LLM, no production environment. This replays all three reviewed
`fixtures/curated_datasets/` families (Synthea, deepset, OTRF — 32 cases) through
the real intake + four-layer guardrail + triage pipeline and prints an
observable summary:

```powershell
$env:PYTHONPATH='src'
python -m threatprism.demo.run_soc_demo
```

It reports cases seeded per family, the terminal triage outcome (including the one
deepset injection case the prompt firewall quarantines end-to-end), severity and
determination distributions, and review-queue counts. This demonstrates pipeline,
guardrail, persistence, and observability correctness — not LLM reasoning quality,
which is gated on real-LLM rollout. Full walkthrough:
[`docs/runbooks/RUN_AGAINST_SOC_DATASET.md`](docs/runbooks/RUN_AGAINST_SOC_DATASET.md).

Re-running is idempotent: fixtures whose `source_case_id` already exists are
skipped. Curated fixtures are post-sanitization snapshots, so replay does not
re-trigger prompt-firewall quarantine for already-sanitized fixtures. See
`docs/specs/31_DATASET_BACKED_DEMO_SEEDER.md`.

## Real-LLM Triage (Gated)

By default ThreatPrism uses the inert `DeterministicDemoProvider`. A real-LLM
provider (Anthropic Claude as the triage brain; OpenAI as an independent
mock-analyst) is **designed and scaffolded** in
[`docs/specs/33_REAL_LLM_PROVIDER_AND_EXECUTIVE_SUMMARY.md`](docs/specs/33_REAL_LLM_PROVIDER_AND_EXECUTIVE_SUMMARY.md).
The deterministic core is implemented and tested with no network:

- **Untrusted-output validation** — LLM output (including the executive summary)
  is routed through the existing output-policy, evidence-grounding, and
  action-safety guardrails before it is trusted.
- **Structured failure reporting** — provider unreachable/timeout/rate-limit/auth,
  unparseable response, Pydantic schema failure, guardrail rejection, or budget
  exceeded each become a `TriageFailureReport` (what/why/which-guardrail/
  `pydantic_triggered`), and the case fails closed.
- **Deterministic batching** — `BATCH_MAX_EVENTS` (50) OR a token budget,
  whichever triggers first; a case is never split.

The live API calls are **gated** — they require your keys and are not exercised in
CI. To open the gate, follow
[`docs/runbooks/OPEN_REAL_LLM_GATE.md`](docs/runbooks/OPEN_REAL_LLM_GATE.md).

The **Evolution 2 backtest** (analyst-vs-ThreatPrism tuning loop) is runnable now
with a deterministic stand-in analyst — swap in the real OpenAI grader at the gate:

```powershell
$env:PYTHONPATH='src'
python -m threatprism.demo.backtest
```

It reports the determination agreement rate and the cases ThreatPrism flagged
non-benign where the analyst cleared them (the tuning signal).

## Demo SOAR Intake

Submit the fake generic SOAR payload:

```powershell
$payload = Get-Content -Raw .\examples\soar_payloads\generic_soar_case.json | ConvertFrom-Json
$created = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/cases -Body ($payload | ConvertTo-Json -Depth 20) -ContentType 'application/json'
$created
```

Fetch the triage report:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/cases/$($created.case_id)/triage-report"
```

Fetch operational metrics:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/metrics
```

Fetch the dashboard-ready case-list envelope:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/cases/read-model?manager_review_required=false"
```

Read dedicated review queues:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/queues/manager-review"
Invoke-RestMethod "http://127.0.0.1:8000/queues/healthcare-review"
```

## Query CSI/RGOI

CSI/RGOI routes are read-only. They require a `tenant_id` and return governed
cognitive objects only when tenant namespace, role, purpose, retrieval zone,
evidence alignment, trust, stale cognition, and quarantine controls permit it.

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/csi/objects?tenant_id=tenant_demo_alpha&query=identity"
Invoke-RestMethod "http://127.0.0.1:8000/csi/lineage/cog_reason_alpha_human_001?tenant_id=tenant_demo_alpha"
Invoke-RestMethod "http://127.0.0.1:8000/csi/replay/cog_reason_alpha_human_001?tenant_id=tenant_demo_alpha"
Invoke-RestMethod "http://127.0.0.1:8000/csi/observability?tenant_id=tenant_demo_alpha"
Invoke-RestMethod "http://127.0.0.1:8000/csi/divergence?tenant_id=tenant_demo_alpha"
```

CSI/RGOI does not write memory, approve knowledge, mutate trust, publish
suppressions, run live RAG, or execute remediation.

Submit analyst feedback:

```powershell
$feedback = @{
  analyst_id = 'analyst_demo_001'
  analyst_determination = 'benign'
  analyst_severity = 'low'
  analyst_confidence = 0.76
  analyst_final_disposition = 'close'
  analyst_notes = 'Synthetic review for local demo.'
  false_positive = $true
  missed_escalation = $true
}

Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/cases/$($created.case_id)/analyst-feedback" -Body ($feedback | ConvertTo-Json -Depth 20) -ContentType 'application/json'
```

## Run The Eval Harness

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -m threatprism.evals.cli --fixtures regression_cases.jsonl
```

Eval artifacts are written under `.eval_runs/<run_id>/` and contain sanitized
previews only.

## Evaluation

Current local validation evidence is documented in
[docs/EVALUATION.md](docs/EVALUATION.md). The canonical baseline (pass/skip count +
eval result) is [docs/VALIDATION_BASELINE.md](docs/VALIDATION_BASELINE.md).

This is deterministic fake-data regression evidence only. It is not a live LLM
safety proof, production-readiness claim, HIPAA compliance claim, HITRUST
certification claim, or audit opinion.

## Active Checklist

Track current work in `docs/WORKING_CHECKLIST.md`.

Use `docs/ARCHITECTURAL_NORTH_STAR.md` as the directional architecture guide
before starting a new slice, accepting a workaround, or adding a major
enhancement.

## Learning Curriculum

Use `Lessons/00_Index.md` for a hands-on curriculum that teaches the current
backend slices, guardrails, tests, and next implementation direction.

The completed healthcare safeguard slice is documented in
`docs/HEALTHCARE_SAFEGUARD_GUARDRAILS.md` and
`docs/specs/15_HEALTHCARE_SAFEGUARD_GUARDRAILS.md`.

Access Control & Audit Integrity v0.1 is implemented. See
`docs/ACCESS_CONTROL_AND_AUDIT_INTEGRITY.md` and
`docs/specs/17_ACCESS_CONTROL_AND_AUDIT_INTEGRITY.md`.

Operational Read Models & Metrics API v0.1 is implemented. See
`docs/OPERATIONAL_READ_MODELS_AND_METRICS.md` and
`docs/specs/16_OPERATIONAL_READ_MODELS_AND_METRICS.md`.

Evaluation Harness & Regression Defense Labs v0.1 is implemented. See
`docs/EVALUATION_HARNESS_AND_REGRESSION_DEFENSE_LABS.md` and
`docs/specs/11_EVALUATION_PLAN.md`.

Demo Operations & CI Hardening v0.1 is implemented. See
`docs/DEMO_OPERATIONS_AND_CI_HARDENING.md` and
`docs/specs/18_DEMO_OPERATIONS_AND_CI_HARDENING.md`.

Demo Scenario Pack & API Contract Freeze v0.1 is implemented. See
`docs/DEMO_SCENARIO_PACK_AND_API_CONTRACT.md`,
`docs/specs/19_DEMO_SCENARIO_PACK_AND_API_CONTRACT.md`, and
`examples/demo_scenarios/demo_scenario_pack.json`.

Data Strategy & Synthetic Fixture Factory v0.1 is implemented. See
`docs/DATA_STRATEGY_AND_FIXTURE_FACTORY.md`,
`docs/specs/20_DATA_STRATEGY_AND_FIXTURE_FACTORY.md`,
`data_sources/registry.json`, and `tools/fixture_factory/`. Public or
synthetic datasets must be manually reviewed, kept out of git as raw data, and
converted into sanitized ThreatPrism-native fixtures before use. Broader
Curated Fixture Expansion v0.2 adds four tracked fake fixtures through the
manifest review gate without enabling generated-folder auto-scanning.

CSI/RGOI Foundation v0.1 is implemented. See
`docs/CSI_RGOI_ARCHITECTURE.md`, `docs/CSI_RGOI_WORKFLOWS.md`,
`docs/specs/23_CSI_RGOI_FOUNDATION.md`, `src/threatprism/csi/`, and
`tests/test_csi_rgoi.py`.

Dashboard UI Preparation v0.1 is implemented. See
`docs/DASHBOARD_DATA_CONTRACT.md`,
`docs/specs/24_DASHBOARD_UI_PREPARATION.md`,
`docs/runbooks/DASHBOARD_READINESS.md`, `examples/dashboard_contract/`, and
the API contract tests in `tests/test_demo_scenarios_and_api_contract.py`.

Dashboard UI Implementation v0.1 is implemented. See
`docs/DASHBOARD_UI_IMPLEMENTATION.md`,
`docs/specs/25_DASHBOARD_UI_IMPLEMENTATION.md`,
`src/threatprism/dashboard/static/`, and `tests/test_dashboard_ui.py`.

Production Dashboard Hardening v0.1 is implemented. See
`docs/DASHBOARD_PRODUCTION_HARDENING.md` and
`docs/specs/26_PRODUCTION_DASHBOARD_HARDENING.md`. This is hardening for the
local fake-data UI only. Live production token verification, live integrations,
external telemetry, production deployment, and real data remain out of scope.

Production Identity Readiness v0.1 is implemented. See
`docs/PRODUCTION_IDENTITY_READINESS.md`,
`docs/specs/28_PRODUCTION_IDENTITY_READINESS.md`, and
`docs/runbooks/PRODUCTION_IDENTITY_READINESS.md`. This is static readiness
only. Live production token verification and trusted claim-to-role mapping are
still future work.

Production Token Verifier Design v0.1 is documented. Production Token Verifier
Implementation v0.1 is implemented for local fake-JWKS verification. See
`docs/PRODUCTION_TOKEN_VERIFIER_DESIGN.md`,
`docs/PRODUCTION_TOKEN_VERIFIER_IMPLEMENTATION.md`,
`docs/specs/29_PRODUCTION_TOKEN_VERIFIER_DESIGN.md`,
`docs/specs/30_PRODUCTION_TOKEN_VERIFIER_IMPLEMENTATION.md`, and
`docs/runbooks/PRODUCTION_TOKEN_VERIFIER_LOCAL_VALIDATION.md`. Live JWKS fetch,
Entra calls, real credentials, and production tenant administration remain
future gated work.

Docker Compose & Local Demo Packaging v0.1 is implemented. See
`docs/DOCKER_COMPOSE_LOCAL_DEMO_PACKAGING.md`,
`docs/specs/22_DOCKER_COMPOSE_LOCAL_DEMO_PACKAGING.md`, `Dockerfile`, and
`docker-compose.yml`.

## License

TODO: Add a license. Until a license is selected and a `LICENSE` file is added,
usage rights are unclear.

## Support

For questions, bugs, or feature requests, open a GitHub issue in
`mwill20/ThreatPrism_V2`.

Security issues should follow [SECURITY.md](SECURITY.md). Do not open public
issues for vulnerabilities or sensitive data exposure.
