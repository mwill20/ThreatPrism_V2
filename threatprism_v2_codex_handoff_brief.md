# ThreatPrism V2 — Codex Handoff Brief

## Purpose

This file summarizes the full planning conversation for ThreatPrism V2 in a clean, implementation-ready format for Codex.

Do not rely on the messy chat transcript. Also do not rely on the previous
final response if it conflicts with the repository; that response leaked
drafting/debug text. Use the live files and validation results as the source of
truth.

Implementation has begun after the original planning baseline. The current live
repo includes an initial backend slice under `src/threatprism/`, fake demo SOAR
payloads under `examples/soar_payloads/`, and tests under `tests/`.

Known validation command:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_new
```

Validation result on 2026-05-21:

```text
13 passed
```

Later validation after the healthcare safeguard guardrails slice on 2026-05-22:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_healthcare3
```

Result:

```text
22 passed
```

Latest validation after Evaluation Harness & Regression Defense Labs v0.1 on
2026-05-24:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_eval_harness_final3
```

Result:

```text
41 passed
```

If Windows reports `WinError 5` while cleaning a reused pytest base temp, rerun
with a fresh ignored base temp such as `.pytest_tmp_run_verify`.

---

## Project Name

Use this name consistently:

**ThreatPrism**

Do not use:
- Incorrect misspellings of the product name
- A V2 suffix as the product name

Repository name:

```text
mwill20/ThreatPrism_V2
```

Local folder target:

```text
C:\Projects\ThreatPrismV2
```

---

## Original Repository

Source repository:

```text
https://github.com/mwill20/threatprism
```

This is the V1 proof-of-concept.

ThreatPrism V2 should use a clean V2 architecture with selective V1 module
porting. Do not full-copy V1 into this repository.

Important rule:

```text
Do not modify the original mwill20/threatprism repository directly.
Copy/fork it first, then work only in the new V2 project.
```

---

## Privacy Rule

Do not mention any real employer, healthcare organization, or specific user workplace anywhere in:

- Code
- Documentation
- Examples
- Comments
- Commit messages
- README
- Demo data

Frame the project generically as a tool for organizations migrating from outsourced MSSP-managed SOC operations to an internal SOC model.

---

## Product Vision

ThreatPrism V2 is a production-style, demo-safe SOC migration accelerator for organizations moving from outsourced SOC/MSSP management toward an internal SOC.

ThreatPrism V2 helps internal SOC teams by providing:

- AI-assisted triage
- Evidence-first SOC reports
- Analyst review workflows
- SOAR integration
- Microsoft security stack friendliness
- Provider-agnostic data intake
- HITRUST-aligned GRC mapping
- Analyst-vs-AI disagreement tracking
- Management and engineering insight
- Guardrail-first AI security
- Demo-safe action simulation

ThreatPrism V2 is not a production deployment yet. It should be designed so it can be adapted to production with minimal architectural change.

---

## Core Philosophy

Preserve the V1 philosophy:

- Evidence-first SOC analysis
- Analyst control
- Deterministic guardrails
- Structured LLM output
- Schema validation
- No autonomous remediation
- Auditable reporting
- Treat LLM output as untrusted until validated
- Human analyst review required

Use `docs/ARCHITECTURAL_NORTH_STAR.md` as the directional guide before new
implementation slices, workarounds, or major enhancements. If architecture
direction changes intentionally, update the North Star, `DECISIONS.md`, and
`docs/WORKING_CHECKLIST.md` together.

---

## Target Architecture

ThreatPrism V2 should evolve into:

```text
CLI + API service + dashboard-ready backend
```

Required design goals:

- Keep or improve the CLI.
- Add a FastAPI service unless the repo strongly suggests a better Python API framework.
- Add dashboard-ready backend routes and schemas.
- Do not build a full frontend dashboard yet unless explicitly requested later.
- Design API responses so a dashboard can be added later.

---

## Main Use Case

ThreatPrism V2 supports an organization transitioning from MSSP-managed SOC operations to an internal SOC.

It should help answer:

- Are SOAR automations working?
- Did automation miss anything?
- Did analysts miss anything?
- Where did ThreatPrism and the analyst disagree?
- Which cases consumed more analyst time?
- Are high-risk cases being handled correctly?
- What findings map to security/GRC control categories?
- What evidence supports each triage decision?

---

## Three Evolution Stages

### Evolution 1: Batch Triage Over SOAR-Automated Cases

ThreatPrism runs triage over batches of events/cases already automated away by SOAR.

Purpose:

- Catch anything automation missed.
- Validate SOAR automations are working.
- Add confidence to automated closures.
- Create auditability.
- Serve as a catchall quality-control layer.

---

### Evolution 2: Batch Review of Human Analyst Determinations

ThreatPrism runs batched triage over cases already handled by human analysts.

Purpose:

- Compare ThreatPrism assessment to analyst determination.
- Identify possible analyst misses.
- Identify where analysts spent more time on cases ThreatPrism marked high risk.
- Identify disagreement patterns between human analysts and ThreatPrism.
- Reveal opportunities to refine ThreatPrism.
- Reveal analyst training, workload, fatigue, process, or laziness issues.
- Provide engineering and management insight.

---

### Evolution 3: Parallel Per-Event SOAR Triage

ThreatPrism runs in parallel per event/case.

Requirements:

- ThreatPrism must not block SOAR workflows.
- SOAR sends the case/event payload to ThreatPrism.
- ThreatPrism immediately returns a tracking ID/status.
- Analyst can continue working in the SOAR.
- ThreatPrism processes triage asynchronously.
- When the report is ready, it can be posted back to SOAR or exposed via API.
- If ThreatPrism is slow, fails, or times out, SOAR continues.
- ThreatPrism failure must not delay incident response.

---

## SOAR Integration

Use a provider-agnostic SOAR adapter interface.

Required adapters/examples:

- Generic webhook adapter
- Microsoft Sentinel / Logic Apps style payload adapter

Demo data required:

```text
examples/soar_payloads/
  generic_soar_case.json
  sentinel_incident.json
  defender_xdr_alert.json
  logic_apps_webhook_payload.json
  swimlane_case_mock.json
```

The demo must not require live SOAR credentials.

---

## Microsoft Security Stack

ThreatPrism should be flexible, but easy to adapt to Microsoft security tools.

Target integrations:

- Microsoft Sentinel incidents
- Microsoft Defender XDR incidents
- Microsoft Defender for Endpoint alerts
- Microsoft Graph Security API
- Microsoft Entra ID sign-in/audit logs
- Azure Monitor / Log Analytics / KQL exports
- Logic Apps / Power Automate webhook flows

Microsoft should be a first-class integration path, but the ingestion model must remain provider-agnostic.

---

## Data Source Strategy

ThreatPrism should accept data from any provider/service that comes through SOAR or API.

Potential data sources:

- Microsoft Sentinel
- Defender XDR
- Generic SOAR webhook
- Cloud logs
- EDR alerts
- SIEM exports
- Identity alerts
- Email security alerts
- Proxy logs
- DNS logs
- Firewall logs
- Existing V1 data sources where useful

---

## Tenancy

V2 is:

```text
Single-org internal SOC only.
```

Do not build MSSP multi-tenancy.

However, avoid hardcoded assumptions that would make future multi-tenant support impossible.

---

## Core Case Model

Design a case model similar to:

```text
Case
- case_id
- source
- source_case_id
- organization_context
- title
- description
- created_at
- updated_at
- status
- alerts
- events
- entities
- IOCs
- evidence
- timeline
- hypotheses
- MITRE mappings
- threat intelligence enrichment
- recommended actions
- simulated actions
- GRC/HITRUST-aligned controls
- analyst feedback
- triage report
- audit trail
```

---

## SOC Workflow

ThreatPrism should support this SOC workflow:

1. Alert intake
2. Evidence normalization
3. Entity extraction
4. IOC extraction
5. IOC enrichment
6. MITRE mapping
7. Timeline generation
8. Hypothesis generation
9. Severity recommendation
10. Disposition recommendation
11. Control mapping
12. Analyst approval
13. Report generation
14. Analyst feedback capture
15. Management/engineering metrics

---

## SOC-Native Fields

Use fields like:

```text
determination:
- benign
- suspicious
- malicious
- critical

severity:
- low
- medium
- high
- critical

disposition:
- close
- monitor
- escalate
- needs_more_info

confidence:
- 0.0 to 1.0
```

Every triage report should include:

- Summary
- Determination
- Severity
- Disposition
- Confidence
- Evidence
- Timeline
- IOCs
- MITRE ATT&CK mapping
- Hypotheses
- Recommended analyst actions
- Simulated response actions if applicable
- GRC/HITRUST-aligned controls
- Limitations
- Analyst review required statement

---

## Analyst Feedback and Disagreement Tracking

Codex should implement or spec tracking for:

- ThreatPrism determination vs analyst determination
- ThreatPrism severity vs analyst severity
- ThreatPrism confidence vs analyst confidence
- ThreatPrism recommended disposition vs analyst final disposition
- time_to_acknowledge
- time_to_close
- analyst_notes
- manager_review_required
- false_positive
- false_negative
- missed_ioc
- missed_mitre_mapping
- missed_escalation

Required API endpoint:

```text
POST /cases/{case_id}/analyst-feedback
```

Purpose:

- QA over analyst decisions
- ThreatPrism refinement
- SOC process improvement
- Analyst training opportunities
- Detection engineering feedback
- Management reporting

---

## API Design Targets

Design these API routes:

```text
/health
/metrics
/cases
/cases/{case_id}
/cases/{case_id}/triage-report
/cases/{case_id}/evidence
/cases/{case_id}/timeline
/cases/{case_id}/ioc-enrichment
/cases/{case_id}/mitre
/cases/{case_id}/grc-controls
/cases/{case_id}/analyst-feedback
/evals/run
```

Implement core routes first:

```text
/health
/cases
/cases/{case_id}
/cases/{case_id}/triage-report
/cases/{case_id}/analyst-feedback
```

Stub or document the remaining routes if needed.

---

## AI Provider Strategy

Use a provider-agnostic LLM interface.

Default provider:

```text
OpenAI
```

Optional/local provider:

```text
OpenAI-compatible local endpoint or Ollama-compatible provider
```

Do not hardcode one provider deeply into business logic.

Use environment variables and configuration.

---

## AI Security and Guardrails

Implement or preserve layered guardrails:

1. Deterministic prompt firewall
2. Input sanitization
3. Schema validation
4. Semantic prompt-injection classifier interface
5. Output policy scanner
6. Strict structured output
7. Evidence-grounding checks
8. No autonomous action enforcement
9. Audit logging
10. Fail-closed behavior where possible

Treat all case text, alert text, logs, and artifacts as untrusted input.

Treat all LLM output as untrusted until validated.

---

## Evaluation Harness

Implemented fixture files:

```text
tests/evals/
  regression_cases.jsonl
  malformed_cases.jsonl
```

Eval harness tests:

- Prompt injection resistance
- Hallucinated claims
- Unsupported conclusions
- Unsafe action claims
- Schema violations
- Evidence citation failures
- Misclassification risk
- No autonomous action claims
- Healthcare safeguard leakage
- Authorization escalation
- Cross-role data leakage
- Metrics/read-model leakage
- Audit-event leakage
- Token-vault mapping exposure
- Compliance-language overclaiming
- Oversized payload handling
- Malformed JSON handling
- Conflicting evidence handling

Eval artifacts are written only under `.eval_runs/` and store sanitized
previews, not raw payload bodies.

---

## Action Safety Model

ThreatPrism V2 must not execute real remediation or containment actions.

Allowed in V2:

- Recommended actions
- Simulated actions
- Dry-run action planning
- Action adapter interface scaffolding

Blocked in V2:

- Real endpoint isolation
- Real account disablement
- Real firewall blocking
- Real email deletion
- Real token revocation
- Any production-impacting action

Hard-coded fail-closed default:

```text
ALLOW_REAL_ACTIONS=false
```

Real remediation/containment is out of scope for V2 and reserved for future V3.

Any future real action must require:

- Explicit configuration
- Authorization
- Audit trail
- RBAC
- Approval workflow
- Safety checks

---

## Threat Intelligence and Enrichment

Add interfaces/stubs for:

- VirusTotal
- URLScan.io
- AbuseIPDB
- WHOIS/RDAP

Use environment variables for API keys.

Do not require live keys for demo mode.

If keys are missing, return clear “not configured” enrichment results instead of crashing.

---

## MITRE ATT&CK

Add MITRE mapping support.

This can start as simple rule-based or LLM-assisted mapping, but outputs must be:

- Structured
- Evidence-linked
- Reviewable by analysts

---

## GRC / HITRUST Alignment

Add a HITRUST-aligned GRC module.

For healthcare-oriented work, ThreatPrism uses safeguard and evidence-alignment
language. It does not classify every identifier as PHI/ePHI by itself.
Identifiers become PHI/ePHI risk when connected to health, patient, care,
billing, encounter, or similar identifying context.

Important language rules:

Do not claim:

- HIPAA compliance
- HIPAA certification
- HITRUST compliance
- HITRUST certification
- That the tool implements HITRUST
- That a control is satisfied
- That evidence is audit-ready
- That evidence proves compliance

Use language like:

- HIPAA Security Rule safeguard theme
- HITRUST-aligned
- HITRUST-inspired control mapping
- HITRUST-style framework category
- GRC-ready evidence organization
- Control category mapping
- Evidence-to-control traceability
- Evidence alignment

Map at the control category level, not specific HITRUST control IDs, unless specific licensed/source material is available and legally usable.

Control categories should include:

- Access control
- Audit logging
- Incident response
- Risk management
- Vendor/third-party risk
- Configuration management
- Data protection
- Vulnerability management
- Change management
- Security monitoring
- Identity and access management

Required docs:

```text
docs/ARCHITECTURAL_NORTH_STAR.md
docs/HITRUST_ALIGNMENT.md
docs/GRC_MAPPING.md
```

---

## Database Strategy

Use:

```text
SQLite for demo mode.
```

But design persistence so PostgreSQL can be added later.

Prefer a clean abstraction layer.

If feasible:

- SQLAlchemy
- Alembic migration notes
- PostgreSQL-ready schema design

---

## Docker Strategy

Add Docker Compose for demo/prod-style local execution.

Recommended services:

```text
threatprism-api
threatprism-worker, if a separate worker is used
postgres, optional/profiled production-style service
redis, only if queue-based background jobs are used
```

Keep demo mode simple and runnable.

---

## Required Documentation

Create or update:

```text
README.md
ARCHITECTURE.md
SECURITY.md
GRC_MAPPING.md
HITRUST_ALIGNMENT.md
RUNBOOK.md
EVALUATION.md
LIMITATIONS.md
DECISIONS.md
docs/V2_AUDIT.md
docs/V2_IMPLEMENTATION_PLAN.md
.env.example
docker-compose.yml
AGENTS.md
```

Also consider:

```text
docs/SOC_WORKFLOW.md
docs/SOAR_INTEGRATION.md
docs/MICROSOFT_INTEGRATION.md
docs/ACTION_SAFETY_MODEL.md
docs/API.md
docs/DEMO_GUIDE.md
```

---

## Spec Pack

Before heavy coding, create:

```text
docs/specs/
  00_VISION.md
  01_PRODUCT_REQUIREMENTS.md
  02_ARCHITECTURE.md
  03_SOC_WORKFLOWS.md
  04_API_CONTRACT.md
  05_DATA_MODEL.md
  06_SOAR_INTEGRATION.md
  07_MICROSOFT_INTEGRATION.md
  08_AI_GUARDRAILS.md
  09_ACTION_SAFETY_MODEL.md
  10_GRC_HITRUST_ALIGNMENT.md
  11_EVALUATION_PLAN.md
  12_IMPLEMENTATION_ROADMAP.md
  13_ACCEPTANCE_CRITERIA.md
  14_DEMO_PLAN.md
```

Specs should be implementation-ready, not vague.

Include examples of:

- API payloads
- Case model fields
- Triage report schema
- Analyst feedback fields
- Acceptance criteria

---

## AGENTS / Skills / Sub-Agents

Add `AGENTS.md` with guidance for future Codex work.

Recommended roles:

- Architect agent
- Security reviewer agent
- SOC workflow reviewer agent
- GRC reviewer agent
- Test/eval agent
- Documentation agent

If appropriate, scaffold a skills/workflows directory for repeatable project tasks:

- Repo audit
- SOC triage report validation
- GRC mapping review
- Guardrail eval creation
- Documentation consistency check
- Security review

Do not over-engineer this if unsupported by the local environment.

At minimum, create `AGENTS.md`.

---

## CI/CD

Add basic CI/CD suitable for a Python security project.

Include where reasonable:

- pytest
- ruff
- mypy, if feasible
- bandit
- semgrep
- gitleaks or secret scanning guidance
- dependency checks
- GitHub Actions workflow

Do not break the project by adding overly strict checks before the codebase is ready.

If strict checks would fail due to existing V1 issues, document the gap and start with warning/non-blocking mode.

---

## Security Rules

- Never log raw secrets.
- Never log full API keys.
- Never log sensitive case payloads unnecessarily.
- Do not store real customer data.
- Demo data must be fake.
- Sanitize prompt-injection-like content.
- Treat alert/case text as untrusted input.
- Treat inbound SOAR payloads as potentially contaminated even when SOAR is
  expected to contain security-only telemetry.
- Treat LLM output as untrusted until schema-validated.
- Do not allow real actions.
- Use `.env.example`, not real `.env` secrets.
- Add clear security limitations.

---

## Testing Requirements

Add or update tests for:

- API health route
- Case creation
- Triage report generation
- Analyst feedback
- Schema validation
- Prompt injection handling
- Action blocking
- Missing API keys for enrichment
- HITRUST/GRC mapping output
- Demo SOAR payload ingestion

---

## First Vertical Slice

Do not try to build the whole platform first.

The first vertical slice should be:

```text
Generic SOAR webhook payload
  ↓
Normalize into ThreatPrism Case
  ↓
Start async triage job
  ↓
Generate structured triage report
  ↓
Add MITRE + IOC + GRC mappings, even if stubbed
  ↓
Return/report status via API
  ↓
Analyst submits feedback
  ↓
ThreatPrism records disagreement metrics
```

The healthcare safeguard slice is implemented. Access Control & Audit Integrity
v0.1 is implemented. Operational Read Models & Metrics API v0.1 is implemented:

```text
Operational Read Models & Metrics API v0.1
  -> Stable GET /metrics aggregate response shape
  -> Dashboard-ready GET /cases/read-model companion envelope route
  -> Manager-review and healthcare-review queue behavior
  -> Safe detail routes for evidence, timeline, MITRE, GRC, and audit events
  -> Authorization and role-safe rendering on read/detail routes
```

Evaluation Harness & Regression Defense Labs v0.1 is implemented.

The immediate next recommended slice is Demo Operations & CI Hardening v0.1.

---

## Recommended Build Order

```text
Phase 0: Repo copy + baseline audit
Phase 1: Spec pack
Phase 2: Core case model
Phase 3: FastAPI skeleton
Phase 4: Generic SOAR webhook ingestion
Phase 5: Async triage job
Phase 6: Triage report schema
Phase 7: Analyst feedback/disagreement model
Phase 8: Guardrails and evals
Phase 9: Threat intel stubs
Phase 10: MITRE + GRC mapping
Phase 11: Microsoft adapter examples
Phase 12: Docker + CI/CD + demo guide
```

---

## Codex Task 1 Prompt: Spec Pack Only

Use this first.

```text
Create the ThreatPrism V2 Spec Pack only. Do not implement application code yet.

Use the existing ThreatPrism V1 repo for context, but do not modify existing source code except to add documentation/spec files.

Create the following:

docs/specs/
  00_VISION.md
  01_PRODUCT_REQUIREMENTS.md
  02_ARCHITECTURE.md
  03_SOC_WORKFLOWS.md
  04_API_CONTRACT.md
  05_DATA_MODEL.md
  06_SOAR_INTEGRATION.md
  07_MICROSOFT_INTEGRATION.md
  08_AI_GUARDRAILS.md
  09_ACTION_SAFETY_MODEL.md
  10_GRC_HITRUST_ALIGNMENT.md
  11_EVALUATION_PLAN.md
  12_IMPLEMENTATION_ROADMAP.md
  13_ACCEPTANCE_CRITERIA.md
  14_DEMO_PLAN.md

Also create or update:
  AGENTS.md
  DECISIONS.md
  LIMITATIONS.md
  docs/ARCHITECTURAL_NORTH_STAR.md

ThreatPrism V2 must be specified as a production-style, demo-safe SOC migration accelerator for organizations moving from outsourced MSSP-managed SOC operations to an internal SOC model.

Use the locked decisions in this handoff brief as the source of truth.

The specs should be implementation-ready, not vague. Include concrete examples of API payloads, case model fields, triage report schema, analyst feedback fields, and acceptance criteria.

Do not mention any real employer or organization name.
```

---

## Codex Task 2 Prompt: Spec Review

Use this after Task 1.

```text
Now review the ThreatPrism V2 Spec Pack for consistency, missing requirements, architectural gaps, security risks, and implementation ambiguity.

Do not implement code yet.

Update the specs only where needed.

Create a summary of:
- What was improved
- Any remaining open decisions
- Any risks or blockers
- Recommended first implementation slice
```

---

## Codex Task 3 Prompt: First Build Slice

Use this after specs are reviewed.

```text
Implement the first ThreatPrism V2 vertical slice only.

Scope:
- Core case model
- FastAPI skeleton
- SQLite demo persistence
- Generic SOAR webhook ingestion
- Async/background triage job pattern
- Structured triage report schema
- Analyst feedback/disagreement model
- Demo payloads
- Basic tests

Do not implement real remediation actions.
Do not implement full threat intelligence integrations yet.
Do not implement a frontend dashboard yet.
Stub future integrations clearly.

Use the existing specs as the source of truth.
Update DECISIONS.md and LIMITATIONS.md as needed.
Run tests and summarize results.
```

---

## Acceptance Criteria

By the end of the first serious V2 foundation, the project should have:

1. Original V1 preserved elsewhere.
2. V2 work only in the new project.
3. Clear V2 spec pack.
4. CLI still usable or clearly migrated.
5. FastAPI service with core routes.
6. Async or background triage pattern.
7. Demo SOAR payload ingestion.
8. Provider-agnostic data normalization.
9. Microsoft-friendly integration structure.
10. Threat intel enrichment interfaces/stubs.
11. WHOIS/RDAP, VirusTotal, URLScan.io, and AbuseIPDB provider interfaces.
12. MITRE mapping support.
13. Case model.
14. Analyst feedback/disagreement tracking.
15. HITRUST-aligned GRC mapping.
16. Guardrails and eval harness.
17. Dry-run-only action adapter scaffolding.
18. Docker Compose.
19. `.env.example`.
20. CI/CD workflow.
21. Updated documentation.
22. Clear limitations and next steps.

---

## Final Codex Response Requirements

At the end of each Codex task, summarize:

- What was changed
- What files were added/modified
- What tests were run
- What passed/failed
- Any blockers
- Any assumptions
- How to run the project locally
- How to demo the SOAR ingestion workflow, if applicable
- Recommended next tasks
