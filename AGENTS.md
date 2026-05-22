# AGENTS.md

## Project Source Of Truth

For ThreatPrism V2 work, read these first:

1. `threatprism_v2_codex_handoff_brief.md`
2. `docs/specs/`
3. `DECISIONS.md`
4. `LIMITATIONS.md`

The handoff brief overrides assumptions from the old V1 README when they conflict.

## Product Identity

Use the product name `ThreatPrism`.

Repository target: `mwill20/ThreatPrism_V2`

Use only `ThreatPrism` as the product name in user-facing docs.

## Privacy Rule

Do not mention any real employer, healthcare organization, or specific user workplace in:

- Code.
- Documentation.
- Examples.
- Comments.
- Commit messages.
- README.
- Demo data.

Frame the project generically as a tool for organizations migrating from outsourced MSSP-managed SOC operations to an internal SOC model.

## Current Task Boundary

The original task boundary was spec pack only, but implementation has now begun.
Do not assume the old docs-only baseline is current.

Current baseline:

- The first backend slice exists under `src/threatprism/`.
- Healthcare safeguard guardrails and role-based rendering helpers exist under
  `src/threatprism/guardrails/`.
- Fake SOAR demo payloads exist under `examples/soar_payloads/`.
- API and guardrail tests exist under `tests/`.
- The known local validation command is:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_verify
```

Before changing code, verify the live repo state directly.

Allowed without a new implementation prompt:

- Documentation files.
- Spec files.
- Decision records.
- Limitations.
- Future-agent guidance.
- Safe local validation.

Only implement additional application scope when the user explicitly asks for
implementation work.

Still not allowed unless explicitly requested:

- Real remediation or containment.
- Live LLM, cloud, SOAR, or enrichment calls.
- Demo data using real organizations, workplaces, users, hosts, domains, IPs,
  tenant IDs, or secrets.
- Full-copying V1 into this repository.

## V1 Context To Preserve

ThreatPrism V1 is a CLI-first Python security analysis pipeline. Useful concepts to preserve in V2:

- CLI remains usable.
- Source ingestion and normalization.
- V1-style provenance fields: `source_file`, `record_index`, and optional `event_id`.
- Deterministic report rendering.
- SQLite demo persistence.
- Structured output validation using a Pydantic-style schema layer.
- Prompt-injection firewall and output policy checks.
- Dry-run validation without live LLM calls.
- Run-level observability artifacts under `runs/<run_id>/`.

V2 changes the product direction to SOC migration acceleration, SOAR integration, FastAPI service, dashboard-ready backend routes, analyst feedback, Microsoft-friendly adapters, and HITRUST-aligned GRC mapping.

## Recommended Future Agent Roles

### Architect Agent

Reviews architecture alignment, API boundaries, persistence strategy, async job flow, and V1 compatibility.

### Security Reviewer Agent

Reviews prompt-injection handling, output policy scanning, action safety, secret handling, and audit logging.

### SOC Workflow Reviewer Agent

Reviews case lifecycle, analyst feedback, disagreement tracking, and management metrics.

### GRC Reviewer Agent

Reviews HITRUST-aligned language, control category mapping, evidence traceability, and compliance-claim avoidance.

### Healthcare Safeguard Reviewer Agent

Reviews context-aware potential PHI/ePHI detection, typed tokenization,
role-based display policy, compliance-language scanning, and healthcare
safeguard framing.

This reviewer must enforce the distinction that identifiers are not PHI/ePHI by
themselves. Identifiers become PHI/ePHI risk when tied to health, patient, care,
billing, encounter, or other reasonably identifying context.

### Test And Eval Agent

Reviews pytest scope, guardrail evals, schema validation tests, and action blocking tests.

### Documentation Agent

Reviews consistency across README, specs, runbooks, limitations, architecture, and demo guide.

### Operational Metrics Reviewer Agent

Reviews dashboard-ready metrics, case-list filters, manager-review queues,
healthcare-review queues, detail read routes, and safe aggregate reporting.

This reviewer must verify that metrics and read models do not expose raw
potential PHI/ePHI, secrets, credentials, or token vault mappings.

### Access Control Reviewer Agent

Reviews demo authentication, identity-to-role mapping, authorization policy,
role escalation denial, and authorization audit events.

This reviewer must enforce that role-based views are not security controls
until identity and authorization enforce the effective role.

## Development Rules For Later Phases

- Keep application behavior evidence-first and analyst-controlled.
- Treat source case text and logs as untrusted.
- Treat LLM output as untrusted until schema and policy validation pass.
- Treat inbound SOAR payloads as potentially contaminated, even though they are
  expected to contain security-only telemetry.
- Do not classify every identifier as PHI/ePHI by itself.
- Use healthcare safeguard and evidence-alignment language, not
  compliance-certification language.
- Do not treat `?role=` as authorization. It is only a view request unless a
  trusted identity-to-role policy has authorized the effective role.
- Do not add real remediation or containment in V2.
- Keep `ALLOW_REAL_ACTIONS=false` by default.
- Use fake demo data only.
- Missing external API keys should return structured `not_configured` results.
- Prefer provider-agnostic interfaces for SOAR, LLMs, and enrichment.
- Keep Microsoft integrations first-class but not hardwired into the core model.
- Avoid strict CI gates that would fail inherited V1 code before the codebase is ready.

## Validation Guidance For Later Phases

Use safe local validation first:

```powershell
python -m pytest
python -m compileall .
```

Do not run live LLM, cloud, SOAR, or enrichment calls unless the user explicitly requests them and credentials are intentionally configured.
