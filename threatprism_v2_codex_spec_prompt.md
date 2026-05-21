# ThreatPrism V2 Spec Pack — Codex Prompt

Copy and paste the prompt below into Codex.

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

ThreatPrism V2 must be specified as a production-style, demo-safe SOC migration accelerator for organizations moving from outsourced MSSP-managed SOC operations to an internal SOC model.

Use these locked decisions:
- Product name: ThreatPrism only
- New repo: mwill20/ThreatPrism_V2
- Local folder: C:\Projects\ThreatPrismV2
- Architecture: CLI + API service + dashboard-ready backend
- SOAR: provider-agnostic adapter interface
- Example adapters: generic webhook and Microsoft Sentinel/Logic Apps style payloads
- Microsoft integrations: Sentinel, Defender XDR, Graph Security API, generic webhook
- Tenancy: single-org internal SOC only
- Actions: recommend and simulate only; real actions blocked by default
- Hard-coded default: ALLOW_REAL_ACTIONS=false
- Real remediation/containment is out of scope for V2 and reserved for future V3
- Threat intel: VirusTotal, URLScan.io, AbuseIPDB, WHOIS/RDAP
- AI provider strategy: provider-agnostic, OpenAI default, local provider optional
- Guardrails: deterministic prompt firewall, schema validation, semantic prompt-injection classifier interface, output policy scanner
- HITRUST: HITRUST-aligned control category mapping only; do not claim compliance
- Demo data: fake/demo SOAR payloads required
- Analyst disagreement tracking required

The specs should be implementation-ready, not vague. Include concrete examples of API payloads, case model fields, triage report schema, analyst feedback fields, and acceptance criteria.

Do not mention any real employer or organization name.
```

## Recommended Follow-Up Prompt After Specs

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

## Recommended First Build Prompt After Spec Review

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
