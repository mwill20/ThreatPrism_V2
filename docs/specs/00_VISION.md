# 00 Vision

## Product Name

Product name: ThreatPrism

Repository target: `mwill20/ThreatPrism_V2`

Target local folder from the handoff brief: `C:\Projects\ThreatPrismV2`

## Vision

ThreatPrism is a production-style, demo-safe SOC migration accelerator for organizations moving from outsourced MSSP-managed SOC operations toward an internal SOC model.

The system helps internal SOC teams review automated closures, compare analyst decisions against evidence-grounded AI-assisted triage, and produce auditable reports that management, engineering, and GRC stakeholders can use.

ThreatPrism is not a production deployment in this version. It must be designed so production adaptation is possible without a major architecture rewrite.

## Core Philosophy

ThreatPrism preserves these principles:

- Evidence-first SOC analysis.
- Analyst control over final determinations.
- Deterministic guardrails before and after AI use.
- Structured LLM output only.
- Schema validation before storing or displaying AI output.
- No autonomous remediation or containment.
- Human analyst review required.
- Auditability for every report, recommendation, and analyst override.
- Treat case text, alert text, logs, and artifacts as untrusted input.
- Treat LLM output as untrusted until validated.

## Target Users

- SOC analyst: reviews triage reports, validates evidence, approves or overrides recommendations, and records feedback.
- SOC manager: reviews disagreement trends, quality-control outcomes, analyst workload, and closure quality.
- Detection engineer: reviews missed IOCs, missed MITRE mappings, false positives, false negatives, and automation gaps.
- GRC or audit stakeholder: reviews evidence-to-control mapping and audit-ready report structure.
- Platform engineer: integrates ThreatPrism with SOAR, SIEM, API clients, and internal deployment tooling.

## Primary Use Case

ThreatPrism supports an organization transitioning from outsourced SOC operations to an internal SOC.

It helps answer:

- Are SOAR automations working as expected?
- Did automation miss anything?
- Did analysts miss anything?
- Where did ThreatPrism and the analyst disagree?
- Which cases consumed more analyst time?
- Are high-risk cases handled correctly?
- What findings map to security and GRC control categories?
- What evidence supports each triage decision?

## Evolution Stages

### Evolution 1: Batch Triage Over SOAR-Automated Cases

ThreatPrism reviews batches of cases already closed or automated away by SOAR.

Primary outcome: catch missed risk, validate automation quality, and create audit evidence for automated closure decisions.

### Evolution 2: Batch Review of Human Analyst Determinations

ThreatPrism reviews cases already handled by human analysts.

Primary outcome: identify disagreement patterns, possible analyst misses, process issues, detection gaps, and training opportunities.

### Evolution 3: Parallel Per-Event SOAR Triage

ThreatPrism runs in parallel with SOAR handling.

Primary outcome: SOAR submits a case, ThreatPrism immediately returns a tracking ID, triage runs asynchronously, and SOAR workflows continue even if ThreatPrism is slow or unavailable.

## Success Measures

- A demo operator can ingest fake SOAR payloads without live credentials.
- Each case produces a structured triage report with evidence citations.
- Analyst feedback can record determination, severity, confidence, disposition, and disagreement fields.
- Unsafe action execution is blocked by default.
- Missing enrichment API keys return explicit `not_configured` results instead of crashing.
- GRC mappings use HITRUST-aligned control categories without claiming compliance or certification.
- API contracts are dashboard-ready.
- Future implementation can build the first vertical slice without resolving basic architecture ambiguity.

## Non-Goals For This Version

- Full frontend dashboard.
- Multi-tenant MSSP platform.
- Live production remediation or containment.
- Claims of HITRUST compliance, certification, or licensed control implementation.
- Dependence on a single SOAR, SIEM, LLM, or enrichment provider.
- Storage of real customer or sensitive production data in demos.
