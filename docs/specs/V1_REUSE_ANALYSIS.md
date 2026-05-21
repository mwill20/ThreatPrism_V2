# V1 Reuse Analysis

## Scope

This analysis reviews `mwill20/threatprism` as read-only context for deciding whether ThreatPrism should be built by full copy/fork or clean build.

Destination repo: `mwill20/ThreatPrism_V2`

Canonical local path: `C:\Projects\ThreatPrismV2`

## V1 Summary

V1 is a CLI-first Python SOC analysis pipeline.

Current V1 shape:

- CLI entrypoint in `src/main.py`.
- File-based ingestion for Windows JSONL, AWS CloudTrail JSON/JSONL, and GCP Audit Logs.
- Common event envelope with `source_file`, `record_index`, `event_id`, and `raw_event`.
- Prompt-injection sanitization and output policy validation in `src/security.py`.
- Pydantic structured output contract in `src/schemas.py`.
- LLM batching and provider calls in `src/llm_analyze.py`.
- Deterministic report rendering in `src/report.py`.
- SQLite run persistence in `src/storage.py`.
- Run artifacts under `runs/<run_id>/` via `src/ops/`.
- Tests for full CLI flow, prompt firewall behavior, source detection, AWS/GCP logic, and semantic evidence validation.

## Strong Reuse Candidates

### Security Guardrails

`src/security.py` is directly valuable.

Reusable concepts:

- `prompt_firewall_event()`
- `validate_output()`
- `validate_semantic_output()`
- prompt-injection rule structure
- prohibited output pattern scanning

V2 should extend this into the guardrail pipeline rather than rewrite it from scratch. The extension should add sensitive-value tokenization before LLM calls and controlled rehydration only after schema, policy, evidence-grounding, and action-safety checks pass.

### Provenance Envelope

V1 consistently uses:

- `source_file`
- `record_index`
- `event_id`
- `raw_event`

This maps well to the V2 evidence and source payload traceability model.

V2 should treat provenance as non-negotiable. Sanitization and tokenization must preserve enough provenance to prove which source event supported each claim.

### Pydantic Schema Discipline

`src/schemas.py` is small but useful because it already encodes:

- evidence-required findings
- confidence bounds
- severity enums
- structured LLM output expectations

V2 needs a richer case/report schema, but this validates the right pattern.

Pydantic models should be the first implementation checkpoint for the V2 case model, triage report, analyst feedback, disagreement record, GRC mapping, tokenization records, and enrichment outputs.

### Deterministic Reporting

`src/report.py` keeps narrative reporting in Python rather than letting the model write free-form reports. V2 should preserve that design.

### Ops Artifacts

`src/ops/` provides a practical run artifact pattern:

- `run_log.jsonl`
- `metrics.json`
- `what_broke.md`

V2 should adapt this to case and triage job artifacts.

### Deterministic Cloud Enrichment

AWS/GCP modules include useful deterministic logic:

- AWS plane tagging.
- AWS proximity clustering.
- AWS batching.
- GCP plane tagging.
- GCP actor and automation classification.

These are useful as optional source adapters or enrichment helpers, not as the center of the V2 architecture.

## Poor Full-Copy Candidates

### `src/main.py`

V1 `main.py` is a large linear CLI orchestration file. It mixes source detection, ingestion, sanitation, provider invocation, validation, report writing, persistence, and ops lifecycle.

V2 needs API-first boundaries, async triage jobs, case persistence, analyst feedback, and provider-agnostic adapters. Copying `main.py` as the foundation would slow that down.

### `src/storage.py`

V1 persistence is run-centric SQLite:

- `analysis_runs`
- `findings`
- `hypotheses`
- `indicators_of_compromise`
- `reports`

V2 needs case-centric persistence with triage jobs, analyst feedback, disagreement records, evidence, enrichment results, simulated actions, and audit events. The SQLite helper can inform early demo storage, but the schema should be redesigned.

### `src/llm_analyze.py`

V1 provider logic is useful as a reference, but it is too tightly tied to source-specific prompts, batching, direct provider SDK calls, and V1 `AnalysisOutput`.

V2 should define a provider interface first, then port only the useful retry, batching, structured JSON, and cost/metrics ideas.

### V1 Docs And Historical Lessons

V1 contains useful architecture and runbook notes, but also historical material and an older V2 spec that conflicts with the current handoff.

Do not bulk-copy V1 docs into V2.

### Dockerfile

The V1 Dockerfile runs a GCP job wrapper. V2 needs an API service and possibly worker service through Docker Compose, so the V1 Dockerfile should not be reused directly.

## Copy/Fork Versus Clean Build

### Full Copy/Fork

Pros:

- Preserves all working V1 code, data, tests, and history.
- Fastest path if V2 were a direct CLI evolution.
- Reduces chance of losing guardrail and provenance behavior.

Cons:

- Brings a lot of architecture that conflicts with V2.
- V1 is run-centric; V2 is case-centric.
- V1 is CLI-first; V2 needs API plus async job flow.
- V1 defaults and old V2 notes conflict with the current handoff.
- Historic docs, lessons, data, and scripts would create cleanup drag.

Assessment: not recommended as the primary V2 foundation.

### Pure Clean Build

Pros:

- Clean architecture from the start.
- No inherited docs or stale assumptions.
- Easier API-first module boundaries.
- Easier case-centric data model.

Cons:

- Higher risk of reimplementing proven guardrails poorly.
- Loses working dry-run, provenance, reporting, and ops patterns.
- Slower to reach parity with V1 safety behavior.

Assessment: not recommended if it means ignoring V1 internals.

### Recommended Hybrid

Build a clean V2 architecture and selectively port V1 modules.

Recommended approach:

1. Start `mwill20/ThreatPrism_V2` with the V2 spec pack, modern package layout, FastAPI skeleton, and case-centric models.
2. Port or adapt V1 guardrails, provenance, deterministic reporting, ops artifacts, and selected tests.
3. Do not copy V1 `main.py`, `storage.py`, old docs, data folders, or Dockerfile wholesale.
4. Keep V1 Windows/AWS/GCP ingestion as compatibility adapters, not the first vertical slice.
5. Build the first V2 slice around generic SOAR webhook ingestion.

## Recommendation

Use a clean build with selective V1 module porting.

This is better than a full fork because V2 has a different architecture and product model, but better than a pure clean build because V1 contains working security and evidence-handling patterns worth preserving.
