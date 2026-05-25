# 20 Data Strategy And Synthetic Fixture Factory

## Status

Implemented in Data Strategy & Synthetic Fixture Factory v0.1.

This spec captures the dataset strategy and the implemented local-only fixture
factory. It does not authorize raw dataset ingestion, automatic downloads, or
live-provider work.

## Problem

Hand-written fake fixtures are safe and deterministic, but they eventually
become too shallow for realistic regression coverage.

ThreatPrism needs realistic-enough fixtures for:

- SOC case normalization
- healthcare-context contamination handling
- prompt-injection defense
- evidence-grounding failures
- role-based leakage checks
- manager/GRC and healthcare-review queues
- eval harness regression coverage

The risk is that importing public datasets directly can introduce licensing
problems, raw sensitive values, unsafe prompt text, real-looking
infrastructure, uncontrolled schemas, large files, and false confidence.

## Goal

Create a safe fixture factory that uses small, manually reviewed public or
synthetic source samples as source material, then converts them into
ThreatPrism-native synthetic fixtures.

## Non-Goals

- Do not auto-download datasets by default.
- Do not commit full raw third-party datasets.
- Do not ingest public dataset schemas directly into runtime flows.
- Do not add Caldera execution.
- Do not add live LLM, SOAR, cloud, enrichment, production IdP, dashboard, or
  remediation scope.
- Do not use real healthcare, workplace, tenant, user, host, domain, IP,
  secret, or PHI/ePHI data.

## Required Data Flow

```text
Candidate source
  -> Manual license and safety review
  -> User places small sample under external_datasets/
  -> Adapter parses source format
  -> Sanitizer removes or rejects unsafe values
  -> Validator enforces ThreatPrism fixture model
  -> JSONL fixture written under fixtures/generated/
  -> User manually promotes safe small samples into tracked tests if needed
```

## Candidate Sources

Preferred v0.1 candidates:

- Synthea sample data: https://github.com/synthetichealth/synthea-sample-data
- OTRF Security Datasets: https://github.com/OTRF/Security-Datasets
- Lakera PINT: https://github.com/lakeraai/pint-benchmark
- Giskard prompt injections: https://github.com/Giskard-AI/prompt-injections

Later candidates:

- Synthea generator: https://github.com/synthetichealth/synthea
- Synthea downloads: https://synthea.mitre.org/downloads
- Synthea coherent data: https://registry.opendata.aws/synthea-coherent-data/
- Security Datasets docs: https://securitydatasets.com
- Mordor legacy datasets: https://github.com/UraSecTeam/mordor
- Mindgard evasion samples:
  https://huggingface.co/datasets/Mindgard/evaded-prompt-injection-and-jailbreak-samples
- TrustAIRLab JailbreakLLMs: https://github.com/TrustAIRLab/JailbreakLLMs
- Apache Caldera: https://github.com/apache/caldera

Every source entry must default to `license_review_required=true`,
`allowed_for_auto_download=false`, and `raw_data_committed=false`.

## Registry

Add a machine-readable registry:

```text
data_sources/registry.json
```

Each entry must include:

- `source_id`
- `name`
- `url`
- `category`
- `intended_use`
- `license_review_required`
- `allowed_for_auto_download`
- `raw_data_committed`
- `notes`

## Directory Structure

```text
data_sources/
  registry.json

external_datasets/
  README.md
  .gitkeep

fixtures/
  generated/
    .gitkeep

tools/
  fixture_factory/
    __init__.py
    models.py
    factory.py
    sanitizers.py
    validators.py
    adapters/
      __init__.py
      synthea_adapter.py
      otrf_adapter.py
      pint_adapter.py
      giskard_adapter.py
```

`.gitignore` must ignore raw and generated data while allowing documentation
and `.gitkeep` placeholders:

```text
external_datasets/**
!external_datasets/README.md
!external_datasets/.gitkeep
fixtures/generated/**
!fixtures/generated/.gitkeep
downloaded_datasets/**
```

## Fixture Models

Implement Pydantic models for:

- `FixtureSourceMetadata`
- `ExpectedGuardrailOutcome`
- `ExpectedRoleVisibility`
- `ThreatPrismSyntheticFixture`
- `SyntheticSOARCaseFixture`
- `PromptInjectionEvalFixture`
- `HealthcareExposureFixture`
- `EvidenceGroundingFixture`

Required fields:

- `fixture_id`
- `source_family`
- `scenario_type`
- `source_reference`
- `synthetic_only`
- `raw_source_retained`
- `payload`
- `expected_result`
- `expected_guardrails`
- `expected_role_visibility`
- `expected_evidence_ids`
- `notes`

`synthetic_only` must be `true`. `raw_source_retained` must be `false`.

## Sanitizer Requirements

The sanitizer must reject or transform:

- potential PHI/ePHI
- secrets and credentials
- raw authorization headers
- raw payload bodies from external sources
- token vault mappings
- real-looking production domains unless replaced with reserved safe examples
- real-looking public IPs unless replaced with documentation ranges
- absolute path and path traversal attempts

Console output and generated summaries must use sanitized previews only.

## Adapter Requirements

Adapters must be local-only by default.

They may read small samples manually placed under `external_datasets/`. They
must not download data unless a future explicit implementation adds a separate
reviewed download command.

`synthea_adapter.py`:

- Convert small synthetic healthcare samples into healthcare exposure fixtures.
- Use accidental contamination scenarios only.
- Avoid framing ThreatPrism as a healthcare records processor.

`otrf_adapter.py`:

- Convert small SOC telemetry samples into SOAR case fixtures.
- Preserve ATT&CK references when present.
- Replace real-looking infrastructure with reserved safe examples.

`pint_adapter.py` and `giskard_adapter.py`:

- Convert prompt-injection rows into eval fixtures.
- Avoid writing raw unsafe prompt text to docs, logs, or summaries.
- Preserve only the fixture payload needed for local eval behavior.

## CLI Requirements

Implemented command shape:

```powershell
python -m tools.fixture_factory.factory --source synthea --input external_datasets/synthea_sample --output fixtures/generated/synthea_healthcare.jsonl --limit 10
```

The CLI must:

- require explicit `--source`
- require explicit `--input`
- require explicit `--output`
- require `--limit`
- reject input path traversal
- reject output path traversal
- require output to stay under `fixtures/generated/`
- refuse overwrite unless `--force` is passed
- print sanitized counts and summaries only

## Tests

Add tests proving:

- registry loads and every source has required metadata
- every source requires license review by default
- auto-download is disabled by default
- fixture models reject `synthetic_only=false`
- fixture models reject `raw_source_retained=true`
- sanitizer removes or rejects potential PHI/ePHI, secrets, credentials, raw
  payload bodies, token vault mappings, and real-looking infrastructure
- adapters can convert small local sample files into valid fixture models
- adapters do not perform network calls
- CLI `--limit` bounds output
- CLI refuses overwrite without `--force`
- path traversal is rejected for inputs and outputs
- generated previews do not leak raw sensitive values

## Acceptance Criteria

- [x] Data strategy docs exist and list candidate sources with review status.
- [x] Machine-readable registry exists.
- [x] Raw external dataset folders are ignored.
- [x] Generated fixture folders are ignored unless explicitly promoted.
- [x] Fixture factory scaffold exists.
- [x] Safe local-only adapters exist for Synthea, OTRF, PINT, and Giskard
  source-shape samples.
- [x] Sanitizer and validator functions fail closed.
- [x] CLI exists with explicit input/output/limit controls.
- [x] Tests cover safety, schema, adapters, path controls, determinism,
  no-network behavior, and non-leakage.
- [x] README, checklist, handoff, decisions, limitations, and lesson index are
  updated.
- [x] `tools/validate-threatprism.ps1` passes before completion.

Validation on 2026-05-25:

```text
73 passed
eval harness dry-run: 15 passed / 0 failed
```

## Future Expansion

v0.2 may add richer adapters and curated promoted fixtures after the v0.1
factory is validated.

v0.3 may add lab-generated telemetry from adversary emulation tools, but only
after explicit approval and only in an isolated lab workflow.
