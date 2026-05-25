# Lesson 16: Data Strategy And Synthetic Fixture Factory

## Goal

Understand how ThreatPrism improves demo and regression data realism without
crossing into raw third-party datasets, live providers, real PHI/PII, real
credentials, real workplace data, RAG, memory/write-back, dashboard UI, or
remediation.

## Primary Files

```text
data_sources/registry.json
external_datasets/README.md
fixtures/generated/.gitkeep
tools/fixture_factory/models.py
tools/fixture_factory/sanitizers.py
tools/fixture_factory/validators.py
tools/fixture_factory/adapters/*.py
tools/fixture_factory/factory.py
tests/test_fixture_factory.py
docs/DATA_STRATEGY_AND_FIXTURE_FACTORY.md
docs/specs/20_DATA_STRATEGY_AND_FIXTURE_FACTORY.md
```

## What The Slice Adds

Data Strategy & Synthetic Fixture Factory v0.1 adds:

- A machine-readable source registry where every source requires manual license
  review, disables auto-download, and forbids raw data commits.
- Ignored local staging under `external_datasets/`.
- Ignored generated output under `fixtures/generated/`.
- Pydantic fixture models for ThreatPrism-native synthetic fixtures.
- Fixture sanitizers that reuse healthcare safeguards and prompt-firewall
  behavior while replacing real-looking infrastructure with reserved examples.
- Path validators that require inputs under `external_datasets/` and outputs
  under `fixtures/generated/`.
- Local-only adapters for Synthea-style, OTRF-style, PINT-style, and
  Giskard-style source-shape samples.
- A CLI entry point for deterministic JSONL generation.
- Tests for registry safety, model constraints, sanitizer behavior, adapters,
  CLI behavior, path safety, determinism, no-network behavior, schema validity,
  and leakage prevention.

## Mental Model

```text
Reviewed tiny source-shape sample
  -> external_datasets/ local-only staging
  -> local adapter
  -> healthcare and prompt sanitization
  -> fixture safety validation
  -> deterministic ThreatPrism-native JSONL
  -> fixtures/generated/ ignored output
  -> manual review before any tracked promotion
```

The factory does not turn public datasets into runtime schemas. It produces
ThreatPrism-native fixture records that can be reviewed, curated, and promoted
only through a later explicit change.

## Registry Rules

Every entry in `data_sources/registry.json` defaults to:

```json
{
  "license_review_required": true,
  "allowed_for_auto_download": false,
  "raw_data_committed": false
}
```

That design makes the approval boundary visible. Codex can build conversion
tools, but it cannot silently approve a source, download a dataset, or commit
raw rows.

## CLI Example

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -m tools.fixture_factory.factory --source synthea_sample_data --input external_datasets/synthea_sample --output fixtures/generated/synthea_healthcare.jsonl --limit 10
```

The CLI requires:

- Explicit `--source`.
- Explicit `--input`.
- Explicit `--output`.
- Explicit `--limit`.
- Input path under `external_datasets/`.
- Output path under `fixtures/generated/`.
- `--force` before overwriting an existing output file.

## Guardrails To Remember

- Generated fixtures must be deterministic.
- Generated fixtures must set `synthetic_only=true`.
- Generated fixtures must set `raw_source_retained=false`.
- Generated fixtures must validate as ThreatPrism case payloads.
- Raw external data, token vault mappings, raw payload bodies, live-looking
  secrets, real-looking infrastructure, and healthcare-context identifiers must
  be removed, tokenized, or replaced before output.
- Adapter tests must prove no network socket is needed.
- Generated fixtures do not silently affect baseline tests or evals.

## Review Questions

- Does the source registry keep download and raw-data commit flags disabled?
- Does the adapter read only local files?
- Does the output path stay under `fixtures/generated/`?
- Is the output deterministic across repeated runs?
- Does the fixture validate against existing ThreatPrism schemas?
- Are raw sensitive values absent from generated JSONL and console summaries?
- Is fixture promotion still manual and reviewed?

## Quick Reference

- Registry: `data_sources/registry.json`.
- Local source staging: `external_datasets/`.
- Generated output: `fixtures/generated/`.
- CLI: `python -m tools.fixture_factory.factory`.
- Focused tests: `tests/test_fixture_factory.py`.
- Full validation:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```
