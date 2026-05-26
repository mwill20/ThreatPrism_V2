# Data Strategy And Synthetic Fixture Factory

## Purpose

ThreatPrism needs more realistic data without introducing real regulated data,
real workplace telemetry, real customer data, unsafe prompt content, or raw
third-party dataset drift.

The implemented strategy is layered:

1. Keep hand-written fake fixtures for deterministic unit and regression tests.
2. Add ThreatPrism-native synthetic fixtures for realistic SOC workflows.
3. Use public or synthetic datasets only as reviewed source material.
4. Convert small source samples through adapters, sanitizers, and fixture
   validation before they can influence tests or demos.

Public datasets must not become the ThreatPrism runtime data model.

## Architecture Rule

```text
Public or synthetic source sample
  -> Manual license and safety review
  -> Local raw file under external_datasets/ ignored by git
  -> Dataset adapter
  -> Sanitizer and validator
  -> ThreatPrism-native synthetic fixture
  -> Generated JSONL under fixtures/generated/ ignored by git
  -> Small curated fixture under fixtures/curated/ promoted only after review
```

Raw third-party datasets should not be committed. Full datasets should not be
auto-downloaded by default.

## Candidate Source Registry

All links below are candidates, not approvals. Before use, the user must review
current license terms, redistribution rules, attribution requirements, safety
constraints, and whether derivative fixtures may be committed.

| Source | Link | Intended Use | First-Slice Status |
| --- | --- | --- | --- |
| Synthea sample data | https://github.com/synthetichealth/synthea-sample-data | Small synthetic healthcare-context samples for accidental exposure tests. | Preferred first healthcare source. |
| Synthea generator | https://github.com/synthetichealth/synthea | Generate synthetic patient/encounter-style context locally. | Later, after sample-data path works. |
| Synthea downloads | https://synthea.mitre.org/downloads | Larger synthetic FHIR, C-CDA, and CSV archives. | Hold for later; can be large. |
| Synthea coherent data | https://registry.opendata.aws/synthea-coherent-data/ | Rich synthetic healthcare corpus. | Hold for later; high complexity. |
| OTRF Security Datasets | https://github.com/OTRF/Security-Datasets | SOC telemetry, ATT&CK-linked event realism, evidence timelines. | Preferred first SOC telemetry source. |
| Security Datasets docs | https://securitydatasets.com | Browse OTRF-style datasets. | Reference only. |
| Mordor legacy datasets | https://github.com/UraSecTeam/mordor | Adversary-simulation event samples. | Later, selective samples only. |
| Lakera PINT | https://github.com/lakeraai/pint-benchmark | Prompt-injection evaluation fixtures. | Preferred first prompt-injection source. |
| Giskard prompt injections | https://github.com/Giskard-AI/prompt-injections | Prompt-injection CSV sample conversion. | Preferred first prompt-injection source. |
| Mindgard evasion samples | https://huggingface.co/datasets/Mindgard/evaded-prompt-injection-and-jailbreak-samples | Evasion-style prompt-injection research fixtures. | Review-required, later only. |
| TrustAIRLab JailbreakLLMs | https://github.com/TrustAIRLab/JailbreakLLMs | Jailbreak prompt research fixtures. | Review-required, later only. |
| Apache Caldera | https://github.com/apache/caldera | Controlled lab telemetry generation. | Do not integrate in v0.1. |

## Manual User Responsibilities

Codex may build adapters and validation, but the user must make the approval
decisions for dataset use.

Required manual steps:

1. Open the candidate dataset page.
2. Review the current license and terms.
3. Decide whether local use, derivative fixtures, and committed samples are
   allowed.
4. Download or clone only a small source sample.
5. Place it under `external_datasets/`.
6. Run the fixture factory with an explicit source, input path, output path,
   and limit.
7. Inspect generated fixtures before promoting any sample into tracked tests.

Manual review must confirm:

- no real organization or workplace data
- no real users, hosts, domains, IPs, tenant IDs, or secrets
- no raw potential PHI/ePHI
- no token vault mappings
- no raw harmful prompt text in public-facing docs or logs
- expected guardrail outcomes make sense

## Implemented Directory Structure

```text
data_sources/
  registry.json

external_datasets/
  README.md
  .gitkeep

fixtures/
  generated/
    .gitkeep
  curated/
    README.md
    manifest.json
    curated_soc_case_0001.jsonl

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
    promotions.py
```

`external_datasets/**` and `fixtures/generated/**` should be ignored by git
except for `.gitkeep` or README files.

## Implemented Fixture Shape

Each generated fixture should be ThreatPrism-native and self-describing:

```json
{
  "fixture_id": "synthea_healthcare_0001",
  "source_family": "synthea",
  "scenario_type": "healthcare_exposure",
  "source_reference": "synthea_sample_data",
  "synthetic_only": true,
  "raw_source_retained": false,
  "payload": {},
  "expected_result": {},
  "expected_guardrails": [],
  "expected_role_visibility": {},
  "expected_evidence_ids": [],
  "notes": "Sanitized ThreatPrism-native fixture generated from reviewed source material."
}
```

## Implemented Adapter Behavior

`synthea_adapter.py`:

- Convert small Synthea CSV/FHIR samples into healthcare exposure fixtures.
- Use synthetic patient context only.
- Create accidental contamination scenarios such as patient-like identifier in
  a file path, portal alert context, or encounter-like reference.

`otrf_adapter.py`:

- Convert small OTRF or Mordor-style event samples into SOC case fixtures.
- Preserve ATT&CK technique references when available.
- Replace real-looking infrastructure with reserved safe examples.

`pint_adapter.py`:

- Convert PINT rows into prompt-injection eval fixtures.
- Avoid logging raw unsafe prompt content.
- Store sanitized previews only in summaries.

`giskard_adapter.py`:

- Convert prompt-injection CSV rows into eval fixtures.
- Preserve category metadata when useful.
- Store sanitized previews only in summaries.

## Implemented CLI

Example command:

```powershell
python -m tools.fixture_factory.factory --source synthea --input external_datasets/synthea_sample --output fixtures/generated/synthea_healthcare.jsonl --limit 10
```

CLI behavior:

- require explicit input path
- require explicit output path under an approved generated-fixture directory
- reject path traversal and absolute output escapes
- require `--limit`
- refuse to overwrite unless `--force` is passed
- print sanitized summaries only
- never auto-download by default

## Implemented Validation

Tests prove:

- dataset registry loads
- adapters do not auto-download by default
- fixture output conforms to Pydantic models
- generated fixtures have `synthetic_only=true`
- generated fixtures have `raw_source_retained=false`
- sanitizer removes or rejects potential PHI/ePHI, secrets, credentials, raw
  payload bodies, and token vault mappings
- path traversal is rejected for input and output paths
- output outside approved directories is rejected
- `--limit` bounds output volume
- console summaries do not leak raw sensitive values

## Completion Notes

Data Strategy & Synthetic Fixture Factory v0.1 is implemented with:

- `data_sources/registry.json`.
- `tools/fixture_factory/` models, sanitizers, validators, adapters, and CLI.
- Local-only adapters for Synthea-style, OTRF-style, PINT-style, and
  Giskard-style source-shape samples.
- Path controls that require inputs under `external_datasets/` and outputs
  under `fixtures/generated/`.
- Deterministic JSONL output with sorted fixture IDs and sorted JSON keys.
- Tests in `tests/test_fixture_factory.py`.

Curated Generated-Fixture Promotion v0.1 adds one tracked, hand-reviewed fake
fixture under `fixtures/curated/` plus manifest validation and tests in
`tests/test_curated_fixture_promotion.py`. This does not change the rule that
`fixtures/generated/` remains ignored and is not auto-scanned.

Validation on 2026-05-25:

```text
73 passed
eval harness dry-run: 15 passed / 0 failed
```

## Out Of Scope For v0.1

- automatic large dataset downloads
- committing raw public datasets
- Caldera execution
- live LLM evaluation
- model fine-tuning
- production SIEM/SOAR telemetry
- real healthcare data
- real workplace or customer data
- dashboard UI
- remediation or containment
