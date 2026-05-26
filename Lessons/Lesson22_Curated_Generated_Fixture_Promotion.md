# Lesson 22: Curated Generated-Fixture Promotion

## Goal

Understand how ThreatPrism promotes a tiny synthetic fixture into tracked tests
without turning ignored generated output or public datasets into runtime
dependencies.

## Primary Files

- `fixtures/curated/manifest.json`
- `fixtures/curated/curated_soc_case_0001.jsonl`
- `tools/fixture_factory/promotions.py`
- `tests/test_curated_fixture_promotion.py`
- `docs/CURATED_GENERATED_FIXTURE_PROMOTION.md`

## Core Idea

The fixture factory can generate sanitized ThreatPrism-native fixtures under
`fixtures/generated/`, but that folder stays ignored. A fixture becomes tracked
only when a curated manifest records that the sample is fake, reviewed, safe,
and approved for tests.

The current promoted fixture is a hand-authored fake SOC source-shape
conversion. It is not copied from a third-party dataset and it does not contain
raw external source material.

## Safety Boundary

Curated promotion does not allow:

- raw dataset commits
- automatic downloads
- generated-folder auto-scanning
- live providers
- RAG or memory write-back
- real PHI, PII, secrets, tenant data, workplace data, or provider output

## What The Tests Prove

`tests/test_curated_fixture_promotion.py` checks that:

- the manifest disables generated-folder auto-scanning
- review statuses are approved
- raw source material is not committed
- fixture paths stay under `fixtures/curated/`
- `fixtures/generated/` paths are rejected
- the promoted fixture validates as a ThreatPrism synthetic fixture
- the payload validates as a ThreatPrism case
- sorted serialization remains deterministic
- forbidden raw fields, token vault metadata, live-looking secrets, and raw
  patient-style identifiers are absent

## Practical Rule

Treat `fixtures/generated/` as staging output, not test input. Treat
`fixtures/curated/manifest.json` as the promotion gate for tracked fixtures.
