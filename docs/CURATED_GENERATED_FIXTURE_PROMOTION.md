# Curated Generated-Fixture Promotion

## Purpose

ThreatPrism now includes a tiny tracked curated fixture set that can be used by
tests and demo review without changing the generated-fixture boundary.

Generated fixture output under `fixtures/generated/` remains ignored and is not
auto-scanned by tests, evals, or demos. Promotion into tracked files requires a
manifest entry with license, safety, and content review status.

## Current Promotion

Tracked files:

- `fixtures/curated/README.md`
- `fixtures/curated/manifest.json`
- `fixtures/curated/curated_soc_case_0001.jsonl`

The promoted fixture is a hand-authored fake SOC source-shape conversion. It is
not a copied third-party dataset row and it does not contain raw external
dataset material.

Review status recorded in `fixtures/curated/manifest.json`:

- `license_review_status=not_third_party_local_fake`
- `safety_review_status=approved_demo_safe`
- `content_review_status=approved_for_tests`
- `raw_source_committed=false`
- `auto_downloaded=false`
- `generated_fixture_auto_scan=false`

## Controls

The curated promotion loader in `tools/fixture_factory/promotions.py` enforces:

- manifest version is explicit
- generated fixture auto-scan is disabled
- each fixture path resolves under `fixtures/curated/`
- `fixtures/generated/` paths are rejected
- absolute paths and traversal are rejected
- fixture files must be `.jsonl`
- license, safety, and content review statuses must be approved
- raw source material must not be committed
- auto-download provenance must be false
- each fixture is schema-valid and passes fixture-factory safety validation

## Boundaries

This slice does not add:

- raw external dataset commits
- automatic dataset downloads
- generated-folder auto-scanning
- live LLM calls
- live SOAR, cloud, enrichment, or external research provider calls
- RAG, memory write-back, trust mutation, or CSI/RGOI source-of-truth changes
- real PHI, PII, secrets, tenant data, workplace data, or provider output

## Validation

Focused test:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; python -m pytest -p no:cacheprovider tests\test_curated_fixture_promotion.py --basetemp .pytest_tmp_curated_fixture_focus
```

Full validation:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```
