# Spec 27: Curated Generated-Fixture Promotion

## Status

Implemented as Curated Generated-Fixture Promotion v0.1 and Broader Curated
Fixture Expansion v0.2.

## Goal

Promote tiny, manually reviewed, fake-data-only generated fixtures into a
tracked repository location without weakening the fixture-factory boundary.

This gives tests and demo reviewers stable promoted fixtures while keeping
ignored generated outputs out of automatic test discovery.

## In Scope

- Add a tracked curated fixture folder.
- Add a curated fixture manifest with review status.
- Add tiny ThreatPrism-native JSONL fixtures covering SOC, healthcare-context
  exposure, sanitized prompt-injection, and evidence-conflict/GRC review.
- Add a promotion loader that validates the manifest and fixture paths.
- Add tests proving curated fixtures are explicit, schema-valid, sanitized,
  reviewed, and not sourced from `fixtures/generated/`.
- Update docs, checklist, handoff, limitations, README, lesson index, and
  validation notes.

## Out Of Scope

- Raw third-party dataset commits.
- Automatic dataset downloads.
- Generated-folder auto-scanning.
- Live LLM, SOAR, cloud, enrichment, RAG, or external research provider calls.
- CSI/RGOI memory write-back, trust mutation, or source-of-truth changes.
- Real PHI, PII, secrets, tenant data, workplace data, or provider output.
- Broad fixture corpus promotion without per-fixture manual review.

## Promoted Fixture Policy

Every promoted fixture must have a manifest entry with:

- `fixture_id`
- `path`
- `source_family`
- `source_sample_status`
- `license_review_status`
- `safety_review_status`
- `content_review_status`
- `reviewed_by`
- `reviewed_at`
- `raw_source_committed=false`
- `auto_downloaded=false`
- allowed uses

For v0.1, accepted review statuses are intentionally narrow:

- `license_review_status=not_third_party_local_fake`
- `safety_review_status=approved_demo_safe`
- `content_review_status=approved_for_tests`

## Path Rules

Curated fixture paths must:

- be relative
- resolve under `fixtures/curated/`
- use `.jsonl`
- reject `fixtures/generated/`
- reject absolute paths
- reject path traversal
- reject null bytes

## Definition Of Done

- `fixtures/curated/README.md` exists.
- `fixtures/curated/manifest.json` exists.
- `fixtures/curated/curated_soc_case_0001.jsonl` exists.
- `fixtures/curated/curated_healthcare_exposure_0001.jsonl` exists.
- `fixtures/curated/curated_prompt_injection_0001.jsonl` exists.
- `fixtures/curated/curated_evidence_conflict_grc_0001.jsonl` exists.
- `tools/fixture_factory/promotions.py` validates curated fixture manifests
  and paths.
- `tests/test_curated_fixture_promotion.py` proves review metadata, path
  safety, schema validity, deterministic fixture serialization, duplicate-ID
  rejection, scenario coverage, and leakage prevention.
- Existing generated fixture folders remain ignored and are not auto-scanned.
- Standard validation passes with `ALLOW_REAL_ACTIONS=false`.
