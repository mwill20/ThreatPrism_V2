# Curated Datasets (Third-Party Synthetic)

This directory holds **committed, sanitized derivative fixtures** promoted from
reviewed third-party *synthetic* datasets. It is a deliberately separate contract
from `fixtures/curated/`:

- `fixtures/curated/` — hand-authored fake source shapes only. Its dev-time
  validator (`tools/fixture_factory/promotions.py`) pins
  `license_review_status` to `not_third_party_local_fake` and therefore **cannot**
  accept third-party data.
- `fixtures/curated_datasets/` (this dir) — sanitized derivatives of reviewed
  third-party synthetic datasets (e.g., Synthea). Its trust gate accepts
  `license_review_status = approved_third_party_apache2_synthetic`.

## What may be committed here

Only sanitized, column-projected `.jsonl` derivatives whose source dataset has a
recorded license/safety review (see `docs/DATASET.md` →
"Third-Party Dataset License Reviews"). **Raw third-party rows are never
committed** — they stay in the gitignored `external_datasets/` staging area.

## Trust gate

The runtime loader `CuratedDatasetSource` (in
`src/threatprism/demo/seeding.py`) seeds an entry only when **all** hold:

- `allowed_uses` contains `demo_review`
- `safety_review_status == approved_demo_safe`
- `content_review_status == approved_for_tests`
- `raw_source_committed` is `false` and `auto_downloaded` is `false`
- `license_review_status` is in the runtime allowlist
  (`DATASET_ALLOWED_LICENSE_REVIEW`)

The accepted-license allowlist lives in **code**, not in this manifest, so a
manifest cannot self-certify a license it was not granted.

## Status

Promoted derivatives:

- `synthea_healthcare.jsonl` — 12 column-projected derivative fixtures from the
  reviewed Synthea sample (`synthea_sample_data`, Apache-2.0). Only the 8
  `SAFE_COLUMNS` survive the adapter's fail-closed projection; the SSN is
  Stage-1 tokenized (`[POTENTIAL_PII:SSN:...]`) and never rehydrated. See the
  `synthea_healthcare` entry in `manifest.json`.
- `deepset_prompt_injection.jsonl` — 12 prompt-injection fixtures from the
  reviewed `deepset/prompt-injections` corpus (Apache-2.0). **Source-scoped
  exception:** unlike every other promoted file, the attacker-controlled
  injection `text` is retained **un-redacted** (`apply_prompt_firewall=False` in
  `tools/fixture_factory/sanitizers.py`) so the runtime prompt firewall has live
  content to detect on replay; credential, healthcare, and infrastructure
  sanitization still apply. Deterministic-firewall bucket mix: 1 quarantine,
  5 redact, 6 unrecognized (RR-L1). The unrecognized rows are real injections
  the deterministic layer misses — they reach the inert demo provider but never
  leak into reports/audit (see `tests/test_deepset_injection_corpus.py`). The
  planned next defense is `docs/specs/32_SEMANTIC_PROMPT_INJECTION_LAYER.md`.

Each promoted file carries a manifest entry with full provenance. Raw third-party
rows remain in the gitignored `external_datasets/` staging area.
