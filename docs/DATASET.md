# Dataset And Fixture Data

ThreatPrism does not require a runtime dataset. Current tests, examples, evals,
and demo flows use fake data only.

## Current Data Sources

| Source | Committed | Purpose |
|---|---:|---|
| `examples/soar_payloads/*.json` | Yes | Fake SOAR payloads for local API demos. |
| `examples/demo_scenarios/*.json` | Yes | Fake role-specific scenario pack. |
| `tests/evals/*.jsonl` | Yes | Fake regression eval fixtures. |
| `data_sources/registry.json` | Yes | Review-required source registry for future fixture generation. |
| `external_datasets/` | No raw data | Ignored local staging for manually reviewed source-shape samples. |
| `fixtures/generated/` | No generated data | Ignored output directory for deterministic sanitized fixtures. |
| `fixtures/curated/` | Yes | Tiny tracked synthetic fixtures promoted through manifest review. |
| `fixtures/curated_datasets/` | Yes | Tracked derivatives of reviewed third-party synthetic datasets (Synthea, deepset), gated by an in-code license allowlist. |

## Source Registry Rules

Every candidate source in `data_sources/registry.json` defaults to:

- `license_review_required=true`
- `allowed_for_auto_download=false`
- `raw_data_committed=false`

These defaults prevent public or synthetic datasets from becoming runtime
dependencies or silently entering the repository.

## Manual Review Required

Before any external or generated fixture can be promoted into tracked tests or
evals, the user must review:

- license and redistribution terms
- attribution requirements
- safety constraints
- whether derivative fixtures may be committed
- whether source content contains real organization, workplace, user, host,
  domain, IP, tenant, credential, PHI, PII, or secret data

The curated promotion set is hand-authored fake source shapes only. Review
status is recorded in `fixtures/curated/manifest.json`, and generated fixture
auto-scanning remains disabled. The tracked set covers SOC, healthcare-context
exposure, sanitized prompt-injection, and evidence-conflict/GRC review
scenarios. Reviewed third-party synthetic datasets (see "Third-Party Dataset
License Reviews" below) are approved but onboard through a separate dataset
manifest, not the hand-authored curated contract.

## Third-Party Dataset License Reviews

Each reviewed third-party source records the outcome here because the registry
schema (`data_sources/registry.json`) is review-status-locked and cannot hold
review outcomes. Raw rows are never committed; only sanitized, column-projected
derivative fixtures are promoted.

### Synthea (`synthea_sample_data`) — reviewed 2026-05-29

- **Generator license:** Apache-2.0 (MITRE). The SyntheaTM generator and its
  sample data carry no cost, privacy, or security use restrictions.
- **Data nature:** Fully synthetic patient records. Synthea contains no real PHI
  by construction; the FAQ confirms generated data is "free from cost, privacy,
  and security restrictions."
- **Attribution:** Not required for the synthetic data; courtesy attribution to
  MITRE/SyntheaTM is recommended and recorded here.
- **Acquisition:** `patients.csv` was manually downloaded by the user into
  `external_datasets/synthea_sample_data/` (gitignored, not auto-downloaded, not
  committed).
- **Decision:** Approved for committed derivative fixtures. The Synthea adapter
  applies a fail-closed column allowlist (`SAFE_COLUMNS`) that drops all direct
  identifiers (names, address, city, county, ZIP, geo, birth/death dates,
  license/passport numbers) before sanitization, retaining only non-identifying
  demographic/financial fields plus the SSN, which the healthcare safeguard
  tokenizes. Promoted on 2026-05-29 into
  `fixtures/curated_datasets/synthea_healthcare.jsonl` (12 column-projected
  derivative fixtures) with a matching `manifest.json` entry carrying
  `license_review_status=approved_third_party_apache2_synthetic`.

### deepset/prompt-injections — reviewed 2026-05-29

- **License:** Apache-2.0 (Hugging Face dataset `deepset/prompt-injections`,
  662 rows, columns `text` + `label`).
- **Acquisition:** `train.parquet` / `test.parquet` manually fetched into
  `external_datasets/deepset_prompt_injections/` (gitignored, not committed).
  Read via `pyarrow==24.0.0` (dev-time only).
- **Decision:** Approved as the injection-fixture source in place of the
  originally-listed Lakera PINT and Giskard sources. Injection `text` is
  intentionally retained un-redacted on replay so the prompt firewall has live
  content to detect — a small, clearly-tagged exception approved for this source
  only (`apply_prompt_firewall=False` in `tools/fixture_factory/sanitizers.py`;
  credential, healthcare, and infrastructure sanitization still apply). Promoted
  on 2026-05-29 into `fixtures/curated_datasets/deepset_prompt_injection.jsonl`
  (12 fixtures) with a matching `manifest.json` entry carrying
  `license_review_status=approved_third_party_apache2_synthetic`, and a
  `deepset_prompt_injections` entry added to `data_sources/registry.json`.
- **Deterministic firewall coverage (honest baseline):** Of the labelled
  injection rows, only a small fraction match the six deterministic patterns.
  The promoted mix preserves that reality: **1 quarantine, 5 redact, 6 none**.
  The six `none` rows are real injections the deterministic firewall does **not**
  recognize — they reach the inert `DeterministicDemoProvider` and are tagged
  `residual_risk=RR-L1`. This is the system honestly demonstrating what the
  cheap deterministic layer cannot catch; the planned semantic layer
  (`docs/specs/32_SEMANTIC_PROMPT_INJECTION_LAYER.md`) is the next line of
  defense. No injection text leaks into triage reports or audit trails because
  the demo provider builds reports from evidence summaries/IDs, not excerpts —
  proven by `tests/test_deepset_injection_corpus.py`.

### Lakera PINT and Giskard — not acquirable

- **`lakera_pint`:** The PINT benchmark dataset is deliberately withheld by
  Lakera to prevent overfitting; only the benchmark code (MIT) is public. There
  is no downloadable dataset. Registry entry retained for provenance only.
- **`giskard_prompt_injections`:** Giskard is a scanning library that generates
  injection probes at scan time, not a downloadable dataset. Registry entry
  retained for provenance only.

## Out Of Scope

- Auto-downloading datasets.
- Committing raw third-party datasets.
- Using public dataset schemas directly in runtime flows.
- Real healthcare records.
- Real workplace or customer telemetry.
- Model training or fine-tuning.
- Caldera execution or adversary emulation labs.
