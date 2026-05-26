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

## Out Of Scope

- Auto-downloading datasets.
- Committing raw third-party datasets.
- Using public dataset schemas directly in runtime flows.
- Real healthcare records.
- Real workplace or customer telemetry.
- Model training or fine-tuning.
- Caldera execution or adversary emulation labs.
