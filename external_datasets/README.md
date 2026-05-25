# External Datasets

This folder is a local-only staging area for tiny, manually reviewed source
samples used by the synthetic fixture factory.

Rules:

- Do not commit raw third-party datasets.
- Do not auto-download datasets.
- Do not place real organization, workplace, tenant, user, host, domain, IP,
  credential, secret, or healthcare data here.
- Review license terms, redistribution rules, attribution requirements, and
  safety constraints before using any source sample.
- Use only tiny reviewed source-shape samples for local conversion.

The fixture factory converts explicit local inputs from this folder into
sanitized ThreatPrism-native JSONL fixtures under `fixtures/generated/`.
