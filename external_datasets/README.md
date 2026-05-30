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

## Local demo seeding (off by default)

`LocalDatasetSource` can replay `.jsonl` payload files dropped anywhere under
this folder through the real demo intake path, without committing or promoting
them:

```bash
python -m threatprism.demo.seed_cli --source local --limit 5
```

Each line must be `{"payload": { ...CaseCreate... }}` (the same shape the
fixture factory emits). This source is local-only and intentionally OFF by
default — it is never the default source, never part of `--source all`, never
run by the startup seed hook, and refused in production environments. Nothing
here is committed (`external_datasets/**` is gitignored); the seeder only reads.
Replayed cases still pass the full four-layer guardrail pipeline at intake.
