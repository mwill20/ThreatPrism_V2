# Curated Fixtures

This folder contains tiny, tracked, manually reviewed synthetic fixtures that
were promoted from the fixture-factory workflow for deterministic tests and
demo review.

Current boundary:

- fake data only
- no raw external dataset rows
- no automatic downloads
- no generated-folder auto-scanning
- no real PHI, PII, secrets, tenants, users, hosts, domains, IPs, workplace
  data, provider output, or token vault mappings

Generated output under `fixtures/generated/` remains ignored. A fixture can be
promoted here only when `manifest.json` records license, safety, and content
review status.
