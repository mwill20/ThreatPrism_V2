# Future Enhancements

This file captures optional future directions that are not part of the current
ThreatPrism build. Entries here are not commitments to implement.

Every item in this file requires explicit approval before implementation. Any
item that adds a provider, network call, corpus, identity boundary, non-demo
data path, or production deployment must also update the relevant specs,
threat models, treatment register, limitations, checklist, tests, and
validation notes.

## Optional External Research Provider Adapter

Status: deferred option.

Candidate examples: Exa.ai or an equivalent public-web research/search
provider.

ThreatPrism does not need an external research provider for the current build.
The current CSI/RGOI foundation is read-only, fake-data-only, and governed by
internal evidence, provenance, trust, tenant namespace, role, purpose, and
retrieval-zone controls. It should not become unrestricted AI memory or an
automatic web-backed RAG system.

Potential future benefits:

- public vendor advisory and security research discovery
- CVE, product documentation, and policy-reference lookup for analyst review
- curated fixture research after manual license, safety, and content review
- creation of `external_unreviewed` cognitive candidates with source
  provenance for human review

Why this is not needed now:

- local demos and validation already run without live providers
- CSI/RGOI currently retrieves only governed fake cognitive objects
- adding web research would add cost, network dependency, poisoning risk,
  provenance complexity, license-review work, and operational review burden
- curated fixture promotion and local dashboard hardening do not require it

Minimum gates before any implementation:

- Update the threat model and treatment register for external retrieval,
  indirect prompt injection, content poisoning, provenance spoofing, cost
  control, and attribution risk.
- Keep the provider disabled by default.
- Keep `ALLOW_REAL_ACTIONS=false`.
- Do not require API keys for tests, validation, CI, local demos, or baseline
  evals.
- Use mocked provider responses and tiny hand-written fake samples in tests.
- Require explicit provider configuration for any live experiment.
- Record source URL, retrieval timestamp, provider name, query hash, content
  hash, license/review status, and reviewer decision.
- Treat provider output as `external_unreviewed` and non-authoritative until a
  human governance path approves it.
- Do not let provider output automatically mutate CSI/RGOI cognition, trust,
  lifecycle state, suppressions, eval baselines, or fixture promotion.

Explicitly out of scope until separately approved:

- live calls during standard validation
- automatic knowledge ingestion
- live RAG over public web results
- CSI/RGOI memory write-back
- autonomous trust mutation or source-of-truth changes
- training or fine-tuning dataset generation
- organization-private, workplace, tenant, patient, or credential queries

## Curated Generated-Fixture Promotion

Status: gated option.

Generated fixtures remain ignored by default. A tiny generated fixture may be
promoted only after manual review for license terms, redistribution rights,
safety, content quality, and absence of real PHI, PII, secrets, tenant data,
workplace data, or provider output.

## Production Dashboard Deployment

Status: gated option.

The current dashboard is local and fake-data-only. Production dashboard
deployment, production identity, external telemetry, browser matrix
certification, and accessibility certification require explicit approval and a
separate implementation slice.
