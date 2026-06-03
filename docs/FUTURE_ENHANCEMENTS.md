# Future Enhancements

This file captures optional future directions that are not part of the current
ThreatPrism build. Entries here are not commitments to implement.

Every item in this file requires explicit approval before implementation. Any
item that adds a provider, network call, corpus, identity boundary, non-demo
data path, or production deployment must also update the relevant specs,
threat models, treatment register, limitations, checklist, tests, and
validation notes.

## Harder / Human-Labeled Adversarial Cases

Status: deferred option (lower priority).

The current adversarial set (`fixtures/curated_adversarial/`) is engineered
rule-ambiguity. Live, two real models diverge only modestly — true-blind agreement
~0.875 with a single reproducible determination split (`adv-0004`). Pushing divergence
higher would need either human-labeled ground-truth cases or a finer-grained confidence
prompt.

Why this is not needed now:

- The methodology is sound (blind mode is genuinely blind; no schema-failure loss) and
  the core finding is established: modest real divergence, and anchoring is material.
- It requires authoring effort plus another paid live run for diminishing marginal
  insight.

Minimum gates: synthetic-only fixtures (RFC 5737 IPs, `.test` domains), manifest review,
demo-safety clean, and an explicit cost estimate + approval before any paid live run.

## Case-Payload-Blob Integrity (OT-1 remainder)

Status: deferred option.

Every persisted `AuditEvent` is already mirrored to an append-only, hash-chained log
(`HashChainedLog`, tamper-evident, `verify()`-able). The non-audit case *payload* blob
itself is still a rewritable SQLite value. A future slice could hash-protect the full
case record (e.g., a per-case content hash carried in the audit chain) so payload
tampering is also detectable. More invasive — it touches every case write — for marginal
benefit over the audit-event coverage already shipped.

## Audit-Log Retention And Rotation (OT-8 remainder)

Status: deferred option.

The integrity logs (failure log + audit-trail mirror) are append-only and verifiable,
and `python -m threatprism.persistence.verify_logs --export` provides a redaction-safe
integrity export. Not yet implemented: automated retention/rotation. Rotating an
append-only hash chain requires **segment sealing** (carry the last record hash forward
into the next segment, or sign each sealed segment) so verifiability survives rotation —
plus a documented retention window. Low urgency for a demo/POC.

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

Status: v0.2 complete for four tiny fake fixtures; additional promotion remains
a gated option.

Generated fixtures remain ignored by default. Any additional generated fixture
may be promoted only after manual review for license terms, redistribution
rights, safety, content quality, and absence of real PHI, PII, secrets, tenant
data, workplace data, or provider output.

## Production Dashboard Deployment

Status: gated option.

The current dashboard is local and fake-data-only. Production dashboard
deployment, live IdP/JWKS integration, external telemetry, browser matrix
certification, and accessibility certification require explicit approval and a
separate implementation slice.

## Live JWKS And IdP Integration

Status: local verifier implemented; live integration gated.

`docs/PRODUCTION_TOKEN_VERIFIER_IMPLEMENTATION.md` implements the
`external_oidc` verifier with fake local JWKS configuration and no-network
validation. A future live integration slice would need to add controlled JWKS
fetch or IdP discovery without weakening the current fail-closed behavior.

Live JWKS fetch, Entra calls, real issuer URLs, real tenant IDs, real group
IDs, production dashboard deployment, and non-demo data remain out of scope
until separately approved.
