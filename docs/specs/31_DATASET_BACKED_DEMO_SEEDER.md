# Spec 31 — Dataset-Backed Demo Seeder v0.1

Status: implemented.

## 1. Purpose

Populate a fresh ThreatPrism demo database with safe, deterministic cases by
replaying hand-reviewed curated fixtures through the real `POST /cases` intake
path. This closes the gap where the fixture factory *produces* sanitized
ThreatPrism-native fixtures but nothing *loads* them into a running demo.

The seeder is demo infrastructure. It does not introduce live providers, live
network calls, real data, or remediation.

## 2. Scope

In scope:

- A runtime-owned curated fixture loader.
- A `DemoSeeder` that replays fixtures through `create_case` + `run_triage`.
- An env-gated startup seed hook and a standalone CLI.
- A `FixtureSource` extension seam for a future dataset-ingest source.

Out of scope (deferred, gated):

- Dataset ingest itself (only the seam is defined; no adapter is built).
- Live LLM, SOAR, cloud, or enrichment calls.
- Auto-downloading or committing raw external datasets.
- Promoting additional fixtures (still requires per-fixture review).

## 3. Architecture decision — runtime-owned loader

The running app must not import dev-time tooling. `tools/fixture_factory/`
already imports `threatprism` (runtime); importing `tools` from runtime would
invert that dependency and is path-fragile (the `tools` package is only on
`sys.path` when launched from the repo root).

Decision: the seeder reads the committed fixture *data* under
`fixtures/curated/` directly (the same way `demo/scenarios.py` reads
`examples/*.json`). The path-sandbox and manifest-filtering logic is
reimplemented in `src/threatprism/demo/seeding.py` rather than reused from
`tools/fixture_factory/promotions.py`. The small duplication is acceptable
because the two paths serve different purposes: promotion-time safety gating vs.
demo-time replay. Both ultimately validate payloads against `CaseCreate`.

## 4. Components

- `SeedCase` — `fixture_id`, `source_case_id`, `payload` (validated `CaseCreate`).
- `FixtureSource` (Protocol) — `name` + `list_demo_fixtures() -> list[SeedCase]`.
- `CuratedFixtureSource` — loads demo-review-approved fixtures from the manifest.
- `DemoSeeder(service)` — `seed(sources, *, skip_existing=True, run_triage=True)`.
- `SeedResult` / `SeedOutcome` — structured, sanitized result (no payload bodies).
- `CuratedFixtureLoadError` — raised on manifest, path, or schema failure.

## 5. Data flow

```text
fixtures/curated/manifest.json
  -> filter: demo_review allowed_use + approved review status
  -> path sandbox (reject absolute/drive/traversal/non-.jsonl/escaping)
  -> read .jsonl line(s)
  -> validate payload as CaseCreate
  -> SeedCase
  -> DemoSeeder.seed()
       -> CaseService.create_case(payload)   # real intake + healthcare safeguards
       -> CaseService.run_triage(case_id)     # real four-layer guardrail pipeline
  -> SeedResult (seeded / skipped_existing)
```

## 6. Safety invariants

- Only manifest entries with `demo_review` in `allowed_uses` **and**
  `safety_review_status == approved_demo_safe` **and**
  `content_review_status == approved_for_tests` are seedable.
- Entries marked `raw_source_committed` or `auto_downloaded` are refused.
- The generated fixture folder is never auto-scanned.
- Path sandbox confines reads to `fixtures/curated/` and `.jsonl` files.
- Cases run the real guardrail pipeline; `ALLOW_REAL_ACTIONS=false` is unchanged.
- Output is sanitized: `SeedResult` carries ids and statuses only, never payload
  bodies, sensitive values, or token-vault mappings.
- Startup hook defaults off (`THREATPRISM_DEMO_SEED=false`) and is refused in
  `prod`/`production` by `Settings.validate_runtime()`.
- Idempotent: `--skip-existing` (default) skips fixtures whose `source_case_id`
  already exists.
- Deterministic: fixtures are sorted by `(fixture_id, source_case_id)`.

## 7. Known behavior — post-sanitization snapshots

Curated fixtures are snapshots taken **after** the fixture factory sanitized
their source material. The unsafe content (e.g., a prompt-injection instruction)
is stored only as a redacted marker. On replay, the prompt firewall therefore
has nothing left to quarantine, so those fixtures triage to `completed` rather
than `blocked_by_guardrail`. Fixtures that retain rehydratable Stage-2 telemetry
(IPs, URLs, hashes) still exercise live tokenization. This is expected and is
recorded in `LIMITATIONS.md`. Demonstrating a *live* quarantine/redaction
requires an unsanitized input, which is out of scope for curated-fixture replay.

## 8. Interfaces

- Startup: set `THREATPRISM_DEMO_SEED=true` (local/demo only).
- CLI: `python -m threatprism.demo.seed_cli [--source curated]
  [--skip-existing | --no-skip-existing]`.

## 9. Future extension

A dataset-ingest source implements `FixtureSource.list_demo_fixtures()` and
returns `SeedCase` objects whose payloads passed its own review gate. It plugs
into `DemoSeeder.seed([...])` with no seeder changes. Adding such a source
requires re-opening the relevant threat treatment before shipping.

## 10. Tests

`tests/test_demo_seeding.py` covers: curated listing + schema validation,
real-intake seeding, full-pipeline terminal status with live tokenization,
idempotency, safety-filter exclusion, path-sandbox rejection, startup-hook
on/off, and the production guard.
