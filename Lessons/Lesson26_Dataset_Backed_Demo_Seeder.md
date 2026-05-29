# Lesson 26 — Dataset-Backed Demo Seeder 🌱

## Goal, Time, Prerequisites

- **Goal:** Understand how ThreatPrism populates a demo database by replaying
  hand-reviewed curated fixtures through the real intake path.
- **Time:** ~25 minutes.
- **Prerequisites:** Lesson 02 (case service), Lesson 04 (guardrails), Lesson 16
  (fixture factory), Lesson 22 (curated fixture promotion).

## Why This Slice Exists

The fixture factory (Lesson 16) *produces* sanitized ThreatPrism-native fixtures,
and curated promotion (Lesson 22) hand-reviews a tiny set of them into
`fixtures/curated/`. But nothing *loaded* those fixtures into a running demo. A
reviewer who started the API saw an empty case list.

This slice closes that gap: a seeder replays curated fixtures through the same
`POST /cases` path a real SOAR webhook uses.

`★ Insight ─────────────────────────────────────`
- The seeder reuses the production intake path instead of inserting rows
  directly. That means seeded cases pass through the *same* four-layer guardrail
  pipeline — there is no "trust me" back door that skips sanitization.
- This mirrors a SOC principle you already know: a SOAR playbook that injects
  test cases should exercise the same enrichment and validation steps as a live
  alert, or the test proves nothing about the real path.
`─────────────────────────────────────────────────`

## Architecture Decision — Runtime Owns The Loader

The dev-time fixture factory under `tools/` already imports the runtime package
`threatprism`. If runtime imported `tools` back, you would get a two-way
dependency, and `tools` is only importable when launched from the repo root.

So the seeder reads the committed fixture *data* directly and never imports
`tools/`. The rule: **dev tooling may import the running app; the running app
must never import dev tooling.** See `DECISIONS.md` D-041.

## Code Walkthrough

### `src/threatprism/demo/seeding.py`

- `SeedCase` — `fixture_id`, `source_case_id`, `payload` (a validated
  `CaseCreate` dict).
- `FixtureSource` (Protocol) — the extension seam: `name` plus
  `list_demo_fixtures() -> list[SeedCase]`. A future dataset-ingest source
  implements this and plugs in with no seeder changes.
- `CuratedFixtureSource.list_demo_fixtures()` — reads
  `fixtures/curated/manifest.json`, keeps only entries that pass
  `_is_demo_seedable()`, sandboxes each path, parses the JSONL, validates each
  payload as `CaseCreate`, and returns them sorted for determinism.
- `_is_demo_seedable(entry)` — the safety gate: `demo_review` must be in
  `allowed_uses`, `safety_review_status` must be `approved_demo_safe`,
  `content_review_status` must be `approved_for_tests`, and neither
  `raw_source_committed` nor `auto_downloaded` may be set.
- `_resolve_curated_path(candidate)` — rejects absolute, drive, traversal,
  non-`.jsonl`, and escaping paths before any file read.
- `DemoSeeder.seed(sources, *, skip_existing=True, run_triage=True)` — for each
  `SeedCase`, calls `CaseService.create_case(payload)` then
  `CaseService.run_triage(case_id)`. Idempotency comes from a set of existing
  `source_case_id` values gathered from `service.list_cases()`.

### `src/threatprism/config.py`

- `demo_seed_enabled` field, parsed from `THREATPRISM_DEMO_SEED`, default
  `False`.
- `validate_runtime()` refuses demo seeding in `prod`/`production`.

### `src/threatprism/api/app.py`

- After the case service is built, if `demo_seed_enabled` is set, `DemoSeeder`
  runs with `CuratedFixtureSource()` and logs a sanitized count.

### `src/threatprism/demo/seed_cli.py`

- `python -m threatprism.demo.seed_cli` — builds settings from env, validates,
  seeds, and prints a sanitized `SeedResult` JSON.

## Hands-On

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
$env:API_AUTH_MODE='none'
$env:THREATPRISM_LOCAL_DEV_ACK='true'
$env:DATABASE_URL='sqlite:///:memory:'
python -m threatprism.demo.seed_cli
```

Bash:

```bash
cd /c/Projects/ThreatPrismV2
PYTHONPATH=src API_AUTH_MODE=none THREATPRISM_LOCAL_DEV_ACK=true \
  DATABASE_URL="sqlite:///:memory:" python -m threatprism.demo.seed_cli
```

## A Subtle But Important Finding

Curated fixtures are **post-sanitization snapshots**. The fixture factory already
reduced their unsafe content (e.g., a prompt-injection instruction) to a redacted
marker before promotion. So when you replay them, the prompt firewall finds
nothing left to quarantine, and those fixtures triage to `completed` rather than
`blocked_by_guardrail`.

This is expected. Fixtures that retain rehydratable Stage-2 telemetry (IPs, URLs,
hashes) still exercise live tokenization. To *demonstrate* a live quarantine, you
need an unsanitized input — which curated-fixture replay intentionally does not
provide. Recorded in `LIMITATIONS.md`.

## Interview Prep Talk Track

> "We seed the demo by replaying reviewed fixtures through the real intake API,
> not by inserting database rows. That keeps the guardrail pipeline honest. The
> loader is runtime-owned and never imports dev tooling, so the dependency graph
> stays one-directional. Seeding is gated off by default and refused in
> production, and the safety filter only replays fixtures explicitly approved for
> demo review."

## Quick Reference Card

| Item | Value |
|------|-------|
| Enable at startup | `THREATPRISM_DEMO_SEED=true` (local/demo only) |
| CLI | `python -m threatprism.demo.seed_cli [--source curated] [--no-skip-existing]` |
| Safety gate | `demo_review` + `approved_demo_safe` + `approved_for_tests` |
| Idempotency | skips existing `source_case_id` |
| Extension seam | `FixtureSource` Protocol |
| Spec | `docs/specs/31_DATASET_BACKED_DEMO_SEEDER.md` |
| Tests | `tests/test_demo_seeding.py` |
