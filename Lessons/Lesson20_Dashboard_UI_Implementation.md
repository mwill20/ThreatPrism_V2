# Lesson 20: Dashboard UI Implementation

## Goal

Understand how ThreatPrism adds a usable dashboard without leaving the
fake-data-only, analyst-controlled safety boundary.

## What Changed

- `GET /dashboard` serves a local dashboard from the FastAPI backend.
- `src/threatprism/dashboard/static/` contains dependency-free HTML, CSS, and
  JavaScript.
- The dashboard consumes the documented API contract from
  `docs/DASHBOARD_DATA_CONTRACT.md`.
- Persona tabs exercise analyst, manager/GRC, legal/privacy, audit/debug,
  engineer, and CSI/RGOI views.
- `tests/test_dashboard_ui.py` verifies route serving, same-origin assets,
  protected API behavior, fake credential boundaries, contract references, and
  responsive layout markers.

## Why Same-Origin Static UI

ThreatPrism did not have a frontend toolchain. Serving static assets through
FastAPI keeps this slice small, reviewable, and free of npm dependencies,
external component libraries, third-party assets, or live network calls.

## Safety Rules

- Use fake demo credentials only.
- Keep `ALLOW_REAL_ACTIONS=false`.
- Consume role-safe API routes; do not bypass backend authorization or masking.
- Keep CSI/RGOI read-only.
- Do not introduce production IdP, live providers, telemetry beacons, external
  assets, or real data.

## Verification

The Browser workflow was used against the local `/dashboard` route to verify:

- desktop layout
- mobile breakpoint layout
- analyst case workflow
- manager/GRC persona navigation
- CSI/RGOI cognitive retrieval view

The UI exposed a detail-panel failure mode where optional downstream route
errors blanked the center panel. The JavaScript now treats optional detail
routes as degradable panels so the selected case remains visible.

## Remaining Work

- Production frontend hardening.
- Broader browser matrix testing.
- Accessibility audit.
- Production identity integration.
- Dashboard deployment packaging.

Those are future slices and require explicit approval.
