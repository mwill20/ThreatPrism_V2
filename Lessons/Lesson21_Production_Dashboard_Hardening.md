# Lesson 21: Production Dashboard Hardening

## Goal

Understand how ThreatPrism hardens the local dashboard surface without turning
it into a production deployment.

## What Changed

- `GET /dashboard` and `/dashboard/assets/*` now receive dashboard-specific
  security headers.
- The Content Security Policy allows same-origin resources and API calls only.
- Dashboard JavaScript rejects non-same-origin request targets.
- Dashboard API calls use timeout-bounded fetch behavior.
- Persona navigation has tab semantics, keyboard movement markers, selected
  state attributes, and visible focus states.
- `tests/test_dashboard_ui.py` now checks header posture, same-origin request
  enforcement, timeout markers, keyboard markers, fake credentials, and
  responsive layout markers.

## Why This Matters

The dashboard is now a user-facing browser surface. Even in a fake-data local
demo, browser risks are different from API-only risks: framing, referrer
leakage, external resource loading, MIME sniffing, stale caches, and keyboard
accessibility regressions are all easy to miss if they are not tested.

## Safety Boundary

This slice does not add production identity, live providers, external
telemetry, real data, real remediation, frontend dependencies, CDN deployment,
or browser matrix certification.

The dashboard still consumes the existing role-safe backend routes and uses
fake demo credentials only.

## Verification

Use the focused dashboard tests for quick feedback:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; python -m pytest tests\test_dashboard_ui.py -p no:cacheprovider --basetemp .pytest_tmp_dashboard_hardening_focus
```

Use the full validation wrapper before closing the slice:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

## Remaining Work

- Production IdP integration.
- TLS/reverse proxy deployment posture.
- Full accessibility audit.
- Browser matrix testing.
- Tracked screenshots or demo recording.

Those remain future slices and require explicit approval.
