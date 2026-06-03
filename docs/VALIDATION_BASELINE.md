# Validation Baseline (canonical)

This is the **single source of truth** for the current validated test baseline.
Other docs (`README.md`, `RUNBOOK.md`, `START_HERE.md`, `Lessons/00_Index.md`,
`docs/WORKING_CHECKLIST.md`) reference this file instead of restating the number, so
the count is edited in exactly one place per slice.

## Current baseline

```text
302 passed, 3 skipped
eval harness dry-run: 15 passed / 0 failed
```

The **3 skipped** are the opt-in live Prompt Guard 2 tests (recall + false-positive +
review-mode), which require the gated local model download and are not run in the
default suite.

## How to reproduce

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

Or run pytest directly:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = '1'
PYTHONPATH=src python -m pytest -p no:cacheprovider
```

## Update protocol

When a slice changes the count, update **this file only**, then confirm the
referencing docs still point here (they should not carry their own number).
