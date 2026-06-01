# Runbook: Run ThreatPrism Against a SOC Dataset

**Purpose.** Prove the system works end-to-end on a realistic SOC dataset **without
a SOAR integration, a live LLM, or a production environment**. This is the premise
of the whole build: realistic SOC data in → full guardrail + triage pipeline →
observable, role-safe output.

**What this proves (and what it does not).** It demonstrates that the *intake,
four-layer guardrails, deterministic triage, persistence, metrics, and read models*
work end-to-end on real-shaped SOC data. It does **not** demonstrate LLM reasoning
quality — the provider is the inert `DeterministicDemoProvider`, and a real semantic
classifier/LLM is gated (see `docs/specs/32_SEMANTIC_PROMPT_INJECTION_LAYER.md`).

The dataset is the three reviewed third-party families promoted under
`fixtures/curated_datasets/`: **Synthea** (healthcare context), **deepset**
(prompt injection), and **OTRF** (SOC telemetry) — 32 cases total, replayed
through the real `create_case` + `run_triage` path.

---

## Option A — One-command end-to-end run (recommended)

Self-contained, in-memory, no server required.

```powershell
# PowerShell
$env:PYTHONPATH = "src"
python -m threatprism.demo.run_soc_demo
```

```bash
# Bash
PYTHONPATH=src python -m threatprism.demo.run_soc_demo
```

Add `--json` for machine-readable output only, or `--show-reports N` to also dump
the full triage reports for the first N completed cases (so you can read the
actual per-case deliverable, not just the aggregate).

The run also prints a **batch executive summary** — cases ranked most-critical-first
with per-case provenance (`sha256` source hash) and evidence-ID traceability, so an
auditor can review quickly. Its `narrative` field (LLM-generated executive prose) is
intentionally empty (`pending_real_llm_provider`) until the real-LLM gate opens — the
ranking and provenance are deterministic and usable today; only the prose is gated.

### Expected output

```text
ThreatPrism - End-to-End SOC Dataset Run
============================================
Source: fixtures/curated_datasets/ (3 reviewed families) - no SOAR, no live LLM, no prod.

Seeded 32 cases (skipped 0) through real intake + triage:
  - deepset_prompt_injection: 12
  - otrf_soc_telemetry: 8
  - synthea_healthcare: 12

Triage outcome (all terminal - nothing left pending):
  completed=31  blocked_by_guardrail=1  needs_review=0  failed=0  queued=0  running=0

Report severity:       {'high': 8, 'low': 11, 'medium': 12}
Report determination:  {'benign': 23, 'suspicious': 8}
Guardrail blocks:      1 (prompt firewall fired on retained injection text)
Manager-review queue:  0    Healthcare-review queue: 0
```

### How to read it

| Signal | What it proves |
|--------|----------------|
| `Seeded 32 ... through real intake + triage` | The dataset was replayed through the *real* pipeline, not mocked |
| `completed=31 ... queued=0 running=0` | Every case reached a terminal triage status — nothing hung |
| `blocked_by_guardrail=1` | The runtime prompt firewall **fired on real dataset content** — one deepset injection row (which retains un-redacted attacker text) was quarantined before the provider ran |
| `severity={'high': 8, ...}` | OTRF credential-dumping telemetry triaged **high**; the deterministic provider produced a coherent distribution |
| `Healthcare-review queue: 0` | **Honest artifact, not a bug:** curated fixtures are post-sanitization snapshots, so the Synthea SSNs are already tokenized — the safeguard correctly sees a token, not raw PHI, on replay (see `docs/specs/31_DATASET_BACKED_DEMO_SEEDER.md` §7) |

---

## Evolution 1 — Auto-close delta (SOAR catch-all safety net)

Models the headline SOC-migration value: a naive SOAR auto-closes everything the
*source* didn't mark high/critical; ThreatPrism's triage catches the cases that
rule would have wrongly closed (the false-negative saves).

```powershell
$env:PYTHONPATH = "src"
python -m threatprism.demo.auto_close_delta
```

```text
SOAR would auto-close:       31 (100% volume reduction)
  ...ThreatPrism cleared:    23 (agreement - safe to auto-close)
  ...ThreatPrism FLAGGED:    8  (the catch - auto-close would have missed these)
```

The corpus has no high inbound severities, so the naive rule would close all 31;
ThreatPrism flags 8 (the OTRF telemetry cases). The **catch** is the value: those 8
are cases a cheap auto-close would have silently closed. The real auto-close rate +
catch count over a benign-heavy feed are an owner `--live` run (no volume fabricated).

---

## Option B — Interactive HTTP path (explore the API)

To poke the live endpoints yourself, start the server with the demo seed hook on
(seeds the same curated families at startup), then query the read endpoints.

```bash
PYTHONPATH=src THREATPRISM_AUTH_REQUIRED=false THREATPRISM_LOCAL_DEV_ACK=true \
  THREATPRISM_DEMO_SEED=true DATABASE_URL="sqlite:///:memory:" \
  python -m threatprism.cli.main
```

Then, against the running server:

```bash
curl localhost:8000/metrics
curl "localhost:8000/cases/read-model?role=analyst"
curl "localhost:8000/cases/read-model?role=manager_grc"   # role-masked view
curl localhost:8000/queues/manager-review
curl localhost:8000/queues/healthcare-review
```

> Note: the startup seed hook seeds the committed curated **and** curated_datasets
> sources; it never seeds the off-by-default `LocalDatasetSource`. Demo seeding is
> refused in `prod`/`production` by `validate_runtime()`.

---

## Validation

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1 -BaseTemp .pytest_tmp_soc_run
```

The end-to-end run is regression-tested in `tests/test_soc_dataset_run.py`
(seeded counts, terminal-status invariant, prompt-firewall-fired assertion, and a
no-leakage check on the summary).

---

## Scope boundaries

- No SOAR, live LLM, cloud, enrichment, or production identity is used or required.
- `ALLOW_REAL_ACTIONS=false` is unchanged; no remediation is executed.
- Raw third-party rows are never read here — only the sanitized committed
  derivatives under `fixtures/curated_datasets/`.
- Demonstrating *LLM triage quality* (vs. pipeline correctness) requires the gated
  real-LLM rollout and the semantic layer in `docs/specs/32`.
