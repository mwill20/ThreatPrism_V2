# 🖥️ Lesson 33 — Operating the Dashboard (Analyst Co-Pilot Walkthrough)

> **Goal:** Drive the local ThreatPrism dashboard as an analyst — switch personas,
> work a case queue, self-assign, submit feedback, and use "My cases" — and know the
> role boundaries and gotchas.
> **Time:** ~20 min · **Prerequisites:** Lesson 20 (dashboard implementation),
> Lesson 32 (case ownership & authorization). This is a *how-to*, not a code lesson.

---

## 1. 🚀 Launch it

From `docs/runbooks/DASHBOARD_READINESS.md` (PowerShell), demo-key auth + a
**file-backed DB**:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
$env:THREATPRISM_ENV='demo'
$env:API_AUTH_MODE='demo_key'
$env:DEMO_API_KEYS='demo-analyst-key:demo_analyst:analyst,demo-engineer-key:demo_engineer:engineer,demo-manager-key:demo_manager:manager_grc,demo-legal-key:demo_legal:legal_privacy,demo-audit-key:demo_audit:audit_debug'
$env:LLM_PROVIDER='deterministic_demo'
$env:ALLOW_REAL_ACTIONS='false'
python -m uvicorn threatprism.api.app:create_app --factory --reload
```

Open `http://127.0.0.1:8000/dashboard`. Use **Load demo case** (top of the queue) to
create a case, or set `$env:THREATPRISM_DEMO_SEED='true'` before launch to seed the
curated corpus.

> ⚠️ **Do not use `DATABASE_URL=sqlite:///:memory:` for the live dashboard.** It
> shares one SQLite connection across threads and 500s under the dashboard's parallel
> detail fetches. The default file DB is fine. (Hardening backlog item.)

---

## 2. 🎭 Personas (the tabs)

The persona tabs switch *both* the authenticated demo key **and** the role-filtered
view. Each persona only sees what its role is allowed to:

| Persona | Sees | Can self-assign / give feedback? |
|---|---|---|
| **Analyst** | Case queue, evidence, full security telemetry | ✅ |
| **Engineer** | Cases, timeline, MITRE mappings | ✅ |
| **Manager/GRC** | Manager-review queue, GRC mappings | ❌ (403 — not their job) |
| **Legal/Privacy** | Healthcare-review queue, exposure metadata | ❌ |
| **Audit/Debug** | Audit events | ❌ |
| **CSI/RGOI** | Governed cognitive objects | ❌ |

The **Analyst co-pilot** controls only appear on **Analyst** and **Engineer** — the
roles whose demo key maps to a case-working identity.

---

## 3. 🗂️ Work the queue

- **Filters:** Status / Severity narrow the list. **My cases only** (analyst/engineer)
  shows just the cases *you* own.
- **Click a case** to load its detail (determination, severity, disposition,
  confidence) + persona-specific panels (evidence / timeline / MITRE / GRC / audit).
- **Refresh** re-pulls metrics + the queue; **Load demo case** seeds a fresh one.

---

## 4. 🤝 The analyst co-pilot loop

On the Analyst/Engineer detail panel, the **Analyst co-pilot** card:

1. **Assign to me** — take ownership. The header flips to *Assigned to `<your id>`*.
   (Self-assign only — you can't assign a case to someone else.)
2. **Work the case** — read the report + evidence panels.
3. **Submit feedback** — pick determination / severity / disposition / confidence,
   add an optional note, click **Submit feedback**. The case status moves to
   `analyst_feedback_submitted`, and ThreatPrism computes disagreement metrics (which
   feed the manager review queue and the tuning loop).
4. **Release** — give the case back when done. Only the **owner or an admin** can
   release; trying to release someone else's case returns 403 (shown inline).

**My cases only** then lets you watch your own queue shrink as you work it.

---

## 5. 🔒 Role boundaries you'll see in practice

- Switch to **Manager/GRC** and the co-pilot controls disappear — and the API would
  reject assign/feedback with **403** anyway (manager isn't a case-working role).
- Feedback is **attributed to your authenticated identity**, not anything you type —
  you can't file feedback as another analyst. (See Lesson 32 §2.6.)
- "My cases" is keyed on **your identity**, not a parameter — you can't peek at
  another analyst's queue (Lesson 32 §2.5).

These aren't UI conveniences; they're the same authorization rules the API enforces,
surfaced visually.

---

## 6. 🧰 Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Case detail shows 500 / blank | You're on `:memory:` DB — relaunch with a file DB (§1). |
| Assign/feedback button does nothing | You're on a non-assignable persona (manager/legal/audit) — switch to Analyst/Engineer. |
| `favicon.ico 404` in console | Harmless — there's no favicon. |
| Empty queue | Click **Load demo case**, or seed with `THREATPRISM_DEMO_SEED=true`. |

---

## 7. 🎤 Talk track

> "The dashboard is the analyst co-pilot: pick the Analyst persona, open a case from
> your queue, **Assign to me**, review the triage report and evidence, then **Submit
> feedback** — which records your disagreement with ThreatPrism's verdict and feeds
> the tuning loop. **My cases only** shows just what I own. The persona tabs are real
> authorization boundaries — a Manager persona literally can't self-assign or file
> feedback, and feedback is attributed to my authenticated identity, not a field I
> type. It's the API's access-control model made visible."
