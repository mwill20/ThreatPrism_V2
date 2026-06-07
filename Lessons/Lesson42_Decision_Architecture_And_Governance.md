# 🏛️ Lesson 42 — Decision Architecture & Governance

> **Goal:** Understand how `DECISIONS.md` works as a governance artifact, navigate the 41
> locked decisions by category, apply the North Star decision rubric before proposing
> any architecture change, and know how to re-open a decision correctly.
> **Time:** ~35 min · **Prerequisites:** Lesson 00 (system overview), Lesson 15 (threat model treatment).

---

## 1. Why a Decision Register Exists

Every architecture choice that is made once and relied on everywhere is a candidate for
`DECISIONS.md`. Without a register, the same debates recur in every new session, new
decisions contradict old ones silently, and "why was this built this way?" has no
authoritative answer.

`DECISIONS.md` records **locked** decisions — not suggestions, not open questions, not
implementation notes. A locked decision means: this was evaluated, a choice was made,
and future changes require re-opening the decision explicitly, not working around it.

Primary files:

```text
DECISIONS.md
docs/ARCHITECTURAL_NORTH_STAR.md
LIMITATIONS.md
AGENTS.md
```

---

## 2. Decision Categories Map

The 41 decisions (D-001 through D-041) fall into six categories:

| Category | Decision IDs | What They Govern |
|----------|-------------|-----------------|
| **Identity & Naming** | D-001 to D-003 | Product name, repository, source of truth |
| **Product & Architecture** | D-004 to D-008, D-015, D-016, D-025 | Product direction, stack, tenancy, SOAR/MS integration, V1 porting, first slice, North Star |
| **AI & Safety** | D-009, D-010, D-011, D-021, D-022, D-037 | LLM provider strategy, action safety, guardrail requirements, healthcare safeguard framing, compliance language, CSI/RGOI boundary |
| **Persistence & Configuration** | D-012, D-019, D-033 | SQLite/PostgreSQL path, async strategy, context-light handoff |
| **Auth & Access Control** | D-017, D-020, D-024, D-026, D-028, D-030, D-038 to D-040 | API security boundary, demo auth modes, metrics/access sequencing, role policy, production identity readiness, token verifier |
| **Slices & Operations** | D-013, D-014, D-023, D-027, D-029 to D-036, D-041 | GRC language, threat intel stubs, metrics slice ordering, slice closeout documentation, eval harness, CI hardening, scenario pack, dataset strategy, Docker, fixture factory, demo seeder |

---

## 3. Five Decisions Worth Deep Study

### D-010 — Action Safety (the "Avoid" anchor)

> V2 permits recommended, simulated, dry-run, and adapter scaffolding only.
> `ALLOW_REAL_ACTIONS=false` by default.

This is the project's most important "Avoid" treatment. Real remediation is not
gated — it is out of scope for V2. The implementation is `enforce_action_safety()` in
`guardrails/policy.py`, which rejects any report where `real_action_executed: true`.

**Why it matters:** The simplest security treatment for "AI executes containment without
human approval" is not to build the execution surface. Every other guardrail layer
protects what exists; this decision prevents a whole threat class from existing.

---

### D-012 — Persistence (the "SQLite now, PostgreSQL-ready" pattern)

> Demo mode uses SQLite. Persistence should be designed so PostgreSQL can be added later.

The implementation uses `SQLiteRepository` with JSON blobs. The PostgreSQL path is kept
open through `database_url` in `Settings` and the repository pattern in
`persistence/sqlite.py`. Nothing in the service layer calls SQLite directly.

**Why it matters:** A demo product that hardwires SQLite into service logic can never be
production-ready without a rewrite. Passing `database_url` through settings and
accessing data only through the repository keeps the future path open at near-zero cost.

---

### D-021 — Healthcare Safeguard Framing (the "assume contamination" principle)

> ThreatPrism treats inbound SOAR data as potentially contaminated. Identifiers become
> PHI/ePHI risk when connected to health context.

The implementation is `HEALTH_CONTEXT_TERMS` co-presence detection in
`guardrails/healthcare.py`. An IP address alone is not flagged; an IP address appearing
in the same payload as "patient portal" or "MRN" is.

**Why it matters:** This decision threads a needle — it prevents over-redacting normal
security telemetry (which would blind SOC analysts) while still protecting identifiers
that carry healthcare exposure risk. Getting this wrong in either direction has real
operational cost.

---

### D-026 — Demo Access Control (the "role rendering ≠ authorization" split)

> ThreatPrism uses demo API-key auth for role-aware views when
> `API_AUTH_MODE=demo_key`. `?role=` is a view request, not authority.

The implementation is `authorize_role_view()` in `auth/demo.py`. The effective role
derives from the demo credential, not from the query parameter.

**Why it matters:** D-024 explains why this decision had to come before metrics: a
`?role=manager_grc` query parameter accepted as authority would let any caller forge any
role. The split between "view request" and "authority" is the architectural principle
that makes the entire role-based rendering system credible.

---

### D-037 — CSI/RGOI Read-Only Boundary (the "humans own truth" principle)

> CSI/RGOI is not unrestricted AI memory. Humans own truth. AI-authored cognition is
> non-authoritative unless approved through a human governance path.

The implementation enforces this through `KnowledgeLearningLoop(enabled=False)` by
default, role-checked human promotion gates, and Stage-1 tokenization before any write.

**Why it matters:** This decision defines the hardest line in the AI governance layer.
Without it, an AI could propose knowledge changes that accumulate unchecked. The
deterministic human gate over a probabilistic model is the pattern that makes RGOI
trustworthy rather than just fast.

---

## 4. How Decisions Interlock

Decisions create dependency chains. Changing one often forces re-examination of others:

```text
D-006 (single-tenancy)
  → enables D-012 (SQLite is sufficient for single-org)
  → enables D-019 (in-process tasks are fine for single-org throughput)
  → enables D-020 (localhost-only demo mode is safe for single-org)

D-010 (no real actions)
  → simplifies D-011 (guardrails don't need remediation rollback logic)
  → closes the action-safety threat class in spec 21

D-026 (demo key auth with role policy)
  → depends on D-024 (access control before metrics)
  → unlocks D-028 (metrics safe to expose behind role policy)
  → is superseded by D-038/D-039/D-040 when external_oidc is enabled
```

Before changing a decision, trace its dependents in this file. A decision that looks
isolated often has downstream decisions that assumed it was locked.

---

## 5. The North Star Decision Rubric

`docs/ARCHITECTURAL_NORTH_STAR.md` includes a 10-question rubric. Ask all 10 before
accepting any architecture change:

1. Does it preserve analyst control?
2. Does it reduce exposure risk or keep exposure risk unchanged?
3. Does it preserve evidence provenance and source traceability?
4. Does it avoid compliance, certification, and control-satisfaction claims?
5. Does it keep data fake and demo-safe?
6. Does it keep real remediation disabled?
7. Does it avoid hardwiring one vendor into the core model?
8. Does it keep Microsoft integrations first-class through adapters?
9. Does it remain testable with local safe validation?
10. Does it leave a reasonable future production path open?

If any answer is "no", either change the design or record the risk with a named
revisit trigger before implementing.

---

## 6. How to Re-Open a Decision

Re-opening a decision is not the same as ignoring it. The process:

1. **Identify the decision ID** and its statement in `DECISIONS.md`.
2. **State the trigger** — what changed that makes the original decision no longer
   appropriate (e.g., "real LLM provider is now integrated").
3. **Evaluate the dependents** — which other decisions assumed this one was locked?
4. **Run the North Star rubric** — does the new approach pass all 10 questions?
5. **Record the new decision** — add a new D-XXX or update the existing one with the
   revised statement and rationale.
6. **Update `docs/ARCHITECTURAL_NORTH_STAR.md`** if the direction changes.
7. **Update `docs/WORKING_CHECKLIST.md`** when the active slice changes.

Silent drift — implementing something that contradicts a locked decision without
updating the register — is explicitly called out as unacceptable in D-025.

---

## ⚖️ Decisions & Trade-offs

### Decisions Touched

| Decision | Statement | Why It Matters Here |
|----------|-----------|---------------------|
| D-025 | `docs/ARCHITECTURAL_NORTH_STAR.md` is the directional architecture guide; update it, `DECISIONS.md`, and the checklist when direction changes | This lesson is the curriculum expression of D-025; the register only works if it stays synchronized with reality |
| D-027 | Every implementation slice must close with documentation and learning updates | Decisions are only durable if they are recorded; D-027 makes decision recording part of the slice closeout contract |
| D-033 | ThreatPrism uses a file-based startup path to reduce new-chat context usage | The decision register is one of the files that provides architectural context without requiring the full handoff doc to be re-pasted |

### What We Explicitly Rejected

- **Inline code comments as the decision record:** Comments rot as code changes and don't survive refactors. A separate `DECISIONS.md` is versioned, searchable, and can be read without understanding the code.
- **Treating architectural decisions as open for re-debate in every session:** D-003 locks the source of truth to the handoff brief and spec pack. The register exists so settled questions stay settled unless explicitly re-opened.

### Trade-off Log

| Choice Made | What We Gained | What We Gave Up |
|-------------|----------------|-----------------|
| Locked decisions in a single flat file | Easy to search, version, and reference; no special tooling required | Flat file doesn't enforce dependencies; a new decision can contradict an old one unless the author checks for conflicts |
| Named decision IDs (D-XXX) | Decisions can be referenced precisely from lesson files, spec docs, and threat treatments | Requires discipline to assign the next sequential ID; ID collisions would silently hide decisions |

### Future Gate Conditions

This lesson's content evolves when:

- **New decisions are added** → add D-XXX entries to the Decisions Categories Map table above
- **A decision is re-opened and superseded** → update the relevant deep-dive section and interlock diagram

### Limitations in Scope

- `[Demo-Safe Boundary]` The decision register records POC-scope decisions; production deployment requires re-opening gated decisions explicitly rather than inheriting them from POC scope
- `[Accepted Risk]` A flat markdown file cannot enforce decision consistency; human review of the register is required before each new slice

---

## Interview Prep

**Q: Why does ThreatPrism record architectural decisions separately from the code?**

A: Because code explains *what* was built; decisions explain *why*. The same code could
implement multiple different design philosophies, and future contributors need to
understand the constraints that shaped each choice — especially the ones that look
surprising. `DECISIONS.md` keeps that rationale durable across sessions and contributors.

**Q: What does it mean for a decision to be "locked"?**

A: It means the choice was evaluated and committed. Future changes require explicitly
re-opening the decision — not working around it silently. D-025 says silent drift is
unacceptable: if the implementation moves away from a locked decision, either the code
or the register must change, and the change must be visible.

**Q: Walk me through the North Star rubric. Why are questions 7 and 8 separate?**

A: Question 7 ("avoid hardwiring one vendor into the core model") protects the
provider-agnostic design for SOAR adapters, LLM providers, and threat intelligence
stubs. Question 8 ("keep Microsoft integrations first-class through adapters") adds a
positive constraint: Microsoft-first is a product direction, but it must be implemented
through adapters, not by making the core model Microsoft-only. Both questions must pass.
