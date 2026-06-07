---
name: decisions
description: Architectural Decision Register — helps you make decisions AND records them. Use when facing an architectural choice ("should I use X or Y?"), when you want to document decisions already made in a codebase, or when auditing an existing decision register for gaps. Reads actual project files to ground every recommendation and record in real constraints.
---

# Architectural Decision Register

You serve two roles: **decision advisor** and **decision recorder**. Both read the
project before acting. Neither invents content.

**As advisor:** When the developer faces a choice, you read their project constraints,
present 2–4 options with trade-offs specific to this project, make a recommendation,
and record the outcome once confirmed.

**As recorder:** When decisions are already made, you document them precisely — what
was decided, why, what was rejected, and what would reopen the decision.

**Non-negotiable:** Read the actual project files before writing anything. Every
recommendation and every recorded decision must be grounded in something real and
visible in the codebase.

---

## How to Invoke

Determine the mode from the argument:

**Think / Decide** — `/decisions think "should I use Redis or Postgres for session storage?"`
→ Read project context, present options with project-specific trade-offs, recommend,
  then record the confirmed decision in `DECISIONS.md`.

**Init** — `/decisions` or `/decisions init`
→ Analyze the project from scratch and generate a complete `DECISIONS.md`.

**Add** — `/decisions add "Use Redis for session caching"`
→ Decision already made — write the entry directly without deliberation.

**Review** — `/decisions review`
→ Read the existing `DECISIONS.md`, compare against the codebase, and suggest gaps,
  outdated entries, or missing categories.

If no argument is given, ask:
> "Should I generate DECISIONS.md from scratch, add a specific decision, or review
> the existing register for gaps?"

---

---

## Think / Decide Mode — Helping You Make a Decision

When invoked with `/decisions think "[question]"`:

### Step A — Read project constraints first

Before presenting any options, read:
- Dependency file — what is already in the stack?
- Config/environment file — what infrastructure already exists?
- Any existing `DECISIONS.md` — what constraints are already locked?
- The specific file(s) most relevant to the decision being made

The goal: understand what the project already commits to, so options that conflict
with locked decisions or introduce unjustified new dependencies are ruled out early.

### Step B — Present options

Present 2–4 realistic options in a table:

```
## Decision: [Restate the question as a decision statement]

### Options

| Option | What it means for this project | Gains | Costs | Fits current stack? |
|--------|-------------------------------|-------|-------|---------------------|
| A | ... | ... | ... | ✅ / ⚠️ / ❌ |
| B | ... | ... | ... | ✅ / ⚠️ / ❌ |
```

**Rules for the options table:**
- Gains and costs must be specific to this project — not generic ("Redis is fast")
  but grounded in what you read ("no new infrastructure needed — Redis already in
  docker-compose.yml" or "adds a new dependency not currently in requirements.txt")
- "Fits current stack?" reflects what you actually found in the project files
- Do not present options that are clearly incompatible with locked decisions

### Step C — Recommend

State a recommendation and the single most important reason for it:

```
### Recommendation: Option [X]

[One paragraph. Why this option fits this project's specific constraints better
than the alternatives. Reference what you read — a file, a dependency, a locked
decision — not generic best practices.]

**The deciding factor:** [One sentence. The specific project constraint that tips
the scales toward this option over the next-best alternative.]
```

### Step D — Confirm and record

Ask before writing:

> "Should I record Option [X] — [decision statement] — as D-[NNN] in DECISIONS.md?
> Or would you like to adjust the decision before locking it?"

Once confirmed, write the entry using the Entry Template in the Record section below.
If the developer modifies the decision, update the entry to reflect their actual choice.

---

## Step 1 — Read the Project

Before writing any decision, read:

**Always read:**
- `README.md` — stated purpose, stack, architecture overview
- Dependency file — `requirements.txt`, `package.json`, `pyproject.toml`, `go.mod`, `Gemfile`
- Config/environment file — `.env.example`, `config.py`, `settings.py`, `appsettings.json`
- Main entry point — `main.py`, `app.py`, `index.ts`, `Program.cs`, `cmd/main.go`
- Any existing `DECISIONS.md`, `docs/decisions/`, or `docs/adr/` files

**Read if present:**
- `docker-compose.yml` or `Dockerfile` — deployment and infrastructure choices
- CI/CD config — `.github/workflows/`, `.gitlab-ci.yml`, `Makefile`
- Auth files — any file with "auth", "jwt", "oauth", "middleware" in the name
- Database files — migration files, schema definitions, ORM models
- Test entry point — understand what the test strategy reveals about architecture

**For AI/ML projects, also read:**
- Any file referencing model providers, embeddings, vector stores, or agents
- Prompt templates or system prompt files
- Safety/guardrail files

Do not begin writing until all reads are complete. State what you read at the top of
your response before generating the register.

---

## Step 2 — Identify Decisions by Category

For each category below, identify what choices were made and why they are locked.
A decision is worth recording if: (a) a reasonable engineer might question it, or
(b) changing it would require significant rework elsewhere.

| Category | What to look for |
|----------|-----------------|
| **Identity & Naming** | Project name, repo name, canonical source of truth |
| **Stack & Language** | Language choice, framework choice, why this over alternatives |
| **Architecture Pattern** | Monolith vs microservices, layered vs hexagonal, event-driven vs request-response |
| **Data Storage** | Database engine, ORM or raw SQL, schema strategy, migration approach |
| **Authentication & Auth** | Auth method, token strategy, role model, demo vs production auth |
| **Scope & Boundaries** | What is explicitly out of scope, demo vs production posture, single vs multi-tenant |
| **AI/ML** (if present) | Model provider strategy, deterministic vs probabilistic, human-in-the-loop gates |
| **Safety & Guardrails** | What safety controls exist, what is explicitly blocked, default-deny surfaces |
| **Integrations** | External services, adapter strategy, vendor lock-in posture |
| **Operations** | Deployment target, CI strategy, observability approach |

Aim for 5–15 decisions for a new project. Quality over quantity — a file with 8 precise
entries is more useful than 30 vague ones.

---

## Step 3 — Write DECISIONS.md

Use this exact format for the file and each entry.

### File Header Template

```markdown
# DECISIONS.md — [Project Name]

This file records locked architectural decisions for [Project Name]. Each entry documents
what was decided, why, what alternatives were rejected, and what conditions would reopen
the decision.

**A locked decision is not open for re-debate.** If implementation diverges from a locked
decision, either the code or this file must change — silent drift is unacceptable.

---

## Decision Index

| ID | Name | Category | Status |
|----|------|----------|--------|
| D-001 | [Name] | [Category] | Locked |

---
```

### Entry Template

```markdown
## D-[NNN] — [Short Name]

**Decision:** [One sentence. State what was decided as a positive claim — not "we
considered X" but "this project uses X."]

**Rationale:** [2–4 sentences. Explain why this choice was made. Connect it to the
project's actual constraints — scope, team size, performance requirements, safety
requirements, or cost. Do not write generic rationale that could apply to any project.]

**Alternatives considered:**
- **[Alternative 1]:** [Why it was rejected — be specific. "Too complex" is not a reason.
  "Requires a separate infrastructure component not justified at POC scope" is a reason.]
- **[Alternative 2]:** [Reason.]

**Gate condition:** [One sentence. Name the specific event or trigger that would cause
this decision to be revisited. "If the project grows" is not a gate condition. "If
multi-tenancy is added" or "when a real LLM provider is integrated" is a gate condition.
If no realistic gate exists, write "No planned gate — this decision is stable."]

**Status:** Locked
**Date:** [YYYY-MM-DD]
```

---

## Rules for Good Decisions

1. **One decision per entry.** If an entry contains "and", it probably covers two decisions.

2. **Rationale must be project-specific.** Generic rationale ("SQLite is simpler") that
   could apply to any project is a sign the decision hasn't been thought through. Tie
   it to this project's actual constraints.

3. **Alternatives must be named.** "We considered other options" is not useful. Name
   the specific technology, pattern, or approach that was rejected and why.

4. **Gate conditions must be triggerable.** If you can't imagine a real scenario that
   would trigger the gate, either the gate is wrong or the decision is too vague.

5. **Status is binary: Locked or Superseded.** A decision is locked until it is
   explicitly reopened and replaced by a new entry. When superseded, add
   `**Superseded by:** D-[NNN]` to the old entry — do not delete it.

6. **Dates matter.** Record when the decision was made. A decision from the project's
   first week has different weight than one made after six months of production use.

---

## Add Mode — Adding a Single Decision

When invoked with `/decisions add "[description]"`:

1. Read the existing `DECISIONS.md` to find the next available ID
2. Read the relevant project files to ground the entry
3. Generate one complete entry using the Entry Template
4. Append it to `DECISIONS.md` and update the Decision Index table

Do not regenerate the whole file — append only.

---

## Review Mode — Auditing an Existing Register

When invoked with `/decisions review`:

1. Read the existing `DECISIONS.md`
2. Read the project's current state (dependency files, config, main files)
3. Report:
   - **Gaps:** Decision categories with no entry (use the category table above)
   - **Stale entries:** Decisions whose rationale no longer matches the code
   - **Missing gate conditions:** Entries that say "No gate" but where a realistic gate exists
   - **Suggested new entries:** Decisions visible in the code that aren't recorded

Format the review as a checklist the developer can act on.

---

## Quality Checklist

Before writing the file, confirm:

- [ ] All project files listed in Step 1 have been read
- [ ] Every decision is evidenced by something in the codebase — no invented entries
- [ ] Every entry has a specific rationale tied to this project's constraints
- [ ] Every alternative is named (not "other options")
- [ ] Every gate condition names a specific trigger event
- [ ] The Decision Index table matches the entries below it
- [ ] Status is set on every entry
- [ ] Date is set on every entry (use today's date if creating from scratch)

---

## Output

Write the file to `DECISIONS.md` at the project root. If the file already exists and
this is an init run, ask before overwriting:
> "DECISIONS.md already exists. Replace it, or review and extend it instead?"

For add and review modes, always extend — never replace.
