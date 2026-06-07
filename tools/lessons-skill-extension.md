# /lessons Skill — Decisions & Trade-offs Extension

This file is an addendum to your existing `~/.claude/skills/lessons/SKILL.md`.
It adds the governance-research step and the mandatory Decisions & Trade-offs
section to every lesson the skill generates.

**To install:** append the contents below to your existing skill file:
```bash
cat tools/lessons-skill-extension.md >> ~/.claude/skills/lessons/SKILL.md
```

---

## Pre-Writing Research Step (add to your workflow)

Before writing any lesson, read these governance files and extract what is
relevant to the lesson's component. Do not invent content — every claim in
the Decisions & Trade-offs section must trace to one of these files:

- `DECISIONS.md` — scan for D-XXX entries that touch this component
- `LIMITATIONS.md` — scan for limitations relevant to this component
- `docs/ARCHITECTURAL_NORTH_STAR.md` — relevant non-negotiables
- `docs/specs/21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md` — **only** for
  security-relevant components (guardrails, auth, healthcare, LLM governance,
  prompt injection)

---

## Decisions & Trade-offs Section — Required in Every Lesson

This section is **mandatory** for every lesson you generate or backfill.
Add it near the end of the lesson — after the main content and before the
Quick Reference Card (Early style) or Interview Prep (Late style).

### Template for Early Style lessons (Lessons 00–14)

```markdown
## ⚖️ Decisions & Trade-offs

### Decisions Touched

| Decision | Statement | Why It Matters Here |
|----------|-----------|---------------------|
| D-XXX | [Exact statement from DECISIONS.md] | [How it shapes this component] |

### What We Explicitly Rejected

- **[Alternative approach]:** [Why it was ruled out — trace to DECISIONS.md or LIMITATIONS.md]
- **[Second alternative]:** [Reason]

### Trade-off Log

| Choice Made | What We Gained | What We Gave Up |
|-------------|----------------|-----------------|
| [Design decision] | [Concrete benefit] | [Concrete cost or constraint] |

### Future Gate Conditions

This component's design would change if:

- [Trigger condition, e.g. "Real LLM is enabled"] → re-opens D-XXX
- [Second trigger] → re-opens D-XXX

### Limitations in Scope

- `[Demo-Safe Boundary]` [Description]
- `[Gated Future Work]` [Description]
- `[Accepted Risk]` [Description — include owner sign-off note if present]
```

### Template for Late Style lessons (Lessons 15+)

```markdown
## ⚖️ Decisions & Trade-offs

### Decisions Touched

| Decision | Statement | Why It Matters Here |
|----------|-----------|---------------------|
| D-XXX | [Exact statement from DECISIONS.md] | [How it shapes this component] |

### What We Explicitly Rejected

- **[Alternative]:** [Reason — grounded in a specific decision or limitation]

### Trade-off Log

| Choice Made | What We Gained | What We Gave Up |
|-------------|----------------|-----------------|
| [Design choice] | [Benefit] | [Cost] |

### Future Gate Conditions

This design would change if:
- [Trigger] → re-opens D-XXX

### Limitations in Scope

- `[Demo-Safe Boundary]` [Description]
- `[Gated Future Work]` [Description]
```

---

## Rules for Filling In This Section

1. **Only cite real decision IDs.** Read `DECISIONS.md` before writing. Never
   invent a D-XXX number. If no decision directly applies, omit that table row.

2. **"What We Explicitly Rejected" must name the alternative.** Vague entries
   like "a more complex approach" are not acceptable. Name the technology,
   pattern, or design (e.g. "SQLAlchemy ORM", "LLM-as-judge primary gate").

3. **Trade-off Log must have concrete gains and costs.** "Simpler" is not a
   gain. "In-memory SQLite" → "no infra deps, test isolation" / "no persistence
   across process restarts" is concrete.

4. **Gate conditions must name the trigger.** "If the project grows" is not a
   trigger. "When `get_provider()` is changed to return a real LLM provider" is
   a trigger.

5. **Limitations must use the exact category label from LIMITATIONS.md:**
   - `[Demo-Safe Boundary]` — intentional POC constraint, acceptable for demo use
   - `[Gated Future Work]` — planned capability with an explicit trigger to unlock
   - `[Accepted Risk]` — known gap with named owner sign-off at POC scope

6. **Security-relevant lessons** (guardrails, auth, healthcare, LLM governance,
   prompt injection) must also add a Threat Treatment table:

```markdown
### Threat Treatment

| Threat ID | Threat | Treatment | Owner Decision |
|-----------|--------|-----------|----------------|
| [ID from spec 21] | [Threat name] | Mitigate / Accept / Avoid / Transfer | [Summary] |
```
