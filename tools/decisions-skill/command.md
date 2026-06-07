---
description: Architectural decision advisor and recorder — helps you make decisions AND documents them in DECISIONS.md
argument-hint: "[think '<question>' | init | add '<decision>' | review]"
---

Use the **decisions** skill (invoke it via the Skill tool) for this project: $ARGUMENTS

Routing:
- If `$ARGUMENTS` starts with "think" — read project context, present options with
  project-specific trade-offs, recommend, then record the confirmed decision
- If `$ARGUMENTS` is empty or "init" — analyze the project and generate DECISIONS.md from scratch
- If `$ARGUMENTS` starts with "add" — decision already made, write the entry directly
- If `$ARGUMENTS` is "review" — audit existing DECISIONS.md for gaps and stale entries

Non-negotiable: read the actual project files before writing or recommending anything.
Every decision and recommendation must be grounded in something real — a config file,
a dependency, a pattern in the code. Never invent decisions or options not visible in
the project.
