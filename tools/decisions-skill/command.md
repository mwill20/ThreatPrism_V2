---
description: Generate or update DECISIONS.md — the architectural decision register for this project
argument-hint: "[init | add '<decision description>' | review]"
---

Use the **decisions** skill (invoke it via the Skill tool) to manage the architectural
decision register for this project: $ARGUMENTS

Routing:
- If `$ARGUMENTS` is empty or "init" — analyze the project and generate DECISIONS.md from scratch
- If `$ARGUMENTS` starts with "add" — add one specific decision described in the argument
- If `$ARGUMENTS` is "review" — read the existing DECISIONS.md and report gaps or stale entries

Non-negotiable: read the actual project files before writing. Every decision must be
grounded in something real — a config file, a dependency, a pattern in the code. Never
invent decisions that aren't visible in the project.
