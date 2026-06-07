# 📋 Lesson 43 — The Limitation Register & Gate Conditions

> **Goal:** Understand `LIMITATIONS.md` as a first-class governance document, read each
> domain's limitations by category, trace the gate conditions that unlock gated future work,
> and produce an operator readiness checklist for moving toward production.
> **Time:** ~30 min · **Prerequisites:** Lesson 42 (decision architecture), Lesson 15 (threat model).

---

## 1. What the Limitation Register Is

`LIMITATIONS.md` documents what ThreatPrism intentionally does **not** do and why. It is
not a bug list or a wishlist. It is a governance record.

Every limitation falls into one of three categories:

| Category | Label | Meaning |
|----------|-------|---------|
| **Demo-Safe Boundary** | `[Demo-Safe Boundary]` | Intentional POC constraint; acceptable for demo use; does not indicate a defect |
| **Gated Future Work** | `[Gated Future Work]` | Planned capability with an explicit trigger condition; must not be built without re-opening the relevant threat treatment |
| **Accepted Risk** | `[Accepted Risk]` | Known gap with named owner sign-off; tolerable at POC scope; must be revisited before moving to production |

The distinction matters: a `[Demo-Safe Boundary]` item may stay forever for demo
deployments. A `[Gated Future Work]` item **must** land before its trigger feature ships.
An `[Accepted Risk]` item has a named owner and a stated justification — it is owned
risk, not unowned risk.

Primary files:

```text
LIMITATIONS.md
DECISIONS.md (gate conditions reference decision IDs)
docs/specs/21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md (gated mitigations)
docs/FUTURE_ENHANCEMENTS.md
```

---

## 2. Domain Walkthrough

### AI Limitations

- AI output is treated as untrusted until it passes all four guardrail layers (schema, output policy, evidence grounding, action safety). This is a `[Demo-Safe Boundary]` design choice — the deterministic demo provider cannot generate real-world errors, but the guardrail pipeline is positioned to catch them when a real LLM is used.
- ThreatPrism does not determine final truth. Analyst review is required. `[Demo-Safe Boundary]`

---

### Action Limitations

Real remediation is blocked: endpoint isolation, account disablement, firewall blocking,
email deletion, token revocation. Only recommendations, simulations, and dry-run planning
are allowed. This is a **product decision** (D-010, "Avoid" treatment), not a technical
limitation. It would require reopening D-010 and the relevant threat treatments before
any real action is built.

---

### SOAR Limitations

- Demo mode must not require live SOAR credentials. `[Demo-Safe Boundary]`
- Parallel SOAR triage must not block incident response. `[Demo-Safe Boundary]`
- Callback posting is `[Gated Future Work]` — implement only after safe intake and
  reporting are stable and relevant threat treatments are re-opened.

---

### Healthcare Safeguard Limitations

- The safeguard is a detection-and-tokenization layer, not a HIPAA compliance claim,
  HITRUST certification, or legal de-identification determination. `[Demo-Safe Boundary]`
- Context-aware rules may miss PHI when health-context vocabulary is absent. `[Accepted Risk]` — tolerable for fake-data POC; requires legal assessment for real PHI.
- Production identity-to-role enforcement for healthcare views is `[Gated Future Work]` (D-038).

---

### Auth & Identity Limitations

Not implemented at this scope:

| Item | Category | Gate Trigger |
|------|----------|-------------|
| OAuth/OIDC redirect flows | `[Gated Future Work]` | D-038/D-039/D-040 implementation slice |
| Live JWKS download | `[Gated Future Work]` | Explicit approval + D-039 re-open |
| Entra ID integration | `[Gated Future Work]` | Explicit approval + threat treatment update |
| Production RBAC/ABAC claim mapping | `[Gated Future Work]` | Production identity slice |
| Break-glass access governance | `[Gated Future Work]` | Production identity slice |

---

### GRC Limitations

- HITRUST-aligned control category mapping only.
- Does NOT provide HIPAA compliance, HIPAA certification, HITRUST compliance, HITRUST
  certification, licensed HITRUST control implementation, or audit opinion.
- All mappings are evidence organization aids, not compliance determinations. `[Demo-Safe Boundary]`

---

### Dataset & Demo Data Limitations

- Demo data must be fake. No real tenant IDs, workplace names, customer names, users,
  hosts, domains, IPs, secrets, or operational details. `[Demo-Safe Boundary]`
- The synthetic fixture factory is local-only tooling — not a download manager, runtime
  data model, or approval mechanism. `[Demo-Safe Boundary]`
- Model training and fine-tuning are out of scope (Avoid treatment, D-041 register). `[Gated Future Work]` if fine-tuning is ever added.

---

### CSI/RGOI Limitations

The read-only CSI/RGOI foundation is not:

- Unrestricted AI memory
- Production RAG
- A knowledge-base approval workflow
- Production multi-tenancy

Not implemented:

| Item | Category |
|------|----------|
| CSI write APIs | `[Gated Future Work]` |
| Autonomous memory persistence | `[Gated Future Work]` |
| Trust mutation API | `[Gated Future Work]` |
| Autonomous suppression publication | `[Gated Future Work]` |
| Live LLM, RAG, SOAR, cloud, or enrichment calls in CSI | `[Gated Future Work]` |

Replay is scaffolding only. It returns governed inputs and a deterministic hash. It
does not re-run a model or mutate state.

---

## 3. The Gate Trigger Pattern

A "gate trigger" is a named condition that, when met, requires re-opening a limitation
before the associated feature can be built. The format is always:

```text
[Feature] requires re-opening [D-XXX or treatment ID] before implementation.
```

Key gate triggers to know:

| Trigger | What It Opens |
|---------|--------------|
| Real LLM provider integration | Semantic firewall enablement (I4/OT-7); LLM DoS controls (L5/OT-L3); CSI/RGOI RAG (L2/OT-L1) |
| Non-demo persistence (PostgreSQL) | SQLite blob tampering mitigation (T1/OT-1); audit retention and tamper-evidence (R1/RR-R1/OT-8) |
| Real PHI/ePHI data flows | Full HIPAA de-identification assessment; LINDDUN threat set re-evaluation |
| External OIDC / live JWKS | D-039; live IdP integration slice |
| Multi-tenancy | D-006 re-open; entire auth and data isolation model |
| Fine-tuning pipeline | L4/OT-L2 training data poisoning treatment |
| Real SOAR callbacks | Callback posting slice; D-007 re-open with adapter design |

The pattern is explicit: **the gate condition is the implementation contract**. A feature
that would trigger a gate cannot ship without closing the gate first.

---

## 4. Operator Readiness Checklist

If you are evaluating ThreatPrism for a real deployment, these are the gaps you must
address before using it with non-demo data:

```text
Identity & Access
  □ Replace API_AUTH_MODE=demo_key with external_oidc
  □ Provision real OIDC issuer, audience, and JWKS endpoint
  □ Configure claim-to-role mapping for your identity provider
  □ Enable live JWKS verification (re-opens D-039)
  □ Implement break-glass access governance

Persistence
  □ Evaluate PostgreSQL vs. SQLite for your scale (re-opens D-012)
  □ Implement tamper-evident audit log with retention policy (re-opens T1/OT-1)
  □ Add database migration tooling if moving from JSON blobs to normalized schema

AI & Guardrails
  □ Integrate real LLM provider (re-opens I4/OT-7, L2/OT-L1, L5/OT-L3)
  □ Enable semantic firewall for prompt injection detection (requires real LLM gate)
  □ Evaluate PROHIBITED_PATTERNS refresh cadence for your threat landscape

Healthcare & Compliance
  □ If real PHI flows through: engage legal review; do not claim HIPAA compliance
  □ If GRC mapping is used: label all outputs as advisory evidence alignment only

Operations
  □ Add dedicated worker/queue for triage (re-opens D-019)
  □ Add deployment hardening (reverse proxy, TLS, rate limiting at edge)
  □ Add monitoring, alerting, and operational runbooks
  □ Replace Docker SQLite volume with production-grade persistence
```

---

## ⚖️ Decisions & Trade-offs

### Decisions Touched

| Decision | Statement | Why It Matters Here |
|----------|-----------|---------------------|
| D-025 | North Star is the directional architecture guide | `LIMITATIONS.md` is the inverse of the North Star: where the North Star says where things are going, the limitation register says where things are not yet |
| D-027 | Every implementation slice must close with documentation and learning updates including `LIMITATIONS.md` | Ensures limitations stay current as new slices ship; a stale limitation register is as dangerous as stale code |

### What We Explicitly Rejected

- **A single "known issues" list without categories:** Mixing "won't do" (boundary decisions) with "not yet" (gated work) with "accepted gap" (risk sign-off) makes it impossible to prioritize. The three-category model forces each limitation to have an explicit disposition.
- **Hidden limitations in code comments:** Limitations documented only in code are invisible to operators, reviewers, and future agents starting from `START_HERE.md`. The register is the searchable surface.

### Trade-off Log

| Choice Made | What We Gained | What We Gave Up |
|-------------|----------------|-----------------|
| Explicit gate trigger per gated item | Clear implementation contract; no feature can silently skip its gate | Authors must know and name the gate when adding a limitation; requires familiarity with the threat register |
| Separate `LIMITATIONS.md` from `DECISIONS.md` | Each file has a clear purpose; decisions are choices made, limitations are gaps accepted | Two files to keep in sync; a new decision often implies a new limitation |

### Future Gate Conditions

This lesson's content evolves when:

- **A gated item ships** → remove its `[Gated Future Work]` entry from `LIMITATIONS.md` and update this lesson
- **A new accepted risk is recorded** → add its `[Accepted Risk]` entry with owner and justification

### Limitations in Scope

- `[Demo-Safe Boundary]` This lesson describes POC-scope limitations; the register must be re-evaluated in its entirety before any production deployment
- `[Accepted Risk]` The limitation register is maintained manually; it can fall out of sync with the codebase if slice closeout documentation is skipped (D-027 addresses this)

---

## Interview Prep

**Q: What is the difference between a `[Demo-Safe Boundary]` and a `[Gated Future Work]` limitation?**

A: A Demo-Safe Boundary is a deliberate scope decision — the limitation is acceptable
for demo use and might stay that way indefinitely. A Gated Future Work item is a
commitment: the feature must not be built until the named gate condition is met and the
relevant threat treatment is re-opened. Confusing the two leads to either building
production features prematurely or deferring things that were actually planned.

**Q: How does an operator know what they need to add before using ThreatPrism with real data?**

A: The limitation register is the entry point. Every `[Gated Future Work]` and
`[Accepted Risk]` entry represents a gap that must be addressed. The operator
readiness checklist in this lesson aggregates the key items by domain. The threat
treatment register (`docs/specs/21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md`)
provides the detailed gate conditions.

**Q: Why are some risks "accepted" rather than mitigated?**

A: Risk acceptance is a deliberate choice, not neglect. An accepted risk has a named
owner, a justification, and an explicit scope (POC only). The classic example here is
unsalted SHA-256 for hash chain tokens — the blast radius of a hash collision in a
fake-data demo is near zero, and adding salting would require a migration for zero real
benefit. The acceptance record makes this reasoning transparent and revisitable.
