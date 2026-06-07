# 🔄 Lesson 44 — Trade-off Patterns Across the System

> **Goal:** Recognize the five recurring trade-off patterns that appear in ThreatPrism's
> design decisions, understand what each pattern solves and what it costs, and apply
> them to new design questions.
> **Time:** ~30 min · **Prerequisites:** Lesson 42 (decisions), Lesson 43 (limitations).

---

## 1. What This Lesson Is For

Individual lessons explain the trade-offs of their own component. This lesson lifts to
the system level and names the five patterns that recur across multiple slices. Once
you recognize them, you can:

- Quickly explain an unfamiliar design choice by mapping it to a known pattern
- Predict what a new feature's constraints will be before reading the spec
- Ask the right questions during design review ("is this a reverse-deny default? what's
  the trigger to enable it?")

---

## 2. Pattern 1 — Demo-Safe Boundary

**Definition:** Accept a simplification that is adequate for a single-org fake-data demo
and explicitly gate the production-grade alternative on a named trigger condition.

**What it solves:** Avoids over-engineering POC scope while keeping the production path
open. The simplification is not a shortcut — it is a deliberate choice with a documented
exit condition.

**Where it appears:**

| Component | Simplification | Gate Trigger |
|-----------|---------------|-------------|
| Persistence | SQLite + JSON blobs | PostgreSQL gate (D-012) |
| Auth | Demo API keys | `external_oidc` mode (D-038/D-039/D-040) |
| Background tasks | In-process FastAPI `BackgroundTask` | Dedicated worker queue (D-019) |
| Audit chain | Unsalted SHA-256 hash chain | Non-demo persistence (T1/OT-1) |
| LLM provider | Deterministic demo provider | Real LLM integration (D-009) |
| Dashboard | Local fake-data FastAPI-served UI | Production deployment (D-035) |

**Cost:** The simplification is temporary by design. If the gate trigger is hit without
explicitly re-opening the decision, the simplification becomes a production liability
rather than a scoped POC choice.

**Canonical code location:**
```python
# config.py
class Settings(BaseSettings):
    env: str = "demo"
    database_url: str = "sqlite:///./data/threatprism.db"
    llm_provider: str = "deterministic_demo"
    allow_real_actions: bool = False
```

The `demo` default is not a missing production default — it is a deliberate gate on the
`env` value that `validate_runtime()` then checks.

---

## 3. Pattern 2 — Detector-not-Gate

**Definition:** Build a detection layer that raises a signal without blocking the
pipeline. The signal escalates to human review or upgrades to a gate only when the
precondition for safe gating is met.

**What it solves:** Allows a probabilistic or potentially-false-positive detection layer
to add value immediately, without introducing a block path that could DoS legitimate
traffic.

**Where it appears:**

| Component | Detector | Condition to promote to gate |
|-----------|----------|------------------------------|
| Semantic prompt-injection firewall (spec 32) | `SemanticFirewall` scores injections; `max(deterministic, semantic)` determines action | Real LLM integration; enables `SemanticAction.QUARANTINE` path (I4/OT-7) |
| Healthcare safeguard context awareness | `requires_context=True` detectors fire only when `HEALTH_CONTEXT_TERMS` co-present | Never gates alone; always combined with deterministic pattern match |
| CSI/RGOI trust scoring | Trust scores are surfaced and logged, not used as access gates | No current gate promotion planned for POC scope |

**Cost:** Novel attack patterns that neither layer detects remain a residual risk. The
detector pattern deliberately accepts this residual to avoid blocking legitimate use.

**The key invariant:** A detector-not-gate layer is **byte-identical** to no-detector
when disabled. `SemanticFirewall` disabled → pipeline unchanged. This is tested
explicitly: `test_semantic_firewall_disabled_is_byte_identical()`.

**Canonical code location:**
```python
# service.py — the semantic firewall is a detector, not a replacement for the deterministic gate
if self._semantic_firewall:
    semantic_result = self._semantic_firewall.analyze(prepared)
    if semantic_result.action in (SemanticAction.QUARANTINE, SemanticAction.FLAG):
        # escalate — but the deterministic firewall's quarantine flag is still the hard gate
        ...
```

---

## 4. Pattern 3 — Deterministic over Probabilistic at Trust Boundaries

**Definition:** At every hard trust boundary (persist, send to model, render to role,
execute action), use a deterministic check — not a probabilistic one — as the final
gate.

**What it solves:** Probabilistic systems (ML classifiers, LLM judges) have false
negative rates. A trust boundary is the wrong place to accept a non-zero false-negative
rate on a safety property.

**Where it appears:**

| Trust Boundary | Deterministic Gate | Probabilistic Layer (advisory) |
|---------------|-------------------|-------------------------------|
| Model-visible payload | Prompt firewall regex + `REHYDRATABLE_TYPES` constant | Semantic firewall (detector-not-gate) |
| Report persistence | `PROHIBITED_PATTERNS` regex + schema validation + `validate_report_evidence()` | None at this layer |
| Action execution | `enforce_action_safety()` checks `real_action_executed` boolean | None — the field is schema-typed |
| Knowledge promotion (RGOI) | Human role check + audit deny before any write | AI-proposed candidates (non-authoritative) |
| Role-view rendering | `ROLE_VIEW_POLICY` static dict lookup | None — the policy is an exact set |

**The governing principle (from D-037):** "Humans own truth. AI cognition is
non-authoritative unless approved through a human governance path." The human gate is
deterministic; the AI proposal is probabilistic. The deterministic gate always wins.

**Canonical code location:**
```python
# csi/learning_loop.py — the human gate is explicit and deterministic
def _enforce_human_gate(self, approver_role, proposal_id):
    if approver_role not in self.approver_roles:
        ...audit deny...
        raise PermissionError("The AI proposes; a human promotes.")
```

---

## 5. Pattern 4 — Provider-Agnostic Adapter

**Definition:** Any integration with an external system (SOAR, LLM, threat intelligence,
identity) is implemented through an adapter or Protocol interface. The core model never
imports a provider directly.

**What it solves:** Avoids lock-in to a single vendor and enables Microsoft-first
integrations (D-008) without making the core model Microsoft-only (North Star question 7
and 8 are separate for this reason).

**Where it appears:**

| Integration | Adapter Pattern | Core Interface |
|-------------|----------------|----------------|
| SOAR intake | `GenericSoarAdapter` subclasses in `soar/generic.py` | `normalize_soar_payload()` dispatches by source |
| LLM provider | `TriageProvider` Protocol in `llm/providers.py` | `get_provider()` factory; core never calls OpenAI directly |
| Threat intelligence | Stubs in `enrichment/stubs.py` returning `not_configured` | Interface defined; live providers are future adapters |
| Auth mode | `API_AUTH_MODE` setting selects handler in `auth/demo.py` | `authorize_role_view()` is the single auth surface |
| Identity (future) | `external_oidc` mode calls `verify_production_bearer_token()` | Local fake-JWKS implementation; live IdP is a future adapter |

**Cost:** Adapter indirection adds one layer of abstraction. For a demo system, this
sometimes feels over-engineered. The cost pays off the first time a SOAR provider
changes its payload schema — only the adapter needs updating, not the core service.

**Canonical code location:**
```python
# llm/providers.py — the Protocol makes the interface explicit
class TriageProvider(Protocol):
    def generate_report(self, case: CaseRecord, settings: Settings) -> TriageReport: ...

def get_provider(name: str, settings: Settings) -> TriageProvider:
    if name == "deterministic_demo":
        return DeterministicDemoProvider()
    # future: if name == "openai": return OpenAIProvider(settings)
    raise ValueError(f"Unknown provider: {name}")
```

---

## 6. Pattern 5 — Reverse-Deny Default

**Definition:** Features that could cause harm if accidentally enabled are disabled by
default and require explicit opt-in. The disabled state is the safe state. Enabling
requires a positive configuration change, not the absence of a configuration change.

**What it solves:** Prevents accidental activation of dangerous features through missing
configuration, default inheritance, or configuration copy-paste errors.

**Where it appears:**

| Feature | Default State | Opt-In Mechanism |
|---------|--------------|-----------------|
| Real actions | `ALLOW_REAL_ACTIONS=false` | Not yet buildable; D-010 "Avoid" |
| Demo auth with no acknowledgement | `API_AUTH_MODE=none` requires `THREATPRISM_LOCAL_DEV_ACK=true` | Must be explicit; startup warns |
| Production auth modes in production env | `validate_runtime()` rejects `none` and `demo_key` in prod | Reversed: only `external_oidc` accepted |
| Demo seed on startup | `THREATPRISM_DEMO_SEED` defaults off; refused in production | Explicit env var required |
| RGOI learning loop | `KnowledgeLearningLoop(enabled=False)` by default | `KnowledgeLearningLoop(enabled=True)` required |
| Semantic firewall | `SEMANTIC_FIREWALL_ENABLED=false` by default | Explicit setting; requires real-LLM gate |
| Live JWKS fetch | `PRODUCTION_IDENTITY_JWKS_FETCH_ENABLED=false` required | Gated; live IdP integration slice |

**The invariant:** "disabled = no behavior." A disabled feature must be byte-identical to
not having the feature. This makes the disabled state testable and makes accidental
activation detectable.

**Canonical code location:**
```python
# csi/learning_loop.py
def propose(self, ...):
    if not self.enabled:
        raise RuntimeError("KnowledgeLearningLoop is disabled. Set enabled=True to use it.")
```

---

## 7. Pattern Cross-Reference

Which patterns apply to each major component:

| Component | Demo-Safe | Detector-not-Gate | Det > Prob | Provider-Agnostic | Reverse-Deny |
|-----------|:---------:|:-----------------:|:----------:|:-----------------:|:------------:|
| Case schemas & service | ✅ | | ✅ | ✅ | ✅ |
| Prompt firewall | | ✅ | ✅ | | |
| Healthcare safeguards | ✅ | ✅ | ✅ | | |
| SQLite persistence | ✅ | | | ✅ | |
| Access control & auth | ✅ | | ✅ | ✅ | ✅ |
| Eval harness | ✅ | | ✅ | | ✅ |
| LLM provider | ✅ | | ✅ | ✅ | ✅ |
| CSI/RGOI | ✅ | ✅ | ✅ | | ✅ |
| Demo seeder | ✅ | | ✅ | | ✅ |

---

## ⚖️ Decisions & Trade-offs

### Decisions Touched

| Decision | Statement | Why It Matters Here |
|----------|-----------|---------------------|
| D-010 | `ALLOW_REAL_ACTIONS=false` by default | Canonical example of Reverse-Deny Default combined with Demo-Safe Boundary |
| D-009 | LLM layer must be provider-agnostic | Canonical example of Provider-Agnostic Adapter |
| D-026 | Role rendering is not authorization until identity-to-role enforcement exists | Explains why Deterministic-over-Probabilistic applies at the role-view trust boundary |
| D-037 | CSI/RGOI is read-only; humans own truth | Canonical example of Deterministic-over-Probabilistic at the knowledge write boundary |

### What We Explicitly Rejected

- **One-size-fits-all "default deny" at every layer:** Some layers benefit from
  detection without blocking (Pattern 2), others need hard gates (Pattern 3). Applying
  reverse-deny to a detector layer would make the system unusable — a semantic classifier
  with a 5% false positive rate would block 1 in 20 legitimate cases.
- **Treating the five patterns as alternatives:** They are composable. A single component
  (e.g., the semantic firewall) can simultaneously be a Demo-Safe Boundary (disabled by
  default), a Detector-not-Gate (scores but doesn't block), and a Reverse-Deny Default
  (requires explicit opt-in to enable scoring).

### Trade-off Log

| Pattern | What It Gains | What It Costs |
|---------|--------------|---------------|
| Demo-Safe Boundary | No over-engineering for POC scope; clear production upgrade path | Every gate trigger must be explicitly managed; missed gates become production debt |
| Detector-not-Gate | Detection value without DoS risk from false positives | Residual false-negative risk accepted; novel bypasses may not be detected |
| Deterministic over Probabilistic | Hard safety guarantees at trust boundaries | Cannot catch semantic / paraphrased violations that deterministic rules miss |
| Provider-Agnostic Adapter | Swap providers without touching core logic; Microsoft-first without lock-in | Indirection adds a layer; adapter bugs are harder to trace than direct calls |
| Reverse-Deny Default | Accidental activation of dangerous features requires deliberate misconfiguration | Adds explicit opt-in friction for legitimate use; developers must know the enable flag |

### Future Gate Conditions

This lesson's patterns remain valid until:

- **A new architectural pattern is introduced** → add it as Pattern 6 and cross-reference it in the table
- **A pattern is retired** → remove it and document which decision re-opened it

### Limitations in Scope

- `[Demo-Safe Boundary]` This analysis covers POC-scope patterns; production patterns (e.g., circuit breakers, bulkheads, chaos engineering) are not yet in scope
- `[Accepted Risk]` Pattern recognition is a heuristic; a new component may combine patterns in a novel way that requires updating the cross-reference table

---

## Interview Prep

**Q: ThreatPrism's semantic firewall is built but default-off. Why build it at all?**

A: The Detector-not-Gate pattern explains this. The semantic classifier adds detection
signal that the deterministic regex cannot provide — it catches paraphrased injections
that don't match a known pattern. By building it as a detector now (byte-identical to
disabled when off), the team gets the architecture in place and proves it works (4/6
deepset rows detected at threshold 0.9). Enabling it as a gate requires only a
configuration change when the real-LLM gate opens, not a new implementation.

**Q: Why does ThreatPrism use a static `ROLE_VIEW_POLICY` dict rather than a database-backed RBAC system?**

A: The Deterministic-over-Probabilistic and Demo-Safe Boundary patterns both apply.
Role authorization is a trust boundary — it must be deterministic. A database-backed
RBAC system introduces a new data store, a new attack surface, and runtime query latency
at every authorization check. For single-org demo scope (D-006), a static dict is
sufficient, auditable, and version-controlled. The production RBAC path is left open
through the `external_oidc` mode (D-038), which maps verified external roles to
ThreatPrism effective roles.

**Q: Can you give an example of two patterns working against each other?**

A: Yes — Demo-Safe Boundary and Reverse-Deny Default can create friction. The demo
boundary wants `ALLOW_REAL_ACTIONS=false` to be the safe default; the reverse-deny
pattern wants enabling real actions to require an explicit opt-in. These goals are
aligned here, but consider the eval harness: the Demo-Safe Boundary accepts in-process
execution (no subprocess sandbox), which a strict reverse-deny default would prohibit.
The resolution is that reverse-deny applies to features that can cause external harm
(actions, auth modes, data writes), while the demo boundary accepts internal
simplifications (in-process eval) that are safe because the system is fake-data-only.
