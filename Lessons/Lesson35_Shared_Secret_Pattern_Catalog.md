# 🗂️ Lesson 35 — One Secret-Pattern Catalog, Many Consumers (DRY Without Coupling)

> **Goal:** Understand why duplicated detection patterns are a *security* bug (not
> just a code-smell), how to give four consumers — including a standalone script
> that must not import the package — a single source of truth, and why "one
> catalog" does **not** mean "everyone uses every pattern."
> **Time:** ~25 min · **Prerequisites:** Lesson 04 (guardrails), Lesson 05
> (healthcare safeguards), Lesson 29 (dev-workflow hooks).

Implements the spec 34 §3 reuse opportunity.

---

## 1. 🎯 The problem: the same regex, copied into four places

Secret-shaped regexes had quietly spread across the repo:

| Site | What it guards |
|---|---|
| `guardrails/healthcare.py` `SECRET_RULES` | Stage-1 tokenization of **inbound** SOAR telemetry |
| `guardrails/tokenization.py` `secret_like` | Stage-2 `[REDACTED_SECRET]` tokens |
| `guardrails/policy.py` `PROHIBITED_PATTERNS` | leaked-secret shapes in **LLM output** |
| `tools/hooks/_common.py` | secrets the **coding assistant** tries to write to disk |

The `sk-…|xox…|AIza…` provider-key regex was **byte-for-byte identical** in
`healthcare.py` and `tokenization.py`. The dev-hook maintained a *separate,
richer* list of nine patterns. Four lists, no shared source.

> SIEM analogy: it's the same detection logic copy-pasted into four correlation
> rules on four sensors. The day someone tightens one rule, the other three keep
> the old blind spot — and nobody notices until an incident.

---

## 2. 🔐 Why duplicated patterns are a *security* defect

This isn't cosmetic DRY. Divergent secret catalogs fail **asymmetrically and
silently**:

- The dev-hook blocks the assistant from committing a Stripe key, but the product
  tokenizer doesn't recognize that shape → the same secret sails through inbound
  triage un-redacted.
- Or the reverse: the product redacts a shape the hook lets land in a commit.

Either way the gap is invisible until exploited. A single catalog makes "what
counts as a secret" **one auditable list** with **one quarterly review**
(`docs/runbooks/PATTERN_REFRESH.md`) instead of four lists drifting on their own
schedules.

---

## 3. 🧩 The design: one catalog, named entries, per-consumer subsets

`src/threatprism/guardrails/secret_catalog.py` defines every secret regex **once**,
as `(name, regex)` pairs. The key insight is what it *doesn't* do: it does **not**
force every consumer to use every pattern.

```python
SECRET_PATTERN_SOURCES: list[tuple[str, str]] = [
    ("private_key_block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("aws_access_key_id", r"\bAKIA[0-9A-Z]{16}\b"),
    ...
    ("provider_token_prefix",  # the product runtime shape
     r"\b(?:sk-[A-Za-z0-9_-]{12,}|xox[baprs]-[A-Za-z0-9-]{12,}|AIza[0-9A-Za-z_-]{12,})\b"),
    ...
]
```

Consumers reference entries **by name** for the subset they need:

- `healthcare.py`: `SensitiveRule("secret", "api_key", pattern_for("provider_token_prefix"), 0.98)`
- `tokenization.py`: `("secret_like", pattern_for("provider_token_prefix"))`
- `policy.py`: `pattern_for("provider_token_prefix")` in `PROHIBITED_PATTERNS`
- the hook: the **full** `SECRET_PATTERNS` list

**Why subsets, not "everyone uses everything"?** Because the consumers have
*different threat models*:

- The **dev-hook** guards what the *assistant writes to disk* — a broad net (all
  nine patterns) is correct; a false positive just asks a human to manage the
  secret by hand.
- The **product tokenizer** guards *inbound SOAR telemetry* — over-tokenizing
  would permanently redact legitimate security data (an IP, a hash) the analyst
  needs to work the case. So it deliberately uses a **narrow** subset.

One source of truth ≠ one behavior. The catalog centralizes the *definitions*; each
consumer owns its *policy* about which definitions apply. That's the difference
between DRY and blindly coupling.

> Security-engineering takeaway: this is least-privilege applied to detection. The
> component touching the riskier surface (permanent redaction of real triage data)
> gets the *minimum* pattern set; the low-stakes surface gets the broad net.

---

## 4. 🪝 The hard part: sharing with a script that must not import the package

The dev-workflow hook has a non-negotiable design rule (spec 34 §6): it runs as a
plain `python tools/hooks/secret_block.py`, **standalone**, with **no
`threatprism` import** — so it works whether or not the package is installed, from
any working directory Claude Code invokes it.

So how does a standalone script share a catalog that lives inside the package?
**Load it by file path, not by import:**

```python
def _load_secret_catalog():
    import importlib.util
    path = REPO_ROOT / "src" / "threatprism" / "guardrails" / "secret_catalog.py"
    spec = importlib.util.spec_from_file_location("_tp_secret_catalog", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
```

`spec_from_file_location` executes the **single file** directly — it never triggers
`threatprism/__init__.py` or pulls in FastAPI/Pydantic. The catalog module is pure
(`import re` and a list, nothing else), so loading it standalone is cheap and
side-effect-free. That purity is what makes the file dual-loadable: the package
imports it normally, the hook execs it by path.

**Fail-open, deliberately.** If the catalog can't be loaded, the hook falls back to
*no* patterns and allows the write:

```python
try:
    _SECRET_CATALOG = _load_secret_catalog()
    SECRET_PATTERNS = _SECRET_CATALOG.SECRET_PATTERNS
except Exception:  # a broken catalog must never wedge the workflow
    _SECRET_CATALOG = None
    SECRET_PATTERNS = []
```

This matches the hooks' documented philosophy (Lesson 29): a hook bug must never
block all of the assistant's work. The trade-off — a missing catalog silently
disables secret blocking — is acceptable because the file is always in-repo and the
"never wedge the workflow" rule outranks it. The happy path is guarded by a test
(§5) so a real regression is caught in CI, not in production.

---

## 5. 🧪 The test that makes "stay in sync" structural

The whole point is that the two catalogs can't drift. So the regression test
asserts they are **identical** — loading the hook by path the same way Claude Code
does:

```python
def test_dev_hook_and_product_share_one_catalog() -> None:
    hook = _load_hook_common()  # path-load, no threatprism import
    assert _name_regex_map(hook.SECRET_PATTERNS) == _name_regex_map(secret_catalog.SECRET_PATTERNS)
```

If a future edit re-introduces a hook-local pattern, this fails immediately. The
other tests pin the product wiring (`tokenization.secret_like` *is* the catalog's
`provider_token_prefix`) and the catalog's actual detection (fake AWS/GitHub/
provider shapes match; a benign name doesn't).

This is the same lesson as Lesson 34's concurrency test and Lesson 32's authz
tests: **encode the invariant as a test, or it isn't really an invariant.**

---

## 6. ♻️ Behavior preservation — what changed and what didn't

A refactor that silently changes detection is a bug, not a refactor. So the change
was scoped precisely:

- **Unchanged byte-for-byte:** `healthcare.py` and `tokenization.py` regexes,
  detector names (`api_key`/`password` — they label the emitted
  `[SECRET:API_KEY:…]` tokens and feed `_confidence_for`), and confidences. The
  highest-risk surface (inbound tokenization of real triage data) is identical.
- **Broadened in the safe direction only:** `policy.py`'s output scan now also
  catches `xox…`/`AIza…` (was `sk-` only); the hook gained the
  `provider_token_prefix` shape. More detection, never less.
- **One test fixture updated on purpose:** `test_overclaim_regression.py` is a
  *coverage guard* that asserts every `PROHIBITED_PATTERNS` regex has a fixture —
  it's designed to force a paired update when a pattern changes. Updating its key
  is the guard working, not a workaround.

The historical slice added four catalog tests and kept the then-current full suite,
eval harness, and demo-safety checks passing. The active suite count now lives in
[../docs/VALIDATION_BASELINE.md](../docs/VALIDATION_BASELINE.md).

---

## 7. 🎤 Interview talk track

> "We had the same secret-detection regex copy-pasted across four files — two
> product guardrails, the output-policy scan, and a standalone dev-workflow hook.
> That's a security defect, not just a smell: divergent catalogs fail silently and
> asymmetrically — the hook blocks a key shape the product doesn't redact, or vice
> versa. I pulled every secret regex into one catalog module and had each consumer
> reference named entries. The subtle part was the standalone hook: it can't import
> the package by design, so it loads the catalog by file path via
> `importlib.spec_from_file_location`, which execs just that one pure module without
> triggering the package. I deliberately kept it as *named subsets* rather than
> forcing identical behavior — the product tokenizer touches real inbound triage
> data, so over-detection there permanently redacts data an analyst needs; it gets
> the narrow set, the dev-hook gets the broad net. Least privilege applied to
> detection. And I encoded 'the two catalogs must stay identical' as a test, so it
> can't drift again."

---

## 8. 🗂️ Quick reference card

| Thing | Value |
|---|---|
| Source of truth | `src/threatprism/guardrails/secret_catalog.py` |
| Product consumers | `healthcare.py` `SECRET_RULES`, `tokenization.py` `secret_like`, `policy.py` |
| Standalone consumer | `tools/hooks/_common.py` (file-path load, fail-open) |
| Edit patterns | **only** in `secret_catalog.py`; refresh via `PATTERN_REFRESH.md` |
| Stay-in-sync guard | `tests/test_secret_catalog.py` |
| Design principle | one catalog, per-consumer named subsets (two threat models) |
| Behavior | healthcare/tokenization unchanged; policy + hook broadened safely |
| Validation | Historical slice pass; current count in [VALIDATION_BASELINE.md](../docs/VALIDATION_BASELINE.md) |
