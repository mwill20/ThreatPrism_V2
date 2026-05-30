# 🎓 Lesson 27: Three Customs Lanes for Untrusted Data — Dataset Onboarding & Fixture Source Contracts

## 🛡️ Welcome Back, Security Analyst!

Ever onboarded a new third-party threat-intel feed and asked the obvious questions before you let it touch production — *who owns this data, what's its license, and what's hiding inside it that I don't want in my SIEM?* 🔍 Today we're exploring **ThreatPrism's dataset onboarding system** (`src/threatprism/demo/seeding.py` + `tools/fixture_factory/adapters/*.py`) — the "customs checkpoint" that lets reviewed third-party data into the demo while guaranteeing nothing forbidden crosses the border.

This lesson builds on **Lesson 26** (the original single-source Dataset-Backed Demo Seeder) and **Lesson 22** (curated fixture promotion). Lesson 26 taught you *one* lane. Here we add two more lanes, a forgery-proof passport check, and a strict "leave your ID at the door" rule for foreign data.

---

## 🎯 Learning Objectives

By the end of this lesson you will be able to:

- Explain why ThreatPrism runs **two parallel fixture contracts** (`CuratedFixtureSource` vs `CuratedDatasetSource`) instead of one
- Describe how the **code-authoritative license allowlist** stops a tampered manifest from self-certifying a license
- Compare the **three different safety treatments** applied to the Synthea, deepset, and OTRF families — and justify why each is different
- Defend the **drop-vs-tokenize** decision as a defense-in-depth choice, not an arbitrary one
- Run the **off-by-default `LocalDatasetSource`** dev loop and explain why it is gated three ways

**Time estimate:** 35 minutes | **Prerequisites:** Lesson 16 (Fixture Factory), Lesson 22 (Curated Promotion), Lesson 26 (Demo Seeder)

---

## 🧠 What This Component Does — Plain English

ThreatPrism's demo needs realistic cases to triage. Hand-authored fake cases only go so far, so the project onboards small, reviewed samples from real third-party datasets and replays them through the real intake pipeline. The problem: third-party data carries two kinds of risk that fake data never does — **licensing risk** (am I allowed to redistribute a derivative of this?) and **content risk** (does a raw row contain a real-looking hostname, SSN, or attacker payload I must not commit?).

The onboarding system answers both. Each source family gets a **dedicated adapter** that converts raw rows into sanitized, ThreatPrism-native case fixtures, and a **manifest entry** recording its provenance and license review. A runtime loader then seeds only the fixtures whose review status is approved — and crucially, the list of *acceptable license statuses lives in code*, so the manifest (which an attacker could edit) cannot grant itself a license it was never given.

**Real-world analogy:** It's customs and immigration at an airport. Different travelers go through different lanes — a citizen (synthetic data) gets a quick wave-through, a diplomatic pouch (attacker injection text) is sealed but explicitly allowed through un-opened for a reason, and a foreign visitor from an untrusted country (lab telemetry) gets a full search where anything that could identify them is confiscated at the gate. And the passport stamp that says "approved" is issued by the border agency's own system (code) — not printed by the traveler on their own passport (the manifest).

---

## 🔵🟡🔴 Career Lens — Three Perspectives on This Component

### 🔵 Analyst Lens — What a SOC Analyst Sees Here

You already do this every time a new feed is proposed for your SIEM. Before a vendor's IOC feed gets ingested, someone checks the licensing/TOS, someone samples the data for false positives and PII, and someone decides which fields actually get parsed into the correlation engine versus dropped on the floor. ThreatPrism's three "lanes" map directly to three feeds you'd treat differently: a synthetic test feed you trust (Synthea), a malware-sample feed where the *payload itself* is the point and must survive intact (deepset injection text), and a raw endpoint-telemetry feed full of real hostnames and account SIDs that you'd never replay verbatim into a shared system (OTRF).

**SOC parallel:** This is feed onboarding governance — exactly the review gate you apply before a new threat-intel source or log source is allowed into FortiSIEM/Sentinel, expressed as code instead of a ticket.

---

### 🟡 Engineer Lens — What a Cybersecurity Engineer Builds Here

The design decision to own here is the **parallel-contract + code-authoritative trust gate**. Rather than weaken the existing, known-good `CuratedFixtureSource` (which deliberately *rejects* third-party licenses) to admit third-party data, the engineer built a *second* source class, `CuratedDatasetSource`, with its own stricter gate. Both reuse the same low-level reader, but the trust policy is separated. The accepted-license allowlist is a `frozenset` in code (`DATASET_ALLOWED_LICENSE_REVIEW`), not a manifest field — a textbook application of *don't let data certify itself*. Adding a new source is an **adapter (Strategy pattern)** plus a reviewed one-line allowlist change, both of which show up in code review.

**Engineering decision to own:** Why the license allowlist lives in code and not the manifest — because the manifest is attacker-mutable data, and a trust decision must be anchored in something the attacker can't edit without a code review.

---

### 🔴 AI Security Engineer Lens — What an AI/ML Security Engineer Watches For

This is the **data-poisoning and training-data-provenance boundary**. Every fixture here is replayed through `create_case` + `run_triage`, so anything that survives onboarding becomes model-visible input. Two ML-specific surfaces matter: (1) **supply-chain integrity** — a malicious or tampered dataset could smuggle prompt-injection or mislabeled content into the corpus that later trains or evaluates a model; the in-code allowlist + fail-closed projection + `sha256` source hashing are the provenance controls. (2) **The deepset lane is a deliberate live-payload exception** — it retains un-redacted injection text *on purpose* so the runtime firewall is exercised, which means the corpus itself is a curated adversarial dataset. An AI security engineer must ensure that exception is source-scoped and never silently inherited by another family.

**AI security surface:** Training/eval-data supply-chain poisoning — the risk that an onboarded third-party dataset injects adversarial or identifying content into the model's data path, mitigated here by a code-anchored trust gate and per-family sanitization rather than blanket trust.

---

## 🗺️ Where This Fits in the System

```
📁 external_datasets/ (gitignored raw)        🛂 ONBOARDING (dev-time)
   │   synthea.csv / deepset.parquet / OTRF.json
   ▼
🏭 tools/fixture_factory/adapters/*.py  ──►  sanitize ──►  fixtures/curated_datasets/*.jsonl
                                                              + manifest.json (provenance)
   ────────────────────────────────────────────────────────────────────  (runtime)
🔓 CuratedDatasetSource ── license allowlist gate ──►  DemoSeeder.seed()
                                                          │
                                                          ▼
   real create_case() + run_triage()  ──►  four-layer guardrails  ──►  SQLite demo DB
                                      ▲
                              [THIS LESSON]
```

If this onboarding gate fails open, unreviewed or unlicensed third-party content — possibly with real identifiers or unvetted injection payloads — reaches the demo database and every downstream view. The gate is the difference between "reviewed synthetic realism" and "we committed someone's lab hostnames to a public repo."

---

## 🔑 Key Concepts

### Parallel Fixture Contracts
`CuratedFixtureSource` (over `fixtures/curated/`) is for hand-authored fakes and **rejects** all third-party licenses. `CuratedDatasetSource` (over `fixtures/curated_datasets/`) is a separate contract for reviewed third-party derivatives. Splitting them means admitting third-party data never weakened the known-good fake-only boundary — the two trust policies evolve independently.

### Code-Authoritative License Allowlist
`DATASET_ALLOWED_LICENSE_REVIEW` is a `frozenset` of accepted `license_review_status` values, defined in `seeding.py`. The manifest only *describes* a fixture's license; the code *decides* whether that status is acceptable. A tampered manifest cannot self-certify a license it was never granted — the security property is "data describes, code decides."

### Three Treatments, Three Risk Profiles
The same pipeline applies different scrubbing per family because the *threat* differs: Synthea (column allowlist + tokenize the SSN), deepset (retain injection text un-redacted, a scoped exception), OTRF (fail-closed field allowlist that **drops** every identifier). One size does not fit all data.

### Drop vs Tokenize (Defense-in-Depth)
*Tokenizing* lets a value into the pipeline and relies on a detector to find and replace it (default-allow). *Dropping* via an allowlist means the field never enters the fixture at all (default-deny). For foreign lab telemetry full of identifier shapes no detector is guaranteed to catch (Windows SIDs), dropping is strictly stronger.

### Off-by-Default Local Source
`LocalDatasetSource` replays uncommitted `.jsonl` staging under gitignored `external_datasets/` for fast local iteration. Because that data is unreviewed, it is gated three ways: never the default `--source`, never in `--source all`, never in the startup hook, and refused in production.

---

## 📝 Code Walkthrough

### The Forgery-Proof Passport Stamp

```python
# src/threatprism/demo/seeding.py — Lines 41-47 (DATASET_ALLOWED_LICENSE_REVIEW)
DATASET_ALLOWED_LICENSE_REVIEW = frozenset(
    {
        "approved_third_party_apache2_synthetic",
        "approved_third_party_mit_lab_telemetry",
    }
)
```

```python
# src/threatprism/demo/seeding.py — Lines 240-243
@staticmethod
def _is_dataset_seedable(entry: dict[str, Any]) -> bool:
    if not CuratedFixtureSource._is_demo_seedable(entry):
        return False
    return entry.get("license_review_status") in DATASET_ALLOWED_LICENSE_REVIEW
```

**Line-by-line breakdown:**

| Lines | What it does | Why it was designed this way |
|-------|-------------|------------------------------|
| 41-47 | Defines the two accepted license statuses as an in-code `frozenset` | The trust anchor lives in source, not in the manifest the data ships with — a tampered manifest can claim any status string, but only these two pass |
| 240-242 | Reuses the base demo-seedable checks (review status, no raw-source-committed, etc.) | Composition, not duplication — the dataset gate is *strictly additive* on top of the curated gate |
| 243 | Final gate: the manifest's `license_review_status` must be a member of the in-code set | "Data describes, code decides." A new license is a reviewed code change, never a manifest edit |

**Design pattern used:** Allowlist (default-deny) trust gate. The manifest is treated as untrusted input; acceptance is decided by code the attacker would have to get through review to change.

### Lane 1 — Synthea: Column Allowlist + Tokenize the SSN

```python
# tools/fixture_factory/adapters/synthea_adapter.py — Lines 30-46 (SAFE_COLUMNS)
SAFE_COLUMNS = frozenset(
    {"Id", "SSN", "GENDER", "MARITAL", "RACE", "ETHNICITY",
     "HEALTHCARE_EXPENSES", "HEALTHCARE_COVERAGE"}
)

def _project_safe_columns(row: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in row.items() if key in SAFE_COLUMNS}
```

Synthea is generated-synthetic, so names/addresses are fake — but regex PHI detection can't reliably catch a generated street address, so the adapter drops everything except an allowlist of non-identifying demographics, **keeping** the SSN specifically so the Stage-1 healthcare safeguard can demonstrate tokenization (`[POTENTIAL_PII:SSN:...]`). This is the only lane that intentionally keeps an identifier in order to *show the tokenizer working*.

### Lane 2 — deepset: Keep the Attacker Payload Intact (On Purpose)

```python
# tools/fixture_factory/adapters/deepset_adapter.py — Line 107
# apply_prompt_firewall=False: keep the injection text intact (see module docstring).
sanitized = sanitize_fixture_source(row, case_id=fixture_id, apply_prompt_firewall=False)
```

> ⚠️ **Common pitfall:** This looks like a sanitization *bug* — the prompt firewall is deliberately skipped. It is the single source-scoped exception in the whole system: the injection `text` must survive un-redacted so the *runtime* firewall has live content to detect on replay. Credential, healthcare, and infrastructure sanitization still apply (see `sanitize_fixture_source`, `sanitizers.py` line 50). Never copy `apply_prompt_firewall=False` to another adapter.

### Lane 3 — OTRF: Fail-Closed Allowlist That Drops Identifiers

```python
# tools/fixture_factory/adapters/otrf_adapter.py — Lines 57-74 (SAFE_FIELDS)
SAFE_FIELDS = frozenset(
    {"EventID", "Channel", "SourceName", "Category", "Severity", "Task",
     "RuleName", "Opcode", "EventType", "EventTypeOrignal", "tags",
     # Timestamps are not identifiers; retained for SOC timeline realism.
     "EventTime", "UtcTime"}
)

SID_PATTERN = re.compile(r"S-1-5(?:-\d+){1,}", re.I)
USER_PATH_PATTERN = re.compile(r"(?i)([A-Za-z]:\\Users\\)[^\\\"]+")
```

```python
# tools/fixture_factory/adapters/otrf_adapter.py — Lines 99-122
def _scrub_identifiers(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _scrub_identifiers(entry) for key, entry in value.items()}
    if isinstance(value, list):
        return [_scrub_identifiers(entry) for entry in value]
    if isinstance(value, str):
        scrubbed = SID_PATTERN.sub("[REDACTED_SID]", value)
        scrubbed = USER_PATH_PATTERN.sub(r"\1[REDACTED_USER]", scrubbed)
        return scrubbed
    return value

def _project_safe(row: dict[str, Any]) -> dict[str, Any]:
    projected: dict[str, Any] = {key: row[key] for key in row if key in SAFE_FIELDS}
    return _scrub_identifiers(projected)
```

OTRF is **MIT-licensed lab telemetry**, not synthetic. Raw events carry real-looking lab identifiers — `Hostname: WORKSTATION5.theshire.local`, `UserID: S-1-5-21-...`, `AccountName`, `Domain`, `port`. The shared sanitizer scrubs IPs/domains/emails but **not Windows SIDs**, so relying on tokenization alone would leak them. The adapter therefore **drops** everything outside `SAFE_FIELDS` (default-deny) and *additionally* scrubs SIDs/user-paths as belt-and-suspenders. Note the comment: timestamps are explicitly kept for SOC timeline realism because they are not identifiers.

> ⚠️ **Common pitfall:** A sanitizer tuned to defang *network indicators* will corrupt *non-network* data that merely looks domain-shaped. Here, `powershell.exe` was being rewritten to `example.org` (the `.exe` looked like a TLD). The fix was to attach the already-validated process basename **after** sanitization, not run it through the domain normalizer — see `convert()` around lines 160-166.

### The Off-by-Default Local Lane

```python
# src/threatprism/demo/seeding.py — Lines 289-305 (LocalDatasetSource.list_demo_fixtures)
def list_demo_fixtures(self) -> list[SeedCase]:
    if not self._local_root.is_dir():
        return []
    seeds: list[SeedCase] = []
    for fixture_path in sorted(self._local_root.rglob("*.jsonl")):
        resolved = fixture_path.resolve()
        # Defense-in-depth against symlinks resolving outside the sandbox.
        if not resolved.is_file() or not _is_within(resolved, self._local_root):
            continue
        relative = resolved.relative_to(self._local_root).with_suffix("")
        fixture_id = "local/" + str(relative).replace("\\", "/")
        seeds.extend(CuratedFixtureSource._read_seed_cases(fixture_id, resolved))
    seeds.sort(key=lambda seed: (seed.fixture_id, seed.source_case_id))
    if self._limit is not None:
        seeds = seeds[: self._limit]
    return seeds
```

This reads uncommitted `.jsonl` under gitignored `external_datasets/`. It has **no license/manifest gate** because it is unreviewed local-only data — which is exactly why it must never activate implicitly. In `seed_cli.py`, `_ensure_source_allowed()` refuses `--source local` in production, `--source all` deliberately excludes it, and the startup hook only ever builds the committed sources.

---

## 🧪 Hands-On Exercises

> Before starting: `cd C:\Projects\ThreatPrismV2` and confirm dependencies are installed (`pip install -r requirements.txt`).

### 🔬 Exercise 1: Confirm All Three Families Load Through the Gate

Proves the license gate admits exactly the three reviewed families.

```powershell
# PowerShell
$env:PYTHONPATH="src"
python -c "from threatprism.demo.seeding import CuratedDatasetSource; s=CuratedDatasetSource().list_demo_fixtures(); import collections; print(collections.Counter(x.fixture_id for x in s))"
```

```bash
# Bash
PYTHONPATH=src python -c "from threatprism.demo.seeding import CuratedDatasetSource; s=CuratedDatasetSource().list_demo_fixtures(); import collections; print(collections.Counter(x.fixture_id for x in s))"
```

📊 **Expected output:**
```
Counter({'deepset_prompt_injection': 12, 'synthea_healthcare': 12, 'otrf_soc_telemetry': 8})
```

✅ **You succeeded if:** you see all three families with counts 12/12/8 (32 total).

---

### 🔬 Exercise 2: Prove the OTRF Lane Drops Identifiers

Verifies no raw lab identifier survived into the committed OTRF fixture.

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest tests/test_otrf_telemetry_corpus.py -q -p no:cacheprovider
```

📊 **Expected output:**
```
.......                                                                   [100%]
7 passed
```

✅ **You succeeded if:** all 7 pass — including `test_committed_otrf_file_has_no_raw_identifiers` and `test_process_basename_is_not_mangled_into_a_domain`.

---

### 🔬 Exercise 3: Intentional Failure — The Manifest Cannot Self-Certify a License

Shows that a forged license status is rejected by the in-code allowlist.

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest tests/test_curated_dataset_seeding.py::test_dataset_source_rejects_non_third_party_license -q -p no:cacheprovider
```

📊 **Expected output:**
```
.                                                                        [100%]
1 passed
```

✅ **You succeeded if:** the test passes — a manifest entry claiming `not_third_party_local_fake` produces an **empty** seed list, because that status is not in `DATASET_ALLOWED_LICENSE_REVIEW`.

---

### 🔬 Exercise 4 (Optional): The Local Lane Is Off by Default

Confirms the uncommitted local source does nothing unless explicitly selected.

```powershell
$env:PYTHONPATH="src"; $env:THREATPRISM_AUTH_REQUIRED="false"; $env:THREATPRISM_LOCAL_DEV_ACK="true"; $env:DATABASE_URL="sqlite:///:memory:"
python -m threatprism.demo.seed_cli --source curated --limit 2
```

📊 **Expected output:**
```
--limit is only supported with --source local.
```

✅ **You succeeded if:** `--limit` is rejected outside `--source local` (a clean message, exit 1) — proving the local lane's options can't leak into the committed lanes.

---

## 📚 Interview Preparation

### 🟡 Cybersecurity Engineering Interview

**Q:** You're onboarding a third-party dataset. The dataset ships a manifest declaring its own license as "approved." How do you design the trust boundary so a tampered manifest can't grant itself access, and where does that check live?

**A:** The manifest is attacker-mutable data, so it can only ever *describe* — it must never *decide*. In ThreatPrism the accepted license statuses are a `frozenset` in code (`DATASET_ALLOWED_LICENSE_REVIEW` in `seeding.py`), and `_is_dataset_seedable()` checks the manifest's declared status against that set. Editing the manifest to claim any status string does nothing unless that exact status is already in the code allowlist — and adding one is a reviewed code change. The general principle is "data describes, code decides": anchor the trust decision in something an attacker can't change without passing code review. It's the same reason you don't let a TLS client assert its own authorization claims unsigned.

*Why this answer works:* Shows you locate the trust anchor on the un-tamperable side of the boundary, not in the data being evaluated.

---

### 🔴 AI Security Engineering Interview

**Q:** This system replays third-party data through the model's intake path, and one dataset deliberately keeps prompt-injection text un-redacted. Walk me through the data-poisoning risk and how the design contains it.

**A:** Anything that survives onboarding becomes model-visible input, so onboarding *is* the training/eval-data supply-chain boundary. Two controls contain it. First, provenance and integrity: each fixture carries a `sha256` of its sanitized row plus a code-gated license/review status, so a tampered or unreviewed source can't silently enter the corpus. Second, per-family treatment instead of blanket trust: the deepset family retains injection text on purpose, but that exception is *source-scoped* (`apply_prompt_firewall=False` is set only in that one adapter) so it's a curated adversarial set, not an accidental hole — and the foreign-telemetry family uses a fail-closed allowlist that drops identifiers rather than trusting a detector to catch them. The AI-security failure mode to prevent is that scoped exception silently propagating to another family, which is why it lives in the adapter and is called out in the module docstring and the manifest, not in shared code.

*Why this answer works:* Shows you treat dataset onboarding as an ML supply-chain trust boundary and can reason about a deliberate adversarial-data exception without conflating it with a vulnerability.

---

## ✅ Key Takeaways

- Two parallel contracts keep third-party data from ever weakening the hand-authored fake-only boundary
- The license allowlist lives in **code**, not the manifest — "data describes, code decides"
- Three families get three treatments because the threat differs: column-project + tokenize (Synthea), retain-payload exception (deepset), fail-closed drop (OTRF)
- **Dropping** an identifier (default-deny allowlist) is stronger than **tokenizing** it (default-allow + detector), which is why foreign lab telemetry is dropped, not scrubbed-in-place
- Unreviewed local data (`LocalDatasetSource`) is gated three ways and refused in production — convenience never becomes an implicit trust grant

---

## 📋 Quick Reference Card

| Item | Value |
|------|-------|
| Files | `src/threatprism/demo/seeding.py`, `src/threatprism/demo/seed_cli.py`, `tools/fixture_factory/adapters/{synthea,deepset,otrf}_adapter.py` |
| Trust gate | `DATASET_ALLOWED_LICENSE_REVIEW` (seeding.py L41) + `_is_dataset_seedable()` (L240) |
| Input | Reviewed `.jsonl` derivatives under `fixtures/curated_datasets/` (+ manifest); raw rows stay gitignored in `external_datasets/` |
| Output | `SeedCase` objects replayed through `create_case` + `run_triage` |
| Key config | `THREATPRISM_DEMO_SEED` (startup hook), `--source {curated,curated_datasets,local,all}`, `--limit N` (local only) |
| Error behavior | Unknown/forged license status → fixture silently excluded; `--limit` without `--source local` → `SystemExit`; `--source local` in prod → refused |
| Test files | `tests/test_curated_dataset_seeding.py`, `tests/test_otrf_telemetry_corpus.py`, `tests/test_local_dataset_seeding.py` |

---

## 📌 Implemented vs. Recommended

### What This Project Implements ✅
- In-code license allowlist anti-tamper gate — `DATASET_ALLOWED_LICENSE_REVIEW`, `seeding.py` L41-47, L243
- Fail-closed field allowlist that drops identifiers — `otrf_adapter.py` `SAFE_FIELDS` L57, `_project_safe` L120
- Source-scoped injection-retention exception — `deepset_adapter.py` L107 (`apply_prompt_firewall=False`)
- Per-fixture `sha256` provenance hash — `tools/fixture_factory/adapters/shared.py` `source_metadata()`
- Three-way-gated, production-refused local dev source — `seeding.py` `LocalDatasetSource` L264, `seed_cli.py` `_ensure_source_allowed()`

### General Best Practices — Recommended but Not Implemented Here
- Cryptographic signing of the manifest (e.g., Sigstore/cosign) so provenance is verifiable, not just hashed — `Recommended (not implemented here)`
- Automated license-scan in CI (e.g., a dependency/dataset license linter) gating promotion — `Recommended (not implemented here)`
- A NotInject-style false-positive corpus for the future semantic firewall — `Recommended (not implemented here; specified in docs/specs/32)`

> This section is honest about what the project does and does not do today.

---

## 🚀 Ready for the Next Slice?

Next up: the **threat-model traceability touch** that records this very onboarding surface — the third-party dataset trust boundary and its controls — into `docs/threat-models/mitigations-traceability.md`. Get ready to map each control you just learned to a tracked threat.

**Optional deeper dive:** Read the MIT `LICENSE` of `OTRF/Security-Datasets` and compare its redistribution terms to Apache-2.0 — then re-read why OTRF needed a *separate* `license_review_status` rather than reusing the synthetic one.

**Modification challenge:** Add a fourth SAFE field to the OTRF adapter (e.g., `ProcessId`), regenerate the fixtures, and run `tests/test_otrf_telemetry_corpus.py`. Watch the no-leak test — decide whether `ProcessId` is an identifier that should be *dropped* instead, and defend your call. (Hint: a PID is ephemeral and non-identifying — but does it ever embed something that isn't?)

*Remember: when untrusted data wants in, let the code decide and make the default deny.* 🛡️
```
