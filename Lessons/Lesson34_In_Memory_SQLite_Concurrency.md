# 🔒 Lesson 34 — Fixing the In-Memory SQLite Concurrency 500 (Shared State Needs a Lock)

> **Goal:** Understand why a single shared `:memory:` SQLite connection returns
> HTTP 500 under FastAPI's threadpool, why `check_same_thread=False` is part of the
> trap rather than the fix, and how a `threading.Lock` around a transaction context
> manager resolves it without breaking the stateful in-memory test suite.
> **Time:** ~20 min · **Prerequisites:** Lesson 07 (SQLite, config & identifiers).

Covers the Security / Reliability Hardening Backlog item surfaced during Evolution
3 sub-slice 2 browser verification (see Lesson 32 §2.7, where this 500 was first
caught).

---

## 1. 🐛 The symptom

The analyst co-pilot dashboard opens a case and fires ~6 **parallel** detail
fetches (`/evidence`, `/timeline`, `/mitre`, `/grc-controls`, `/audit-events`, plus
the case itself). Intermittently, one of those returned **HTTP 500** instead of
data. Reloading sometimes fixed it; sometimes a different panel failed. Classic
*intermittent* — the tell of a race condition, not a logic bug.

File-backed mode (`sqlite:///./data/threatprism.db`) never showed it. Only
`:memory:` mode did. That contrast is the whole diagnosis in one observation.

> SOC analogy: an alert that fires sometimes, on no consistent input, and only on
> one sensor — you stop looking at the payload and start looking at a timing/shared-
> resource problem on that sensor.

---

## 2. 🧩 Why `:memory:` is different

[`persistence/sqlite.py`](../src/threatprism/persistence/sqlite.py) runs in two
modes, and the difference is structural:

| Mode | Connection strategy | Why |
|---|---|---|
| **File-backed** | one fresh `sqlite3.connect()` **per operation** | Every connection opens the same file; SQLite's own file locking coordinates them. |
| **`:memory:`** | **one shared connection** held on the repository instance | Each new `sqlite3.connect(":memory:")` is a *separate, empty database* — so you *cannot* open a new one per op, or you'd read an empty DB. |

That last cell is the constraint that drives everything. The in-memory database
*only exists inside its one connection*. The whole test suite relies on this:
`POST` a case, then `GET` it back, all against the same `:memory:` DB. Switch
`:memory:` to connection-per-op and every stateful test breaks — you'd write into
one throwaway database and read from another.

So `:memory:` is *forced* to share one connection. And a shared mutable resource
across threads is exactly where races live.

---

## 3. ⚠️ `check_same_thread=False` is the footgun, not the fix

The original code already had this:

```python
self._memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
```

By default, `sqlite3` **refuses** to let a connection be used from a thread other
than the one that created it — raising `ProgrammingError: SQLite objects created in
a thread can only be used in that same thread`. FastAPI runs synchronous route
handlers in a **threadpool**, so each parallel fetch lands on a *different* thread.
That default guard would have turned every cross-thread use into an error.

`check_same_thread=False` **disables that guard**. But disabling the *warning* about
a hazard does not remove the *hazard*. Now multiple threads may legally reach into
one connection at the same time — and a `sqlite3.Connection` is **not safe for
concurrent use**. Two threads calling `execute()` at once race the connection's
single underlying cursor and its implicit transaction state, producing:

```text
InterfaceError: bad parameter or other API misuse
```

…or a read that silently returns `None` because another thread's transaction
clobbered the connection mid-statement. FastAPI maps the raised exception to a 500.

> Security-engineering parallel: `check_same_thread=False` is like silencing a noisy
> SIEM correlation rule because the alerts annoy you. The alert was pointing at a
> real condition. You removed the visibility, not the risk.

The missing piece was never "allow cross-thread access." It was **"serialize
cross-thread access."**

---

## 4. ✅ The fix — a lock that spans the whole transaction

The control is a mutex around the **entire** critical section. Not just the
`execute()` call — the whole `BEGIN → execute → COMMIT` span, because the race is on
the transaction state, not a single statement.

A `threading.Lock` is added in `__init__`, and all DB access is routed through one
`_transaction()` context manager:

```python
@contextmanager
def _transaction(self) -> Iterator[sqlite3.Connection]:
    if self._memory_conn is not None:
        # One shared connection: hold the lock for the whole transaction
        # (BEGIN -> execute -> COMMIT) so threads cannot interleave on it.
        with self._lock, self._memory_conn as conn:
            yield conn
        return
    # File-backed mode: a fresh connection per operation. SQLite handles
    # cross-connection file locking, so no process-level lock is needed.
    conn = sqlite3.connect(self.db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        with conn:
            yield conn
    finally:
        conn.close()
```

Three design choices worth naming:

1. **Context manager, not scattered `lock.acquire()`.** A `with` block guarantees
   the lock is released even if the query raises. Manual acquire/release is how you
   ship a deadlock the first time an exception fires mid-transaction.
2. **The lock spans the transaction.** `with self._lock, self._memory_conn as conn:`
   holds the lock until the inner `with conn` commits/rolls back. Locking only
   around `execute()` would still let a second thread slip in before `COMMIT`.
3. **The lock is scoped to `:memory:` only.** File-backed mode keeps its
   connection-per-op path untouched — SQLite already coordinates separate
   connections to a file, so a process lock there would just throttle throughput for
   no safety gain. (It also now `close()`s each file connection — a latent leak the
   old code left to the garbage collector.)

Every one of the 9 repository methods now goes through `_transaction()`, so the
serialization is structural, not something each method has to remember.

---

## 5. 🪤 The trap we did *not* fall into

The "obvious" alternative is: *just use connection-per-op for `:memory:` too, like
file mode.* That would also serialize... by giving every operation its own database.
And that is precisely why it's wrong here — **each `:memory:` connection is a
separate empty DB**, so the case you just `save_case()`'d would vanish on the next
`get_case()`. It would turn one intermittent 500 into a *total* failure of every
stateful in-memory test. The full suite passing after the lock fix (267 passed) is
the proof we preserved the shared-state semantics the tests depend on.

> Lesson: when two paths both "fix concurrency," the one that changes *correctness
> semantics* (per-op DB) is not a fix — it's a different, larger bug.

---

## 6. 🧪 Test-driven: reproduce the race first

[`tests/test_persistence_concurrency.py`](../tests/test_persistence_concurrency.py)
was written **before** the fix and watched fail (TDD red). Reproducing a race
reliably takes deliberate contention:

```python
thread_count = 8
barrier = threading.Barrier(thread_count)   # release all threads at once

def worker():
    barrier.wait()                          # maximize simultaneous access
    for _ in range(50):                     # many iterations = many chances to race
        for case in cases:
            assert repo.get_case(case.case_id) is not None
        assert len(repo.list_cases()) == len(cases)
```

Key moves: a **`Barrier`** so all 8 threads start the read loop at the same instant
(not staggered), and **50 iterations** so the interleaving window is hit, not missed
by luck. Pre-fix this raised `InterfaceError('bad parameter or other API misuse')`
and spurious `None` reads; post-fix it passes. Exceptions are captured into a list
and asserted on the main thread, because an `assert` that fails *inside* a worker
thread won't fail the test on its own.

> Why reproduce first? A test written *after* the fix passes immediately and proves
> nothing — you never saw it catch the bug. Watching it go red, then green, is what
> proves the test actually guards this regression.

---

## 7. 🔐 Why a reliability bug is also a security note

This was logged as *reliability*, not *security* — correctly. But availability is
the **A** in the CIA triad. A latent concurrency race that an attacker (or merely a
busy dashboard) can drive into repeatable failures is a denial-of-service surface.
"It only happens under load" is not reassurance; load is the cheapest thing for an
adversary to manufacture. Fixing the race closes a small availability gap *and*
removes the kind of nondeterministic 500 that hides real errors in the noise.

---

## 8. 🎤 Interview talk track

> "The dashboard threw intermittent 500s only in in-memory mode. Intermittent +
> single-environment told me race condition on a shared resource. The in-memory
> SQLite DB lives entirely inside one connection — you can't open a new one per
> request like file mode, or you'd get a fresh empty database — so that one
> connection is shared across FastAPI's threadpool. The previous author had set
> `check_same_thread=False`, which I treat as the root cause's enabler: it silenced
> SQLite's thread-ownership guard without adding serialization, so threads raced the
> connection's cursor. The fix was a `threading.Lock` held across the whole
> transaction via a context manager, scoped to in-memory mode only — file mode keeps
> connection-per-op since SQLite coordinates those itself. I explicitly rejected
> per-op connections for `:memory:` because that changes correctness, not just
> concurrency. And I wrote the regression test first, with a barrier and many
> iterations to force the interleaving, so I watched it fail before it passed."

---

## 9. 🗂️ Quick reference card

| Thing | Value |
|---|---|
| File | `src/threatprism/persistence/sqlite.py` |
| Root cause | shared `:memory:` connection + `check_same_thread=False` + no lock |
| Fix | `threading.Lock` spanning a `_transaction()` context manager |
| Scope | `:memory:` only; file mode keeps connection-per-op |
| Rejected alt | connection-per-op for `:memory:` (breaks shared in-memory state) |
| Regression test | `tests/test_persistence_concurrency.py` (8 threads × 50 iters, barrier) |
| Pre-fix failure | `InterfaceError('bad parameter or other API misuse')` + `None` reads |
| Validation | 267 passed / 3 skipped, eval 15/15, demo safety passed |
| Security angle | availability (DoS surface) — the A in CIA |
