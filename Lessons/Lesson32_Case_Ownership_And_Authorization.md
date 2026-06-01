# 🔑 Lesson 32 — Case Ownership & Authorization (Authn vs Authz vs Object-Level)

> **Goal:** Understand the three distinct access-control checks behind a single
> "self-assign a case" action — authentication, role authorization, and
> object-level (ownership) authorization — and why each is audited.
> **Time:** ~25 min · **Prerequisites:** Lesson 09 (access control & audit).

Covers Evolution 3 sub-slice 1 (case ownership/assignment).

---

## 1. 🎯 The feature

An analyst self-assigns a case to work it (the start of the live co-pilot loop):

- `POST /cases/{id}/assign` — the caller takes ownership (`assigned_to` = caller).
- `POST /cases/{id}/release` — give it up.

Simple on the surface — but a *consequential, authenticated, audited* write, so it
gets the full security treatment (the project's default, not an add-on).

---

## 2. 🧱 Three different access-control questions

A common mistake is to treat "access control" as one check. This one action asks
**three** distinct questions, each a different layer:

| Question | Layer | Where |
|---|---|---|
| **Who are you?** (authentication) | identity | `authorize_role_view` resolves a `DemoPrincipal(identity, role)` from the demo key / token |
| **Is your *role* allowed to do this at all?** (role authz) | role allowlist | `_ASSIGNABLE_ROLES = {analyst, engineer, admin}` in `_authorized_principal()` |
| **Are you allowed to touch *this specific object*?** (object-level authz) | ownership | `release_case()` — only the current owner or an admin may release |

Role authz is coarse ("analysts may release cases"); **object-level authz is the
one people forget** ("…but not *this* case, which belongs to someone else"). Without
it, any analyst could release a colleague's case. The check lives in the service
(`if case.assigned_to and case.assigned_to != identity and actor_role != "admin"`)
because it is a *business rule about the object*, not a property of the endpoint.

> SOC analogy: role authz is "analysts can work the IR queue"; object-level authz is
> "but you can't close the ticket another analyst is actively handling." Both matter.

---

## 3. 🧾 Every decision is audited — allow *and* deny

`_authorized_principal()` records an `AuditEvent` on the case for the authenticated
access, and a separate `authorization_denied` event when the role allowlist refuses
(`manager_grc` trying to self-assign → 403 + audit). `assign_case`/`release_case`
each append their own `case_assigned` / `case_released` event with the actor. This
is the security-first rule: **who did what, when — denials included** — so the
ownership history is forensically reconstructable. The metadata carries the actor
identity and role (safe to log), never a secret.

---

## 4. 🧩 Schema design — orthogonal, backward-compatible

Ownership is **not** a `CaseStatus` value. The status enum is the *triage* lifecycle
(received → triage → needs_review → closed); who *owns* a case is a separate axis.
Conflating them would couple two state machines. So ownership is two new optional
fields (`assigned_to`, `assigned_at`) with defaults — which also keeps the
JSON-blob persistence **backward-compatible**: every previously stored case
deserializes unchanged (the fields default to `None`).

---

## 5. 🧪 Testing all three layers

`tests/test_case_assignment.py` tests each question independently:

- **Authn:** no key → 401.
- **Role authz:** `manager_grc` → 403; `analyst` → 200.
- **Object-level authz:** a non-owner working role → 403 on release; the owner → 200;
  admin → 200 on any case.
- **Service unit:** `assign_case` sets owner + audit; `release_case` raises
  `PermissionError` for a non-owner non-admin; unknown case → `KeyError`.

Testing them separately is the point — a test that only checks "analyst can assign"
would miss the object-level hole entirely.

---

## 6. 🎤 Interview talk track

> "Self-assigning a case looks trivial but it's three access-control checks:
> authentication (who is the caller), role authorization (is this role allowed to
> own cases at all — I allowlisted analyst/engineer/admin), and object-level
> authorization (can you release *this* case — only its owner or an admin). The
> last one is the commonly-missed layer: role checks alone would let any analyst
> release a colleague's case. I audited every decision including denials, and made
> ownership an orthogonal field rather than a triage-status value so I wasn't
> coupling two state machines — which also kept the stored-blob schema
> backward-compatible."
