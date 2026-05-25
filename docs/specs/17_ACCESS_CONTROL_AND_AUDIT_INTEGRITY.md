# 17 Access Control And Audit Integrity

## Slice Name

Access Control & Audit Integrity v0.1

Status: implemented.

## Goal

Make ThreatPrism role-based views enforceable and auditable before any
non-demo data, live LLM calls, live SOAR callbacks, frontend dashboard, or
production integrations are added.

The healthcare safeguard slice added role-aware rendering, but view rendering
is not authorization by itself. This slice adds a demo-safe identity and
authorization boundary so role-based views are harder to misuse and every allow
or deny decision is auditable.

## Why This Slice Supersedes Metrics

Operational read models and metrics remain important, but they should not be
the immediate next implementation target while role selection can still be
expressed directly by a request parameter.

Current risk:

```text
GET /cases/{case_id}?role=manager_grc
GET /cases/{case_id}?role=analyst
GET /cases/{case_id}?role=audit_debug
```

These role views are useful for tests and demos. They must not be treated as
security controls unless a trusted identity-to-role layer enforces the effective
role. The key rule is:

```text
Views are not security controls until identity and authorization enforce them.
```

Therefore, Access Control & Audit Integrity v0.1 should run before the
Operational Read Models & Metrics API slice.

That sequencing is now complete. Operational Read Models & Metrics API v0.1 is
also implemented.

## In Scope

### Demo Authentication

Add demo authentication only. This is not a production IdP integration.

Acceptable approaches:

- Static demo API keys mapped to identities and roles.
- Signed development tokens with local demo secrets.
- Test-only dependency override for FastAPI tests.

Required behavior:

- Missing credentials fail closed when demo auth is enabled.
- Unknown credentials fail closed.
- Caller identity is normalized into an authenticated principal.
- Principal includes an effective role.
- Demo auth is clearly documented as non-production.

### Role Authorization

Do not trust `?role=` as the source of authority outside explicit demo/test
override behavior.

Required behavior:

- Derive the effective role from the authenticated caller.
- Treat requested role as a view request, not authority.
- Deny role escalation.
- Deny missing, unknown, or unauthorized roles.
- Keep model-visible/AI views tokenized.
- Keep manager/GRC, legal/privacy, and audit/debug views masked or tokenized by
  default.

Recommended initial role rules:

| Effective role | Allowed view roles |
| --- | --- |
| `analyst` | `analyst`, `ai` |
| `engineer` | `engineer`, `analyst`, `ai`, `audit_debug` |
| `manager_grc` | `manager_grc`, `ai` |
| `legal_privacy` | `legal_privacy`, `audit_debug`, `ai` |
| `audit_debug` | `audit_debug`, `ai` |
| `admin` | all role-safe views |

No V2 role may execute real remediation.

### Demo Role Override

`?role=` may remain available only as a demo/test convenience when explicitly
enabled.

Recommended config:

```text
API_AUTH_MODE=none|demo_key
THREATPRISM_AUTH_REQUIRED=true
THREATPRISM_LOCAL_DEV_ACK=false
DEMO_ROLE_OVERRIDE_ENABLED=false
```

Rules:

- In `API_AUTH_MODE=none`, route behavior may remain easy for local fake-data
  demos only when `THREATPRISM_LOCAL_DEV_ACK=true` is set explicitly.
- In `API_AUTH_MODE=demo_key`, role escalation must be denied.
- `DEMO_ROLE_OVERRIDE_ENABLED=true` should be test/demo-only and should still
  create audit events.

### Audit Integrity Events

Record authorization decisions without storing raw sensitive values.

Authorization audit events should include:

- caller identity
- requested role
- effective role
- endpoint
- method
- case ID or report ID when available
- allow or deny decision
- reason
- timestamp
- redacted request metadata hash

Audit events must not include:

- raw potential PHI/ePHI
- secrets
- full credentials
- token vault mappings
- raw payload bodies

### Route Coverage

Apply authorization to role-aware routes first:

- `GET /cases/{case_id}`
- `GET /cases/{case_id}/triage-report`

Detail/read-model routes added in Operational Read Models & Metrics API v0.1
use the same authorization policy:

- evidence
- timeline
- MITRE mappings
- GRC mappings
- audit events
- metrics or review queues if role-specific detail is exposed

## Out Of Scope

- Production IdP integration.
- OAuth/OIDC/Entra implementation.
- Multi-tenant authorization.
- Full RBAC administration UI.
- Break-glass raw sensitive value access.
- Frontend dashboard.
- Live LLM calls.
- Live SOAR calls.
- Live enrichment calls.
- Real remediation or containment.
- Real healthcare data.

## Security Rules

- `ALLOW_REAL_ACTIONS=false` remains required.
- Demo data stays fake.
- API keys or tokens must never be logged in full.
- Role escalation fails closed.
- Authorization deny decisions are audited.
- Authorization allow decisions are audited for sensitive view routes.
- Audit/debug views must not reveal raw potential PHI/ePHI or secrets.
- Manager/GRC views must not receive analyst or engineer rehydrated views.
- Legal/privacy views should receive exposure metadata and audit trail context,
  not raw sensitive values.
- AI/model-visible views remain tokenized.

## Implementation Notes

- Keep auth logic small and replaceable.
- Avoid introducing production identity assumptions in this slice.
- Prefer a dedicated `auth` module or package rather than embedding policy
  logic directly in route handlers.
- Keep authorization policy testable without FastAPI.
- Use request metadata hashes rather than raw request bodies in audit events.
- Preserve existing local demo ergonomics where possible, but make the security
  boundary explicit in docs and tests.

## Tests

Add tests proving:

- Unauthenticated access is denied when demo auth is enabled.
- Unknown demo credentials are denied.
- Valid demo credentials map to the expected effective role.
- Manager/GRC cannot force analyst or engineer views.
- Audit/debug cannot access raw values.
- Invalid role escalation fails closed.
- Allow decisions create audit events.
- Deny decisions create audit events.
- Authorization audit events do not store raw potential PHI/ePHI, secrets, or
  full credentials.
- Existing healthcare leakage protections still pass.
- Full local pytest validation passes.

## Acceptance Criteria

- [x] Role-aware case and report routes use an effective role derived from a
  trusted demo principal when demo auth is enabled.
- [x] `?role=` is not trusted as authority outside explicit demo/test override
  behavior.
- [x] Unauthorized role requests fail closed.
- [x] Allow and deny decisions create safe audit events.
- [x] Audit events include caller, requested role, effective role, endpoint,
  decision, reason, and case/report ID when available.
- [x] Audit events do not include raw sensitive data, full credentials, or token
  vault mappings.
- [x] Existing healthcare safeguard tests remain green.
- [x] Safe local validation passes.

Original slice validation result:

```text
41 passed
```

Current full-project validation is tracked in `docs/WORKING_CHECKLIST.md`.

## Recommended Implementation Prompt

```text
Implement Access Control & Audit Integrity v0.1 for ThreatPrism.

Current state:
- Healthcare Safeguard & Evidence Alignment Guardrails v0.1 is implemented and pushed.
- Validation currently passes with 22 tests.
- Role-based views exist for AI, analyst, engineer, manager/GRC, legal/privacy, and audit/debug.
- The project must continue using fake/demo data only.

Goal:
Make role-based healthcare views enforceable and auditable before any non-demo
data, live integrations, or dashboard work are added.

Implement:
- demo authentication middleware or dependency using fake/demo keys only
- caller identity to effective-role mapping
- authorization checks that deny role escalation
- explicit handling so ?role= is not authority outside demo/test override
- role-view policy hardening
- authorization audit events for allow and deny decisions
- tests for unauthenticated denial, role escalation denial, audit event creation, and no sensitive value leakage

Do not add live LLM calls, live SOAR calls, production credentials, real
remediation, real healthcare data, dashboard work, or production IdP
integration. Keep ALLOW_REAL_ACTIONS=false.

Run:
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_auth
```
