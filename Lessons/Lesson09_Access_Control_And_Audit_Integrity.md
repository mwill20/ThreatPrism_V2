# 🎓 Lesson 09: The Gate Badge - Access Control And Audit Integrity

## 🛡️ Welcome Back, Authorization Reviewer!

What stops a manager from asking for an analyst view just by changing `?role=`? 🔍 Today we are exploring **Access Control & Audit Integrity** - the "gate badge" that maps fake demo credentials to roles, denies role escalation, and records safe authorization audit events.

Goal: understand the implemented demo authorization layer and how it protects role-aware reads.

Time estimate: 45 minutes.

Prerequisites:

- Complete Lessons 00-08.
- Understand role views from Lesson 05.

## 🎯 Learning Objectives

- Explain demo API-key authentication.
- Map fake credentials to effective roles.
- Describe the role-view authorization policy.
- Trace allow and deny audit events.
- Run access-control tests.
- Explain why this is not production IdP integration.

## 🔍 What This Component Does

### ✅ Implemented Here

Primary files:

- `C:\Projects\ThreatPrismV2\src\threatprism\auth\demo.py`
- `C:\Projects\ThreatPrismV2\src\threatprism\api\app.py`
- `C:\Projects\ThreatPrismV2\src\threatprism\cases\service.py`
- `C:\Projects\ThreatPrismV2\tests\test_access_control.py`
- `C:\Projects\ThreatPrismV2\.env.example`

When `API_AUTH_MODE=demo_key`, role-aware case and report reads require a fake demo key:

```text
X-ThreatPrism-Demo-Key: demo-manager-key
```

That key maps to an identity and effective role. The `?role=` query parameter becomes a requested view, not authority.

### Recommended (not implemented here)

- OAuth/OIDC/Entra integration.
- Production API gateway enforcement.
- Central policy administration.
- Break-glass governance.
- Tamper-evident audit storage.
- Credential rotation and secret management.

## 🧠 Real-World Analogy

The demo API key is a temporary conference badge:

- It proves which demo role you are acting as.
- It does not make you production-ready.
- It lets the system test the door policy before real badges are issued.

## 🔗 Pipeline Context

```text
GET /cases/{case_id}?role=analyst
  -> extract demo key
  -> map credential to principal
  -> check requested role against allowed role views
  -> write authorization audit event
  -> render allowed role view or deny
```

## 🎯 Key Concepts

### ✅ Implemented Here

| Concept | Meaning |
|---|---|
| Demo principal | Identity and role derived from a fake key. |
| Effective role | Role trusted by the app after authentication. |
| Requested role | Role from `?role=`. It is not trusted authority. |
| View role | Role actually used for rendering. |
| Role escalation | Asking for a role view not allowed by your effective role. |
| Authorization audit event | Safe record of allow or deny decision. |

### Recommended (not implemented here)

- Treat production identity as external and verified by a trusted IdP.
- Add policy version IDs to audit events.
- Forward authorization denials to SIEM in production.

## 📝 Code Walkthrough: Role Policy

File: `C:\Projects\ThreatPrismV2\src\threatprism\auth\demo.py`

### Role policy

```python
ROLE_VIEW_POLICY: dict[str, set[ViewRole]] = {
    "analyst": {"analyst", "ai"},
    "engineer": {"engineer", "analyst", "ai", "audit_debug"},
    "manager_grc": {"manager_grc", "ai"},
    "legal_privacy": {"legal_privacy", "audit_debug", "ai"},
    "audit_debug": {"audit_debug", "ai"},
    "admin": set(VIEW_ROLES),
}
```

Line-by-line:

1. Analysts can see analyst and AI-safe views.
2. Engineers can see engineer, analyst, AI, and audit/debug views.
3. Manager/GRC cannot force analyst or engineer views.
4. Admin can access all role-safe views.

Why: role policy is explicit and testable.

### Authorization decision

`authorize_role_view()`:

1. Extracts credential from `X-ThreatPrism-Demo-Key` or `Authorization: Bearer`.
2. Handles `API_AUTH_MODE=none` for local fake-data demos.
3. Requires known fake credentials in `API_AUTH_MODE=demo_key`.
4. Chooses a default view role from the principal when no `?role=` is provided.
5. Denies role escalation.
6. Creates a safe audit event.

## 📝 Code Walkthrough: Route Enforcement

File: `C:\Projects\ThreatPrismV2\src\threatprism\api\app.py`

`GET /cases/{case_id}` now calls `_authorized_view_role()` before rendering a role view.

```python
view_role = _authorized_view_role(request, case_id, "get_case", role)
if view_role is not None:
    view = _service(request).get_case_view(case_id, view_role)
```

Why: route handlers no longer pass `?role=` directly into rendering when demo auth is enabled.

## 📝 Code Walkthrough: Audit Event Persistence

File: `C:\Projects\ThreatPrismV2\src\threatprism\cases\service.py`

`record_audit_event()` appends authorization events to the case audit trail and saves the case.

The audit event metadata includes:

- Caller identity.
- Requested role.
- Effective role.
- View role.
- Endpoint.
- Method.
- Case ID.
- Decision.
- Reason.
- Request metadata hash.

It does not include raw credentials or request bodies.

## 🧪 Manual Verification

### 🔬 Exercise 1: Run Access-Control Tests

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest tests\test_access_control.py -q -p no:cacheprovider --basetemp .pytest_tmp_lesson09
```

Expected output:

```text
7 passed
```

### 🔬 Exercise 2: Inspect Demo Key Defaults

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTHONPATH='src'
python -c "from threatprism.config import Settings; s=Settings(); print(s.api_auth_mode); print('demo-manager-key' in s.demo_api_keys); print(s.demo_role_override_enabled)"
```

Expected output:

```text
none
True
False
```

### 🔬 Exercise 3: Prove Manager Cannot Request Analyst View

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest tests\test_access_control.py::test_manager_grc_cannot_force_analyst_view -q -p no:cacheprovider --basetemp .pytest_tmp_lesson09_manager
```

Expected output:

```text
1 passed
```

### 🔬 Exercise 4: Prove Full Suite Still Passes

PowerShell:

```powershell
Set-Location C:\Projects\ThreatPrismV2
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_lesson09_full
```

Expected output:

```text
66 passed
```

## 📚 Interview Prep

**Q: Why is `?role=` not enough for access control?**  
**A**: Request parameters are caller-controlled. The app must derive an effective role from authenticated identity and treat `?role=` only as a requested view.

**Q: Why is this called demo authentication?**  
**A**: It uses static fake keys and no external IdP. It proves policy behavior locally but is not suitable for production identity or credential management.

**Q: What gets audited on deny?**  
**A**: Caller identity when known, requested role, effective role, endpoint, method, case ID, decision, reason, and a redacted request metadata hash. Full credentials and raw payload bodies are not stored.

**Q: What is the next production-grade step?**  
**A**: Replace demo keys with a trusted identity layer, preserve the role-policy interface, and send authorization events to durable audit storage.

## 🎯 Key Takeaways

- `API_AUTH_MODE=none` remains local fake-data demo mode.
- `API_AUTH_MODE=demo_key` enforces role-aware reads with fake demo keys.
- `?role=` is a request, not authority.
- Manager/GRC cannot force analyst or engineer views.
- Authorization decisions are audited without full credentials or raw payloads.

## 📋 Summary Reference Card

| Item | Details |
|---|---|
| Auth mode | `API_AUTH_MODE=demo_key` |
| Header | `X-ThreatPrism-Demo-Key` |
| Demo key format | `credential:identity:role` |
| Main policy | `ROLE_VIEW_POLICY` |
| Main function | `authorize_role_view()` |
| Audit event type | `authorization_decision` |
| Test file | `tests/test_access_control.py` |

## 🚀 Ready For The Next Slice?

Next, study Operational Read Models & Metrics API v0.1 to see how this authorization pattern protects broader read surfaces.

Remember: access control turns role views from helpful formatting into enforceable behavior. 🛡️
