# Access Control And Audit Integrity

## Current Status

Access Control & Audit Integrity v0.1 is implemented.

Operational Read Models & Metrics API v0.1 has also been implemented. Access
control remains the prerequisite that makes those broader read surfaces safer.

## Rationale

ThreatPrism now has role-based rendering for:

- AI/model-visible views.
- Analyst views.
- Engineer views.
- Manager/GRC views.
- Legal/privacy views.
- Audit/debug views.

Those views are useful, but they are not authorization controls by themselves.
A request such as `?role=analyst` must not be trusted as authority unless the
API has a trusted identity-to-role enforcement layer.

Core rule:

```text
Views are not security controls until identity and authorization enforce them.
```

## Implemented Behavior

ThreatPrism now has a demo-safe access-control layer for role-aware case and
report reads.

Implemented scope:

- Demo authentication dependency/helper.
- Fake/demo API keys or signed development tokens only.
- Caller identity mapped to an effective role.
- Role escalation denied.
- `?role=` treated as a view request, not authority, outside explicit demo/test
  override behavior.
- Authorization allow and deny events recorded safely.
- Audit events exclude raw potential PHI/ePHI, secrets, full credentials, raw
  payload bodies, and token vault mappings.

## Implemented Tests

- Unauthenticated access is denied when demo auth is enabled.
- Unknown demo credentials are denied.
- Manager/GRC cannot force analyst or engineer views.
- Audit/debug cannot access raw values.
- Invalid role escalation fails closed.
- Allow decisions create audit events.
- Deny decisions create audit events.
- Existing healthcare leakage tests still pass.

Validation result:

```text
41 passed
```

## Out Of Scope

- Production IdP integration.
- OAuth/OIDC/Entra implementation.
- Frontend dashboard.
- Live LLM calls.
- Live SOAR calls.
- Live enrichment calls.
- Real remediation or containment.
- Real healthcare data.

## Current Follow-On

Demo Operations & CI Hardening v0.1 is implemented. Use the safe validation
wrapper for current checks:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate-threatprism.ps1
```

The next recommended slice is Demo Scenario Pack & API Contract Freeze v0.1.
