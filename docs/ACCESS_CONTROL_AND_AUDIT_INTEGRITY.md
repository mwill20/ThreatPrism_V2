# Access Control And Audit Integrity

## Current Recommendation

Access Control & Audit Integrity v0.1 is the next implementation slice.

This supersedes the previously prepped Operational Read Models & Metrics API
v0.1 slice as the immediate next step. Metrics remain important, but role-based
views should be enforceable before ThreatPrism expands read surfaces.

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

## Implementation Target

Build a demo-safe access-control layer before any non-demo data, live LLM,
live SOAR, live enrichment, dashboard, or production integration work.

Minimum scope:

- Demo authentication middleware or dependency.
- Fake/demo API keys or signed development tokens only.
- Caller identity mapped to an effective role.
- Role escalation denied.
- `?role=` treated as a view request, not authority, outside explicit demo/test
  override behavior.
- Authorization allow and deny events recorded safely.
- Audit events exclude raw potential PHI/ePHI, secrets, full credentials, raw
  payload bodies, and token vault mappings.

## Required Tests

- Unauthenticated access is denied when demo auth is enabled.
- Unknown demo credentials are denied.
- Manager/GRC cannot force analyst or engineer views.
- Audit/debug cannot access raw values.
- Invalid role escalation fails closed.
- Allow decisions create audit events.
- Deny decisions create audit events.
- Existing healthcare leakage tests still pass.

## Out Of Scope

- Production IdP integration.
- OAuth/OIDC/Entra implementation.
- Frontend dashboard.
- Live LLM calls.
- Live SOAR calls.
- Live enrichment calls.
- Real remediation or containment.
- Real healthcare data.

## Next Prompt

```text
Implement Access Control & Audit Integrity v0.1 for ThreatPrism.

Use fake/demo credentials only. Map caller identity to an effective role and
deny role escalation. Do not trust ?role= as authority outside explicit
demo/test override behavior. Add safe audit events for allow and deny
authorization decisions.

Do not add live LLM calls, live SOAR calls, production credentials, real
remediation, real healthcare data, dashboard work, or production IdP
integration. Keep ALLOW_REAL_ACTIONS=false.

Run:
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; python -m pytest -p no:cacheprovider --basetemp .pytest_tmp_run_auth
```
