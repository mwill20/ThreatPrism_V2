# 09 Action Safety Model

## Policy

ThreatPrism V2 must not execute real remediation or containment actions.

Required default:

```text
ALLOW_REAL_ACTIONS=false
```

## Allowed In V2

- Recommended actions.
- Simulated actions.
- Dry-run action planning.
- Action adapter interface scaffolding.
- Analyst approval workflow design.
- Audit records that show real action execution was blocked.

## Blocked In V2

- Real endpoint isolation.
- Real account disablement.
- Real firewall blocking.
- Real email deletion.
- Real token revocation.
- Real cloud resource modification.
- Any production-impacting action.

## Action Types

### Recommended Action

Human-readable analyst guidance.

Example:

```json
{
  "action_type": "analyst_review",
  "action": "Review recent sign-in history and mailbox rule changes.",
  "priority": "high",
  "evidence_ids": ["ev-001"]
}
```

### Simulated Action

Dry-run representation of what an action adapter would do in a future version.

Example:

```json
{
  "action_type": "simulate_account_disablement",
  "would_target": "demo.user@example.invalid",
  "real_action_executed": false,
  "blocked_reason": "Real remediation is disabled in V2.",
  "requires_future_controls": [
    "explicit configuration",
    "authorization",
    "audit trail",
    "RBAC",
    "approval workflow",
    "safety checks"
  ]
}
```

## Enforcement Requirements

Future implementation must enforce action safety in at least three places:

1. Configuration load must default `ALLOW_REAL_ACTIONS` to `false`.
2. Any action adapter must refuse real actions while the flag is false.
3. Output policy scanning must reject LLM claims that real actions were completed.

## Future V3 Requirements For Real Actions

Real remediation is reserved for a future version and must require:

- Explicit configuration.
- Authorization.
- Audit trail.
- RBAC.
- Approval workflow.
- Safety checks.
- Target allowlists.
- Per-action dry-run preview.
- Rollback or recovery notes where applicable.

## Action Safety Tests

Required tests in a later implementation phase:

- Default configuration sets `ALLOW_REAL_ACTIONS=false`.
- Simulated actions record `real_action_executed=false`.
- Real action adapter calls fail closed.
- Unsafe LLM output claims are blocked.
- API cannot trigger real actions.
- Audit events capture action safety blocks.
