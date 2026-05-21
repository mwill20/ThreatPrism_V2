from __future__ import annotations

from threatprism.cases.schemas import SimulatedAction


def simulated_action(action: str, would_target: str | None = None) -> SimulatedAction:
    return SimulatedAction(
        action=action,
        would_target=would_target,
        real_action_executed=False,
        blocked_reason="Real remediation is disabled in V2.",
    )
