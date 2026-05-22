from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

from threatprism.cases.schemas import AuditEvent


ViewRole = Literal["ai", "analyst", "engineer", "manager_grc", "legal_privacy", "audit_debug"]


SECURITY_TELEMETRY_PATTERNS = [
    ("IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("URL", re.compile(r"https?://[^\s\"'<>]+", re.I)),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("FILE_HASH", re.compile(r"\b[a-fA-F0-9]{32,64}\b")),
]

SENSITIVE_TYPED_TOKEN_PATTERN = re.compile(
    r"\[(?:POTENTIAL_PHI|POTENTIAL_PII|SECRET):[A-Z_]+:[a-z]+_\d{4}\]"
)


@dataclass(frozen=True)
class RoleViewResult:
    payload: Any
    audit_events: list[AuditEvent] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def render_role_view(value: Any, role: ViewRole, case_id: str | None = None) -> RoleViewResult:
    metadata = {"role": role, "masked_security_telemetry": 0, "sensitive_tokens_present": 0}
    payload = _render_value(value, role, metadata)
    audit_events = [
        AuditEvent(
            case_id=case_id,
            event_type="role_view_policy_applied",
            summary="Role-based view policy was applied.",
            metadata=metadata,
        )
    ]
    if metadata["sensitive_tokens_present"]:
        audit_events.append(
            AuditEvent(
                case_id=case_id,
                event_type="rehydration_denied",
                summary="Sensitive typed tokens were not rehydrated for this role.",
                metadata={"role": role, "token_count": metadata["sensitive_tokens_present"]},
            )
        )
    return RoleViewResult(payload=payload, audit_events=audit_events, metadata=metadata)


def _render_value(value: Any, role: ViewRole, metadata: dict[str, Any]) -> Any:
    if hasattr(value, "model_dump"):
        return _render_value(value.model_dump(mode="json"), role, metadata)
    if isinstance(value, dict):
        return {key: _render_value(entry, role, metadata) for key, entry in value.items()}
    if isinstance(value, list):
        return [_render_value(entry, role, metadata) for entry in value]
    if isinstance(value, str):
        return _render_text(value, role, metadata)
    return value


def _render_text(text: str, role: ViewRole, metadata: dict[str, Any]) -> str:
    sensitive_tokens = SENSITIVE_TYPED_TOKEN_PATTERN.findall(text)
    if sensitive_tokens:
        metadata["sensitive_tokens_present"] += len(sensitive_tokens)
    if role in {"analyst", "engineer"}:
        return text
    masked = text
    for detector, pattern in SECURITY_TELEMETRY_PATTERNS:
        def replace(_: re.Match[str]) -> str:
            metadata["masked_security_telemetry"] += 1
            return f"[SECURITY_TELEMETRY:{detector}:masked]"

        masked = pattern.sub(replace, masked)
    return masked
