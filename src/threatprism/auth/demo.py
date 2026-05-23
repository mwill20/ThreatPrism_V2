from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Mapping

from threatprism.cases.schemas import AuditEvent
from threatprism.config import Settings
from threatprism.guardrails.views import ViewRole


EffectiveRole = ViewRole | str

VIEW_ROLES: set[ViewRole] = {
    "ai",
    "analyst",
    "engineer",
    "manager_grc",
    "legal_privacy",
    "audit_debug",
}

ROLE_VIEW_POLICY: dict[str, set[ViewRole]] = {
    "analyst": {"analyst", "ai"},
    "engineer": {"engineer", "analyst", "ai", "audit_debug"},
    "manager_grc": {"manager_grc", "ai"},
    "legal_privacy": {"legal_privacy", "audit_debug", "ai"},
    "audit_debug": {"audit_debug", "ai"},
    "admin": set(VIEW_ROLES),
}


@dataclass(frozen=True)
class DemoPrincipal:
    identity: str
    role: str
    auth_mode: str


@dataclass(frozen=True)
class RequestMetadata:
    method: str
    path: str
    query_keys: tuple[str, ...]
    credential_present: bool
    auth_mode: str


@dataclass(frozen=True)
class AuthorizationResult:
    principal: DemoPrincipal
    requested_role: ViewRole | None
    view_role: ViewRole | None
    allowed: bool
    reason: str
    audit_event: AuditEvent | None


class AuthorizationError(Exception):
    def __init__(
        self,
        status_code: int,
        reason: str,
        audit_event: AuditEvent | None,
    ) -> None:
        super().__init__(reason)
        self.status_code = status_code
        self.reason = reason
        self.audit_event = audit_event


def authorize_role_view(
    *,
    settings: Settings,
    headers: Mapping[str, str],
    method: str,
    path: str,
    query_keys: list[str],
    requested_role: ViewRole | None,
    case_id: str | None,
    endpoint: str,
) -> AuthorizationResult:
    credential = _extract_credential(headers)
    request_metadata = RequestMetadata(
        method=method,
        path=path,
        query_keys=tuple(sorted(query_keys)),
        credential_present=credential is not None,
        auth_mode=settings.api_auth_mode,
    )

    if settings.api_auth_mode == "none":
        principal = DemoPrincipal(identity="local_demo", role="admin", auth_mode="none")
        return AuthorizationResult(
            principal=principal,
            requested_role=requested_role,
            view_role=requested_role,
            allowed=True,
            reason="auth_disabled_for_local_demo",
            audit_event=None,
        )

    if settings.api_auth_mode != "demo_key":
        event = _authorization_event(
            principal=DemoPrincipal(identity="unknown", role="unknown", auth_mode=settings.api_auth_mode),
            requested_role=requested_role,
            view_role=None,
            case_id=case_id,
            endpoint=endpoint,
            decision="deny",
            reason="unsupported_auth_mode",
            request_metadata=request_metadata,
        )
        raise AuthorizationError(403, "Unsupported API auth mode.", event)

    if credential is None:
        event = _authorization_event(
            principal=DemoPrincipal(identity="anonymous", role="none", auth_mode="demo_key"),
            requested_role=requested_role,
            view_role=None,
            case_id=case_id,
            endpoint=endpoint,
            decision="deny",
            reason="missing_demo_credential",
            request_metadata=request_metadata,
        )
        raise AuthorizationError(401, "Missing demo API key.", event)

    principal = _principal_for_credential(credential, settings)
    if principal is None:
        event = _authorization_event(
            principal=DemoPrincipal(identity="unknown", role="unknown", auth_mode="demo_key"),
            requested_role=requested_role,
            view_role=None,
            case_id=case_id,
            endpoint=endpoint,
            decision="deny",
            reason="unknown_demo_credential",
            request_metadata=request_metadata,
        )
        raise AuthorizationError(401, "Unknown demo API key.", event)

    view_role = requested_role or _default_view_role(principal.role)
    if view_role is None:
        event = _authorization_event(
            principal=principal,
            requested_role=requested_role,
            view_role=None,
            case_id=case_id,
            endpoint=endpoint,
            decision="deny",
            reason="no_default_view_role",
            request_metadata=request_metadata,
        )
        raise AuthorizationError(403, "No default view role is available.", event)

    allowed_roles = ROLE_VIEW_POLICY.get(principal.role, set())
    if view_role not in allowed_roles:
        event = _authorization_event(
            principal=principal,
            requested_role=requested_role,
            view_role=view_role,
            case_id=case_id,
            endpoint=endpoint,
            decision="deny",
            reason="role_view_not_allowed",
            request_metadata=request_metadata,
        )
        raise AuthorizationError(403, "Requested role view is not allowed for this caller.", event)

    event = _authorization_event(
        principal=principal,
        requested_role=requested_role,
        view_role=view_role,
        case_id=case_id,
        endpoint=endpoint,
        decision="allow",
        reason="role_view_allowed",
        request_metadata=request_metadata,
    )
    return AuthorizationResult(
        principal=principal,
        requested_role=requested_role,
        view_role=view_role,
        allowed=True,
        reason="role_view_allowed",
        audit_event=event,
    )


def _extract_credential(headers: Mapping[str, str]) -> str | None:
    demo_key = headers.get("x-threatprism-demo-key") or headers.get("X-ThreatPrism-Demo-Key")
    if demo_key:
        return demo_key.strip()
    authorization = headers.get("authorization") or headers.get("Authorization")
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return None


def _principal_for_credential(credential: str, settings: Settings) -> DemoPrincipal | None:
    for configured_credential, identity, role in _parse_demo_api_keys(settings.demo_api_keys):
        if credential == configured_credential:
            return DemoPrincipal(identity=identity, role=role, auth_mode="demo_key")
    return None


def _parse_demo_api_keys(value: str) -> list[tuple[str, str, str]]:
    entries: list[tuple[str, str, str]] = []
    for raw_entry in value.split(","):
        entry = raw_entry.strip()
        if not entry:
            continue
        parts = [part.strip() for part in entry.split(":")]
        if len(parts) != 3:
            continue
        credential, identity, role = parts
        if role in ROLE_VIEW_POLICY and credential and identity:
            entries.append((credential, identity, role))
    return entries


def _default_view_role(role: str) -> ViewRole | None:
    if role in VIEW_ROLES:
        return role  # type: ignore[return-value]
    if role == "admin":
        return "analyst"
    return None


def _authorization_event(
    *,
    principal: DemoPrincipal,
    requested_role: ViewRole | None,
    view_role: ViewRole | None,
    case_id: str | None,
    endpoint: str,
    decision: str,
    reason: str,
    request_metadata: RequestMetadata,
) -> AuditEvent:
    return AuditEvent(
        case_id=case_id,
        event_type="authorization_decision",
        actor=principal.identity,
        summary=f"Authorization decision: {decision}.",
        metadata={
            "caller_identity": principal.identity,
            "requested_role": requested_role,
            "effective_role": principal.role,
            "view_role": view_role,
            "endpoint": endpoint,
            "method": request_metadata.method,
            "case_id": case_id,
            "decision": decision,
            "reason": reason,
            "request_metadata_hash": _request_metadata_hash(request_metadata),
        },
    )


def _request_metadata_hash(request_metadata: RequestMetadata) -> str:
    payload = {
        "method": request_metadata.method,
        "path": request_metadata.path,
        "query_keys": list(request_metadata.query_keys),
        "credential_present": request_metadata.credential_present,
        "auth_mode": request_metadata.auth_mode,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"
