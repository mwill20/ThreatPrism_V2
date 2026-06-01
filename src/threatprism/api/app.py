from __future__ import annotations

import logging
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from threatprism import __version__
from threatprism.auth.demo import (
    VIEW_ROLES,
    AuthorizationError,
    DemoPrincipal,
    authorize_role_view,
)
from threatprism.auth.production import PRODUCTION_IDENTITY_AUTH_MODE
from threatprism.cases.read_models import CaseReadModelEnvelope, OperationalMetrics, ReviewQueueEnvelope
from threatprism.cases.schemas import (
    AnalystFeedbackCreate,
    AuditEvent,
    CaseAcceptedResponse,
    CaseAssignmentResponse,
    CaseSummary,
    CaseStatus,
    Determination,
    FeedbackResponse,
    Severity,
    Source,
    TriageStatus,
)
from threatprism.cases.service import CaseService
from threatprism.config import Settings
from threatprism.demo.seeding import CuratedDatasetSource, CuratedFixtureSource, DemoSeeder
from threatprism.csi.schemas import (
    AIVsHumanDivergenceEnvelope,
    CognitiveObjectDetailEnvelope,
    CognitiveObjectType,
    CognitiveObservabilitySnapshot,
    CognitiveReplayEnvelope,
    CognitiveRetrievalResponse,
    ReasoningLineageGraph,
    RetrievalContext,
    RetrievalPurpose,
    RetrievalZone,
)
from threatprism.csi.service import CognitiveRetrievalService
from threatprism.guardrails.views import ViewRole


logger = logging.getLogger(__name__)
DASHBOARD_STATIC_DIR = Path(__file__).resolve().parents[1] / "dashboard" / "static"
DASHBOARD_CONTENT_SECURITY_POLICY = "; ".join(
    [
        "default-src 'self'",
        "base-uri 'none'",
        "connect-src 'self'",
        "font-src 'self'",
        "form-action 'none'",
        "frame-ancestors 'none'",
        "img-src 'self' data:",
        "media-src 'none'",
        "object-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "worker-src 'none'",
    ]
)
DASHBOARD_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": DASHBOARD_CONTENT_SECURITY_POLICY,
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-Permitted-Cross-Domain-Policies": "none",
}

AUTH_ERROR_RESPONSES = {
    401: {"description": "Missing or invalid demo credential"},
    403: {"description": "Requested role is not authorized"},
}
CASE_ERROR_RESPONSES = {
    **AUTH_ERROR_RESPONSES,
    404: {"description": "Case not found"},
}


class InMemoryRateLimiter:
    def __init__(self, max_requests: int, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        window_start = current - self.window_seconds
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and hits[0] <= window_start:
                hits.popleft()
            if len(hits) >= self.max_requests:
                return False
            hits.append(current)
            return True


def create_app(settings: Settings | None = None) -> FastAPI:
    active_settings = settings or Settings.from_env()
    active_settings.validate_runtime()
    app = FastAPI(title="ThreatPrism API", version=__version__)
    app.state.settings = active_settings
    app.state.case_service = CaseService(active_settings)
    app.state.cognitive_service = CognitiveRetrievalService.demo()
    app.state.case_rate_limiter = InMemoryRateLimiter(active_settings.case_post_rate_limit_per_minute)
    app.state.triage_semaphore = threading.BoundedSemaphore(active_settings.triage_concurrency_limit)
    logger.info("ThreatPrism API auth mode: %s", active_settings.api_auth_mode)
    if active_settings.api_auth_mode == "none":
        logger.warning("API authentication is disabled for explicit local-development use only.")
    if active_settings.api_auth_mode == PRODUCTION_IDENTITY_AUTH_MODE:
        if active_settings.production_identity_live_verification_enabled:
            logger.info(
                "Production identity token verification is enabled with local no-network JWKS configuration."
            )
        else:
            logger.warning(
                "Production identity readiness is configured, but token verification is disabled; "
                "protected requests fail closed."
            )

    if active_settings.demo_seed_enabled:
        seeder = DemoSeeder(app.state.case_service)
        seed_result = seeder.seed([CuratedFixtureSource(), CuratedDatasetSource()])
        logger.info(
            "Demo seed complete: %d seeded, %d skipped (existing).",
            seed_result.seeded_count,
            seed_result.skipped_count,
        )

    if DASHBOARD_STATIC_DIR.exists():
        app.mount(
            "/dashboard/assets",
            StaticFiles(directory=str(DASHBOARD_STATIC_DIR)),
            name="dashboard-assets",
        )

    @app.middleware("http")
    async def request_guards(request: Request, call_next):  # noqa: ANN001
        if request.method.upper() == "POST" and request.url.path == "/cases":
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    request_size = int(content_length)
                except ValueError:
                    request_size = active_settings.max_request_body_bytes + 1
                if request_size > active_settings.max_request_body_bytes:
                    return JSONResponse(status_code=413, content={"detail": "Request body too large."})

            client_key = request.client.host if request.client else "unknown"
            if not app.state.case_rate_limiter.allow(client_key):
                return JSONResponse(status_code=429, content={"detail": "POST /cases rate limit exceeded."})

            if not content_length:
                body = await request.body()
                if len(body) > active_settings.max_request_body_bytes:
                    return JSONResponse(status_code=413, content={"detail": "Request body too large."})

                async def receive() -> dict[str, object]:
                    return {"type": "http.request", "body": body, "more_body": False}

                request = Request(request.scope, receive)
        response = await call_next(request)
        return _apply_dashboard_security_headers(response, request.url.path)

    @app.get("/health")
    def health() -> dict[str, object]:
        return {
            "status": "ok",
            "service": "threatprism-api",
            "version": __version__,
            "mode": active_settings.env,
            "allow_real_actions": active_settings.allow_real_actions,
        }

    @app.get("/dashboard", include_in_schema=False)
    def dashboard() -> FileResponse:
        if not DASHBOARD_STATIC_DIR.exists():
            raise HTTPException(status_code=404, detail="Dashboard assets are not available.")
        return FileResponse(DASHBOARD_STATIC_DIR / "index.html")

    @app.post(
        "/cases",
        response_model=CaseAcceptedResponse,
        status_code=202,
        responses={400: {"description": "Invalid case payload"}},
    )
    def create_case(
        payload: dict,
        background_tasks: BackgroundTasks,
        request: Request,
    ) -> CaseAcceptedResponse:
        service = _service(request)
        try:
            accepted = service.create_case(payload)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        background_tasks.add_task(_run_triage_with_limit, service, accepted.case_id, request.app.state.triage_semaphore)
        return accepted

    @app.get("/cases", response_model=list[CaseSummary])
    def list_cases(request: Request) -> list[CaseSummary]:
        return _service(request).list_cases()

    @app.get("/metrics", response_model=OperationalMetrics, responses=AUTH_ERROR_RESPONSES)
    def get_metrics(request: Request) -> OperationalMetrics:
        _authorized_global_view_role(request, "get_metrics", None)
        return _service(request).get_operational_metrics()

    @app.get("/csi/objects", response_model=CognitiveRetrievalResponse, responses=AUTH_ERROR_RESPONSES)
    def list_cognitive_objects(
        request: Request,
        tenant_id: str,
        query: str | None = None,
        object_type: CognitiveObjectType | None = None,
        retrieval_zone: RetrievalZone | None = None,
        purpose: RetrievalPurpose = RetrievalPurpose.analyst_investigation,
        include_stale: bool = False,
        limit: int = 20,
        role: ViewRole | None = None,
    ) -> CognitiveRetrievalResponse:
        context = _authorized_csi_context(request, "list_cognitive_objects", tenant_id, purpose, role)
        return _csi_service(request).search(
            context=context,
            query=query,
            object_type=object_type,
            retrieval_zone=retrieval_zone,
            include_stale=include_stale,
            limit=limit,
        )

    @app.get(
        "/csi/objects/{object_id}",
        response_model=CognitiveObjectDetailEnvelope,
        responses={**AUTH_ERROR_RESPONSES, 404: {"description": "Cognitive object not found or not retrievable"}},
    )
    def get_cognitive_object(
        object_id: str,
        request: Request,
        tenant_id: str,
        purpose: RetrievalPurpose = RetrievalPurpose.analyst_investigation,
        include_stale: bool = False,
        role: ViewRole | None = None,
    ) -> CognitiveObjectDetailEnvelope:
        context = _authorized_csi_context(request, "get_cognitive_object", tenant_id, purpose, role)
        detail = _csi_service(request).get_object(context=context, object_id=object_id, include_stale=include_stale)
        if detail is None:
            raise HTTPException(status_code=404, detail="Cognitive object not found or not retrievable.")
        return detail

    @app.get(
        "/csi/lineage/{object_id}",
        response_model=ReasoningLineageGraph,
        responses={**AUTH_ERROR_RESPONSES, 404: {"description": "Lineage not found or not retrievable"}},
    )
    def get_cognitive_lineage(
        object_id: str,
        request: Request,
        tenant_id: str,
        purpose: RetrievalPurpose = RetrievalPurpose.analyst_investigation,
        role: ViewRole | None = None,
    ) -> ReasoningLineageGraph:
        context = _authorized_csi_context(request, "get_cognitive_lineage", tenant_id, purpose, role)
        graph = _csi_service(request).lineage(context=context, object_id=object_id)
        if graph is None:
            raise HTTPException(status_code=404, detail="Lineage not found or not retrievable.")
        return graph

    @app.get(
        "/csi/replay/{object_id}",
        response_model=CognitiveReplayEnvelope,
        responses={**AUTH_ERROR_RESPONSES, 404: {"description": "Replay not found or not retrievable"}},
    )
    def get_cognitive_replay(
        object_id: str,
        request: Request,
        tenant_id: str,
        purpose: RetrievalPurpose = RetrievalPurpose.analyst_investigation,
        role: ViewRole | None = None,
    ) -> CognitiveReplayEnvelope:
        context = _authorized_csi_context(request, "get_cognitive_replay", tenant_id, purpose, role)
        replay = _csi_service(request).replay(context=context, object_id=object_id)
        if replay is None:
            raise HTTPException(status_code=404, detail="Replay not found or not retrievable.")
        return replay

    @app.get("/csi/observability", response_model=CognitiveObservabilitySnapshot, responses=AUTH_ERROR_RESPONSES)
    def get_cognitive_observability(
        request: Request,
        tenant_id: str,
        purpose: RetrievalPurpose = RetrievalPurpose.analyst_investigation,
        role: ViewRole | None = None,
    ) -> CognitiveObservabilitySnapshot:
        context = _authorized_csi_context(request, "get_cognitive_observability", tenant_id, purpose, role)
        return _csi_service(request).observability(context=context)

    @app.get("/csi/divergence", response_model=AIVsHumanDivergenceEnvelope, responses=AUTH_ERROR_RESPONSES)
    def get_cognitive_divergence(
        request: Request,
        tenant_id: str,
        purpose: RetrievalPurpose = RetrievalPurpose.analyst_investigation,
        role: ViewRole | None = None,
    ) -> AIVsHumanDivergenceEnvelope:
        context = _authorized_csi_context(request, "get_cognitive_divergence", tenant_id, purpose, role)
        return _csi_service(request).divergence(context=context)

    @app.get("/cases/read-model", response_model=CaseReadModelEnvelope, responses=AUTH_ERROR_RESPONSES)
    def list_case_read_models(
        request: Request,
        source: Source | None = None,
        status: CaseStatus | None = None,
        triage_status: TriageStatus | None = None,
        severity: Severity | None = None,
        determination: Determination | None = None,
        manager_review_required: bool | None = None,
        healthcare_review_required: bool | None = None,
        guardrail_blocked: bool | None = None,
        authorization_denied: bool | None = None,
        assigned_to: str | None = None,
        created_after: datetime | None = None,
        created_before: datetime | None = None,
        limit: int = 50,
        cursor: str | None = None,
        role: ViewRole | None = None,
    ) -> CaseReadModelEnvelope:
        view_role = _authorized_global_view_role(request, "list_case_read_models", role)
        return _service(request).list_case_read_models(
            source=str(source.value) if source else None,
            status=str(status.value) if status else None,
            triage_status=str(triage_status.value) if triage_status else None,
            severity=str(severity.value) if severity else None,
            determination=str(determination.value) if determination else None,
            manager_review_required=manager_review_required,
            healthcare_review_required=healthcare_review_required,
            guardrail_blocked=guardrail_blocked,
            authorization_denied=authorization_denied,
            assigned_to=assigned_to,
            created_after=created_after,
            created_before=created_before,
            limit=limit,
            cursor=cursor,
            role=view_role,
        )

    @app.get("/queues/manager-review", response_model=ReviewQueueEnvelope, responses=AUTH_ERROR_RESPONSES)
    def get_manager_review_queue(
        request: Request,
        source: Source | None = None,
        status: CaseStatus | None = None,
        triage_status: TriageStatus | None = None,
        severity: Severity | None = None,
        determination: Determination | None = None,
        guardrail_blocked: bool | None = None,
        authorization_denied: bool | None = None,
        created_after: datetime | None = None,
        created_before: datetime | None = None,
        limit: int = 50,
        cursor: str | None = None,
        role: ViewRole | None = None,
    ) -> ReviewQueueEnvelope:
        view_role = _authorized_global_view_role(request, "get_manager_review_queue", role)
        envelope = _service(request).list_case_read_models(
            source=str(source.value) if source else None,
            status=str(status.value) if status else None,
            triage_status=str(triage_status.value) if triage_status else None,
            severity=str(severity.value) if severity else None,
            determination=str(determination.value) if determination else None,
            manager_review_required=True,
            guardrail_blocked=guardrail_blocked,
            authorization_denied=authorization_denied,
            created_after=created_after,
            created_before=created_before,
            limit=limit,
            cursor=cursor,
            role=view_role,
        )
        return ReviewQueueEnvelope(queue="manager-review", **envelope.model_dump())

    @app.get("/queues/my-cases", response_model=ReviewQueueEnvelope, responses=AUTH_ERROR_RESPONSES)
    def get_my_cases(
        request: Request,
        limit: int = 50,
        cursor: str | None = None,
    ) -> ReviewQueueEnvelope:
        # The caller's own owned cases, keyed on the AUTHENTICATED identity (not a
        # query param), so a caller can only ever list their own queue. Role-view
        # masking applies at the caller's role.
        principal = _authorized_principal(request, None, "get_my_cases", _ASSIGNABLE_ROLES)
        view_role = principal.role if principal.role in VIEW_ROLES else None
        envelope = _service(request).list_case_read_models(
            assigned_to=principal.identity,
            limit=limit,
            cursor=cursor,
            role=view_role,
        )
        return ReviewQueueEnvelope(queue="my-cases", **envelope.model_dump())

    @app.get("/queues/healthcare-review", response_model=ReviewQueueEnvelope, responses=AUTH_ERROR_RESPONSES)
    def get_healthcare_review_queue(
        request: Request,
        source: Source | None = None,
        status: CaseStatus | None = None,
        triage_status: TriageStatus | None = None,
        severity: Severity | None = None,
        determination: Determination | None = None,
        guardrail_blocked: bool | None = None,
        authorization_denied: bool | None = None,
        created_after: datetime | None = None,
        created_before: datetime | None = None,
        limit: int = 50,
        cursor: str | None = None,
        role: ViewRole | None = None,
    ) -> ReviewQueueEnvelope:
        view_role = _authorized_global_view_role(request, "get_healthcare_review_queue", role)
        envelope = _service(request).list_case_read_models(
            source=str(source.value) if source else None,
            status=str(status.value) if status else None,
            triage_status=str(triage_status.value) if triage_status else None,
            severity=str(severity.value) if severity else None,
            determination=str(determination.value) if determination else None,
            healthcare_review_required=True,
            guardrail_blocked=guardrail_blocked,
            authorization_denied=authorization_denied,
            created_after=created_after,
            created_before=created_before,
            limit=limit,
            cursor=cursor,
            role=view_role,
        )
        return ReviewQueueEnvelope(queue="healthcare-review", **envelope.model_dump())

    @app.get("/cases/{case_id}", responses=CASE_ERROR_RESPONSES)
    def get_case(case_id: str, request: Request, role: ViewRole | None = None) -> dict:
        view_role = _authorized_view_role(request, case_id, "get_case", role)
        if view_role is not None:
            view = _service(request).get_case_view(case_id, view_role)
            if view is None:
                raise HTTPException(status_code=404, detail="Case not found")
            return view
        case = _service(request).get_case(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return case.model_dump(mode="json")

    @app.get("/cases/{case_id}/triage-report", responses=CASE_ERROR_RESPONSES)
    def get_triage_report(case_id: str, request: Request, role: ViewRole | None = None) -> dict:
        view_role = _authorized_view_role(request, case_id, "get_triage_report", role)
        case = _service(request).get_case(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="Case not found")
        report = _service(request).get_report(case_id)
        if report is None:
            message = "Triage report is not ready."
            if case.triage_status == TriageStatus.blocked_by_guardrail and any(
                event.event_type == "triage_blocked_by_prompt_firewall" for event in case.audit_trail
            ):
                message = "Triage was blocked by the prompt firewall."
            return {
                "case_id": case_id,
                "status": case.triage_status,
                "message": message,
            }
        if view_role is not None:
            view = _service(request).get_report_view(case_id, view_role)
            if view is None:
                raise HTTPException(status_code=404, detail="Triage report not found")
            return view
        return report.model_dump(mode="json")

    @app.get("/cases/{case_id}/evidence", responses=CASE_ERROR_RESPONSES)
    def get_case_evidence(case_id: str, request: Request, role: ViewRole | None = None) -> dict:
        view_role = _authorized_view_role(request, case_id, "get_case_evidence", role)
        view = _service(request).get_evidence_view(case_id, view_role)
        if view is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return view

    @app.get("/cases/{case_id}/timeline", responses=CASE_ERROR_RESPONSES)
    def get_case_timeline(case_id: str, request: Request, role: ViewRole | None = None) -> dict:
        view_role = _authorized_view_role(request, case_id, "get_case_timeline", role)
        view = _service(request).get_timeline_view(case_id, view_role)
        if view is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return view

    @app.get("/cases/{case_id}/mitre", responses=CASE_ERROR_RESPONSES)
    def get_case_mitre(case_id: str, request: Request, role: ViewRole | None = None) -> dict:
        view_role = _authorized_view_role(request, case_id, "get_case_mitre", role)
        view = _service(request).get_mitre_view(case_id, view_role)
        if view is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return view

    @app.get("/cases/{case_id}/grc-controls", responses=CASE_ERROR_RESPONSES)
    def get_case_grc_controls(case_id: str, request: Request, role: ViewRole | None = None) -> dict:
        view_role = _authorized_view_role(request, case_id, "get_case_grc_controls", role)
        view = _service(request).get_grc_controls_view(case_id, view_role)
        if view is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return view

    @app.get("/cases/{case_id}/audit-events", responses=CASE_ERROR_RESPONSES)
    def get_case_audit_events(case_id: str, request: Request, role: ViewRole | None = None) -> dict:
        view_role = _authorized_view_role(request, case_id, "get_case_audit_events", role)
        view = _service(request).get_audit_events_view(case_id, view_role)
        if view is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return view

    @app.post(
        "/cases/{case_id}/analyst-feedback",
        response_model=FeedbackResponse,
        responses={404: {"description": "Case not found"}},
    )
    def submit_feedback(
        case_id: str,
        feedback: AnalystFeedbackCreate,
        request: Request,
    ) -> FeedbackResponse:
        try:
            return _service(request).submit_feedback(case_id, feedback)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Case not found") from exc

    @app.post(
        "/cases/{case_id}/assign",
        response_model=CaseAssignmentResponse,
        responses=CASE_ERROR_RESPONSES,
    )
    def assign_case(case_id: str, request: Request) -> CaseAssignmentResponse:
        principal = _authorized_principal(request, case_id, "assign_case", _ASSIGNABLE_ROLES)
        try:
            return _service(request).assign_case(
                case_id, actor_identity=principal.identity, actor_role=principal.role
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Case not found") from exc

    @app.post(
        "/cases/{case_id}/release",
        response_model=CaseAssignmentResponse,
        responses=CASE_ERROR_RESPONSES,
    )
    def release_case(case_id: str, request: Request) -> CaseAssignmentResponse:
        principal = _authorized_principal(request, case_id, "release_case", _ASSIGNABLE_ROLES)
        try:
            return _service(request).release_case(
                case_id, actor_identity=principal.identity, actor_role=principal.role
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Case not found") from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    return app


def _service(request: Request) -> CaseService:
    return request.app.state.case_service


def _csi_service(request: Request) -> CognitiveRetrievalService:
    return request.app.state.cognitive_service


def _apply_dashboard_security_headers(response: Response, path: str) -> Response:
    if path == "/dashboard" or path.startswith("/dashboard/"):
        for header, value in DASHBOARD_SECURITY_HEADERS.items():
            response.headers[header] = value
    return response


def _run_triage_with_limit(service: CaseService, case_id: str, semaphore: threading.BoundedSemaphore) -> None:
    with semaphore:
        service.run_triage(case_id)


def _authorized_view_role(
    request: Request,
    case_id: str,
    endpoint: str,
    requested_role: ViewRole | None,
) -> ViewRole | None:
    service = _service(request)
    settings: Settings = request.app.state.settings
    try:
        result = authorize_role_view(
            settings=settings,
            headers=request.headers,
            method=request.method,
            path=request.url.path,
            query_keys=list(request.query_params.keys()),
            requested_role=requested_role,
            case_id=case_id,
            endpoint=endpoint,
        )
    except AuthorizationError as exc:
        if exc.audit_event is not None:
            service.record_audit_event(case_id, exc.audit_event)
        raise HTTPException(status_code=exc.status_code, detail=exc.reason) from exc

    if result.audit_event is not None:
        service.record_audit_event(case_id, result.audit_event)
    return result.view_role


def _authorized_global_view_role(
    request: Request,
    endpoint: str,
    requested_role: ViewRole | None,
) -> ViewRole | None:
    settings: Settings = request.app.state.settings
    try:
        result = authorize_role_view(
            settings=settings,
            headers=request.headers,
            method=request.method,
            path=request.url.path,
            query_keys=list(request.query_params.keys()),
            requested_role=requested_role,
            case_id=None,
            endpoint=endpoint,
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.reason) from exc
    return result.view_role


# Roles permitted to own/work a case (Evolution 3). Non-working roles (manager_grc,
# legal_privacy, audit_debug, ai) cannot self-assign.
_ASSIGNABLE_ROLES = frozenset({"analyst", "engineer", "admin"})


def _authorized_principal(
    request: Request,
    case_id: str,
    endpoint: str,
    allowed_roles: frozenset[str],
) -> DemoPrincipal:
    """Authenticate the caller for a mutating case action and enforce a role
    allowlist. Records the auth audit (allow) and a deny audit on role refusal —
    every authorization decision is audited on the case."""
    service = _service(request)
    settings: Settings = request.app.state.settings
    try:
        result = authorize_role_view(
            settings=settings,
            headers=request.headers,
            method=request.method,
            path=request.url.path,
            query_keys=list(request.query_params.keys()),
            requested_role=None,
            case_id=case_id,
            endpoint=endpoint,
        )
    except AuthorizationError as exc:
        if exc.audit_event is not None:
            service.record_audit_event(case_id, exc.audit_event)
        raise HTTPException(status_code=exc.status_code, detail=exc.reason) from exc

    if result.audit_event is not None:
        service.record_audit_event(case_id, result.audit_event)
    if result.principal.role not in allowed_roles:
        service.record_audit_event(
            case_id,
            AuditEvent(
                case_id=case_id,
                event_type="authorization_denied",
                actor=result.principal.identity,
                summary=f"Role '{result.principal.role}' is not authorized for {endpoint}.",
                metadata={"endpoint": endpoint, "effective_role": result.principal.role, "decision": "deny"},
            ),
        )
        raise HTTPException(
            status_code=403,
            detail=f"Role '{result.principal.role}' is not authorized to {endpoint.replace('_', ' ')}.",
        )
    return result.principal


def _authorized_csi_context(
    request: Request,
    endpoint: str,
    tenant_id: str,
    purpose: RetrievalPurpose,
    requested_role: ViewRole | None,
) -> RetrievalContext:
    settings: Settings = request.app.state.settings
    try:
        result = authorize_role_view(
            settings=settings,
            headers=request.headers,
            method=request.method,
            path=request.url.path,
            query_keys=list(request.query_params.keys()),
            requested_role=requested_role,
            case_id=None,
            endpoint=endpoint,
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.reason) from exc

    view_role: ViewRole = result.view_role or requested_role or "analyst"
    return RetrievalContext(
        tenant_id=tenant_id,
        principal_id=result.principal.identity,
        effective_role=result.principal.role,
        view_role=view_role,
        purpose=purpose,
    )
