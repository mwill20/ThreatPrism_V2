from __future__ import annotations

from datetime import datetime

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request

from threatprism import __version__
from threatprism.auth.demo import AuthorizationError, authorize_role_view
from threatprism.cases.read_models import CaseReadModelEnvelope, OperationalMetrics
from threatprism.cases.schemas import (
    AnalystFeedbackCreate,
    CaseAcceptedResponse,
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
from threatprism.guardrails.views import ViewRole


def create_app(settings: Settings | None = None) -> FastAPI:
    active_settings = settings or Settings.from_env()
    app = FastAPI(title="ThreatPrism API", version=__version__)
    app.state.settings = active_settings
    app.state.case_service = CaseService(active_settings)

    @app.get("/health")
    def health() -> dict[str, object]:
        return {
            "status": "ok",
            "service": "threatprism-api",
            "version": __version__,
            "mode": active_settings.env,
            "allow_real_actions": active_settings.allow_real_actions,
        }

    @app.post("/cases", response_model=CaseAcceptedResponse, status_code=202)
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
        background_tasks.add_task(service.run_triage, accepted.case_id)
        return accepted

    @app.get("/cases", response_model=list[CaseSummary])
    def list_cases(request: Request) -> list[CaseSummary]:
        return _service(request).list_cases()

    @app.get("/metrics", response_model=OperationalMetrics)
    def get_metrics(request: Request) -> OperationalMetrics:
        _authorized_global_view_role(request, "get_metrics", None)
        return _service(request).get_operational_metrics()

    @app.get("/cases/read-model", response_model=CaseReadModelEnvelope)
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
            created_after=created_after,
            created_before=created_before,
            limit=limit,
            cursor=cursor,
            role=view_role,
        )

    @app.get("/cases/{case_id}")
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

    @app.get("/cases/{case_id}/triage-report")
    def get_triage_report(case_id: str, request: Request, role: ViewRole | None = None) -> dict:
        view_role = _authorized_view_role(request, case_id, "get_triage_report", role)
        case = _service(request).get_case(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="Case not found")
        report = _service(request).get_report(case_id)
        if report is None:
            return {
                "case_id": case_id,
                "status": case.triage_status,
                "message": "Triage report is not ready.",
            }
        if view_role is not None:
            view = _service(request).get_report_view(case_id, view_role)
            if view is None:
                raise HTTPException(status_code=404, detail="Triage report not found")
            return view
        return report.model_dump(mode="json")

    @app.get("/cases/{case_id}/evidence")
    def get_case_evidence(case_id: str, request: Request, role: ViewRole | None = None) -> dict:
        view_role = _authorized_view_role(request, case_id, "get_case_evidence", role)
        view = _service(request).get_evidence_view(case_id, view_role)
        if view is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return view

    @app.get("/cases/{case_id}/timeline")
    def get_case_timeline(case_id: str, request: Request, role: ViewRole | None = None) -> dict:
        view_role = _authorized_view_role(request, case_id, "get_case_timeline", role)
        view = _service(request).get_timeline_view(case_id, view_role)
        if view is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return view

    @app.get("/cases/{case_id}/mitre")
    def get_case_mitre(case_id: str, request: Request, role: ViewRole | None = None) -> dict:
        view_role = _authorized_view_role(request, case_id, "get_case_mitre", role)
        view = _service(request).get_mitre_view(case_id, view_role)
        if view is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return view

    @app.get("/cases/{case_id}/grc-controls")
    def get_case_grc_controls(case_id: str, request: Request, role: ViewRole | None = None) -> dict:
        view_role = _authorized_view_role(request, case_id, "get_case_grc_controls", role)
        view = _service(request).get_grc_controls_view(case_id, view_role)
        if view is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return view

    @app.get("/cases/{case_id}/audit-events")
    def get_case_audit_events(case_id: str, request: Request, role: ViewRole | None = None) -> dict:
        view_role = _authorized_view_role(request, case_id, "get_case_audit_events", role)
        view = _service(request).get_audit_events_view(case_id, view_role)
        if view is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return view

    @app.post("/cases/{case_id}/analyst-feedback", response_model=FeedbackResponse)
    def submit_feedback(
        case_id: str,
        feedback: AnalystFeedbackCreate,
        request: Request,
    ) -> FeedbackResponse:
        try:
            return _service(request).submit_feedback(case_id, feedback)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Case not found") from exc

    return app


def _service(request: Request) -> CaseService:
    return request.app.state.case_service


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
