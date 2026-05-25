from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import datetime
from typing import Any

from threatprism.cases.read_models import (
    CaseCountMetrics,
    CaseReadModelEnvelope,
    CaseReadModelItem,
    DisagreementMetrics,
    GrcMetrics,
    GuardrailMetrics,
    MetricsWindow,
    OperationalMetrics,
    ReportDecisionMetrics,
    SafeAuditEvent,
    TimingMetrics,
    TriageReadSummary,
    TriageStatusMetrics,
)
from threatprism.cases.schemas import (
    AnalystFeedback,
    AnalystFeedbackCreate,
    AuditEvent,
    CaseAcceptedResponse,
    CaseRecord,
    CaseStatus,
    CaseSummary,
    DisagreementRecord,
    FeedbackResponse,
    SanitizationRecord,
    TriageReport,
    TriageStatus,
    utc_now,
)
from threatprism.config import Settings
from threatprism.guardrails.evidence import validate_report_evidence
from threatprism.guardrails.healthcare import safeguard_value
from threatprism.guardrails.policy import enforce_action_safety, scan_output_policy
from threatprism.guardrails.prompt_firewall import sanitize_text
from threatprism.guardrails.tokenization import TokenVault, rehydrate_text, tokenize_text
from threatprism.guardrails.views import RoleViewResult, ViewRole, render_role_view
from threatprism.ids import new_id
from threatprism.llm.providers import get_provider
from threatprism.persistence.sqlite import SQLiteRepository
from threatprism.reports.render import render_report
from threatprism.soar.generic import normalize_soar_payload


class CaseService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.repository = SQLiteRepository(settings.database_url)
        self.provider = get_provider(settings.llm_provider)

    def create_case(self, payload: dict[str, Any]) -> CaseAcceptedResponse:
        case_create = normalize_soar_payload(payload)
        source_hash = _payload_hash(payload)
        case_id = new_id("case")
        case = CaseRecord.model_validate(
            {
                **case_create.model_dump(mode="json", exclude_none=True),
                "case_id": case_id,
                "source_payload_hash": f"sha256:{source_hash}",
                "status": CaseStatus.queued_for_triage,
                "triage_status": TriageStatus.queued,
                "audit_trail": [
                    AuditEvent(
                        event_type="case_created",
                        summary="Case accepted from generic SOAR payload.",
                        metadata={"source_payload_hash": f"sha256:{source_hash}"},
                    ).model_dump(mode="json")
                ],
            }
        )
        case = self._apply_healthcare_safeguards(case)
        for audit_event in case.audit_trail:
            audit_event.case_id = case.case_id
        self.repository.save_case(case)
        tracking_id = new_id("triage")
        return CaseAcceptedResponse(
            case_id=case.case_id,
            source=case.source,
            source_case_id=case.source_case_id,
            status=case.status,
            triage_status=case.triage_status,
            tracking_id=tracking_id,
            created_at=case.created_at,
            links={
                "case": f"/cases/{case.case_id}",
                "triage_report": f"/cases/{case.case_id}/triage-report",
                "analyst_feedback": f"/cases/{case.case_id}/analyst-feedback",
            },
        )

    def _apply_healthcare_safeguards(self, case: CaseRecord) -> CaseRecord:
        scan = safeguard_value(case.model_dump(mode="json"), case_id=case.case_id)
        safeguarded = CaseRecord.model_validate(scan.value)
        safeguarded.sanitization_records.extend(scan.records)
        if scan.records:
            safeguarded.source_metadata["healthcare_safeguard"] = scan.summary
            safeguarded.audit_trail.append(
                AuditEvent(
                    case_id=safeguarded.case_id,
                    event_type="healthcare_safeguard_applied",
                    summary="Inbound case content was scanned for accidental healthcare data exposure.",
                    metadata=scan.summary,
                )
            )
            safeguarded.audit_trail.append(
                AuditEvent(
                    case_id=safeguarded.case_id,
                    event_type="sensitive_data_tokenized",
                    summary="Sensitive-looking inbound values were replaced with typed tokens.",
                    metadata=scan.summary,
                )
            )
            if scan.summary.get("secret_exposure_detected"):
                safeguarded.audit_trail.append(
                    AuditEvent(
                        case_id=safeguarded.case_id,
                        event_type="secret_exposure_detected",
                        summary="Inbound case content contained a secret-like value and was tokenized.",
                        metadata={
                            "detectors": scan.summary.get("detectors", {}),
                            "field_paths": scan.summary.get("field_paths", []),
                        },
                    )
                )
        return safeguarded

    def run_triage(self, case_id: str) -> None:
        case = self.repository.get_case(case_id)
        if case is None:
            return

        case.status = CaseStatus.triage_running
        case.triage_status = TriageStatus.running
        case.updated_at = utc_now()
        self.repository.save_case(case)

        tokenized_case, records, vault = self._prepare_case_for_model(case)
        case.sanitization_records.extend(records)
        quarantine_records = [record for record in records if record.operation == "quarantine"]
        if quarantine_records:
            case.status = CaseStatus.needs_analyst_review
            case.triage_status = TriageStatus.blocked_by_guardrail
            case.audit_trail.append(
                AuditEvent(
                    case_id=case.case_id,
                    event_type="triage_blocked_by_prompt_firewall",
                    summary="Triage was blocked before provider execution by the prompt firewall.",
                    metadata={
                        "field_paths": sorted({record.field_path for record in quarantine_records}),
                        "flags": sorted(
                            {
                                flag
                                for record in quarantine_records
                                for flag in record.metadata.get("flags", [])
                            }
                        ),
                    },
                )
            )
            case.updated_at = utc_now()
            self.repository.save_case(case)
            return

        report = self.provider.generate_report(tokenized_case)
        issues = []
        issues.extend(scan_output_policy(report.model_dump(mode="json")))
        issues.extend(validate_report_evidence(report, {item.evidence_id for item in tokenized_case.evidence}))
        issues.extend(enforce_action_safety(report.model_dump(mode="json")))

        if issues:
            case.status = CaseStatus.needs_analyst_review
            case.triage_status = TriageStatus.blocked_by_guardrail
            case.audit_trail.append(
                AuditEvent(
                    case_id=case.case_id,
                    event_type="triage_blocked_by_guardrail",
                    summary="Triage output was blocked by guardrail validation.",
                    metadata={"issues": issues},
                )
            )
            case.updated_at = utc_now()
            self.repository.save_case(case)
            return

        report = self._rehydrate_report(report, vault)
        self._append_rehydration_audit(case, records)
        report.rendered_report = render_report(report)

        case.status = CaseStatus.triage_completed
        case.triage_status = TriageStatus.completed
        case.triage_report = report
        case.timeline = report.timeline
        case.hypotheses = report.hypotheses
        case.mitre_mappings = report.mitre_mappings
        case.recommended_actions = report.recommended_actions
        case.simulated_actions = report.simulated_actions
        case.grc_controls = report.grc_controls
        case.audit_trail.append(
            AuditEvent(
                case_id=case.case_id,
                event_type="triage_report_validated",
                summary="Triage report passed schema, policy, evidence, and action-safety validation.",
                metadata={"report_id": report.report_id},
            )
        )
        case.updated_at = utc_now()
        self.repository.save_report(report)
        self.repository.save_case(case)

    def list_cases(self) -> list[CaseSummary]:
        return [self._summary(case) for case in self.repository.list_cases()]

    def get_operational_metrics(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> OperationalMetrics:
        cases = self._cases_in_window(self.repository.list_cases(), start, end)
        case_ids = {case.case_id for case in cases}
        feedback = [
            item
            for item in self.repository.list_feedback()
            if item.case_id in case_ids
        ]
        disagreements = [
            item
            for item in self.repository.list_disagreements()
            if item.case_id in case_ids
        ]

        case_counts = CaseCountMetrics(total=len(cases))
        triage = TriageStatusMetrics()
        report_decisions = ReportDecisionMetrics()
        guardrails = GuardrailMetrics()
        grc = GrcMetrics()

        for case in cases:
            _increment(case_counts.by_source, _enum_value(case.source))
            _increment(case_counts.by_status, _enum_value(case.status))
            setattr(
                triage,
                _enum_value(case.triage_status),
                getattr(triage, _enum_value(case.triage_status)) + 1,
            )

            report = case.triage_report
            if report is not None:
                _increment(report_decisions.determination, _enum_value(report.determination))
                _increment(report_decisions.severity, _enum_value(report.severity))
                _increment(report_decisions.disposition, _enum_value(report.disposition))
                for control in report.grc_controls:
                    grc.mapping_count += 1
                    if control.evidence_ids:
                        grc.mappings_with_evidence_count += 1
                    if control.review_required:
                        grc.review_required_count += 1

            if self._case_guardrail_blocked(case):
                guardrails.blocked_cases += 1
            healthcare_summary = self._healthcare_safeguard_summary(case)
            if healthcare_summary.get("privacy_legal_review_required"):
                guardrails.healthcare_review_required += 1
            if healthcare_summary.get("potential_sensitive_data_exposure"):
                guardrails.potential_sensitive_data_exposure += 1
            if healthcare_summary.get("secret_exposure_detected"):
                guardrails.secret_exposure_detected += 1

            for event in case.audit_trail:
                if event.event_type == "rehydration_denied":
                    guardrails.rehydration_denied_events += 1
                elif event.event_type == "role_view_policy_applied":
                    guardrails.role_view_policy_applied_events += 1
                elif event.event_type == "authorization_decision":
                    if event.metadata.get("decision") == "allow":
                        guardrails.authorization_allowed_events += 1
                    elif event.metadata.get("decision") == "deny":
                        guardrails.authorization_denied_events += 1

        timing = TimingMetrics(
            average_time_to_acknowledge_seconds=_average(
                item.time_to_acknowledge_seconds for item in feedback
            ),
            average_time_to_close_seconds=_average(item.time_to_close_seconds for item in feedback),
        )
        disagreement_metrics = DisagreementMetrics(
            feedback_count=len(feedback),
            determination_mismatch_count=sum(item.determination_mismatch for item in disagreements),
            severity_mismatch_count=sum(item.severity_mismatch for item in disagreements),
            disposition_mismatch_count=sum(item.disposition_mismatch for item in disagreements),
            manager_review_required_count=sum(item.manager_review_required for item in disagreements),
        )
        return OperationalMetrics(
            window=MetricsWindow(start=start, end=end),
            case_counts=case_counts,
            triage=triage,
            report_decisions=report_decisions,
            guardrails=guardrails,
            disagreement=disagreement_metrics,
            timing=timing,
            grc=grc,
        )

    def list_case_read_models(
        self,
        *,
        source: str | None = None,
        status: str | None = None,
        triage_status: str | None = None,
        severity: str | None = None,
        determination: str | None = None,
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
        disagreements = self.repository.list_disagreements()
        items = [
            self._case_read_model_item(case, disagreements)
            for case in self._cases_in_window(
                self.repository.list_cases(),
                created_after,
                created_before,
            )
        ]
        filters = {
            "source": source,
            "status": status,
            "triage_status": triage_status,
            "severity": severity,
            "determination": determination,
            "manager_review_required": manager_review_required,
            "healthcare_review_required": healthcare_review_required,
            "guardrail_blocked": guardrail_blocked,
            "authorization_denied": authorization_denied,
            "created_after": created_after.isoformat() if created_after else None,
            "created_before": created_before.isoformat() if created_before else None,
            "limit": limit,
            "cursor": cursor,
        }
        filtered = [
            item
            for item in items
            if _matches_filter(_enum_value(item.source), source)
            and _matches_filter(_enum_value(item.status), status)
            and _matches_filter(_enum_value(item.triage_status), triage_status)
            and _matches_filter(item.triage.severity if item.triage else None, severity)
            and _matches_filter(item.triage.determination if item.triage else None, determination)
            and _matches_bool(item.manager_review_required, manager_review_required)
            and _matches_bool(item.healthcare_review_required, healthcare_review_required)
            and _matches_bool(item.guardrail_blocked, guardrail_blocked)
            and _matches_bool(item.authorization_denied, authorization_denied)
        ]
        envelope = CaseReadModelEnvelope(
            items=filtered[: max(0, limit)],
            total=len(filtered),
            next_cursor=None,
            filters={key: value for key, value in filters.items() if value is not None},
        )
        if role is None:
            return envelope
        result = render_role_view(envelope, role)
        payload = _payload_with_role_view_metadata(result.payload, result.metadata)
        return CaseReadModelEnvelope.model_validate(payload)

    def get_evidence_view(self, case_id: str, role: ViewRole | None = None) -> dict[str, Any] | None:
        case = self.repository.get_case(case_id)
        if case is None:
            return None
        return self._detail_view(case, "evidence", case.evidence, role)

    def get_timeline_view(self, case_id: str, role: ViewRole | None = None) -> dict[str, Any] | None:
        case = self.repository.get_case(case_id)
        if case is None:
            return None
        return self._detail_view(case, "timeline", case.timeline, role)

    def get_mitre_view(self, case_id: str, role: ViewRole | None = None) -> dict[str, Any] | None:
        case = self.repository.get_case(case_id)
        if case is None:
            return None
        return self._detail_view(case, "mitre_mappings", case.mitre_mappings, role)

    def get_grc_controls_view(self, case_id: str, role: ViewRole | None = None) -> dict[str, Any] | None:
        case = self.repository.get_case(case_id)
        if case is None:
            return None
        return self._detail_view(case, "grc_controls", case.grc_controls, role)

    def get_audit_events_view(self, case_id: str, role: ViewRole | None = None) -> dict[str, Any] | None:
        case = self.repository.get_case(case_id)
        if case is None:
            return None
        events = [
            SafeAuditEvent.model_validate(event.model_dump(mode="json"))
            for event in case.audit_trail
        ]
        return self._detail_view(case, "audit_events", events, role)

    def get_case(self, case_id: str) -> CaseRecord | None:
        return self.repository.get_case(case_id)

    def get_case_view(self, case_id: str, role: ViewRole) -> dict[str, Any] | None:
        case = self.repository.get_case(case_id)
        if case is None:
            return None
        result = render_role_view(case, role, case_id=case_id)
        self._record_role_view_audit(case, result)
        return _payload_with_role_view_metadata(result.payload, result.metadata)

    def get_report(self, case_id: str) -> TriageReport | None:
        return self.repository.get_report(case_id)

    def get_report_view(self, case_id: str, role: ViewRole) -> dict[str, Any] | None:
        report = self.repository.get_report(case_id)
        if report is None:
            return None
        case = self.repository.get_case(case_id)
        if case is not None:
            result = render_role_view(report, role, case_id=case_id)
            self._record_role_view_audit(case, result)
            return _payload_with_role_view_metadata(result.payload, result.metadata)
        result = render_role_view(report, role, case_id=case_id)
        return _payload_with_role_view_metadata(result.payload, result.metadata)

    def record_audit_event(self, case_id: str, audit_event: AuditEvent) -> None:
        case = self.repository.get_case(case_id)
        if case is None:
            return
        case.audit_trail.append(audit_event)
        case.updated_at = utc_now()
        self.repository.save_case(case)

    def submit_feedback(self, case_id: str, feedback_create: AnalystFeedbackCreate) -> FeedbackResponse:
        case = self.repository.get_case(case_id)
        if case is None:
            raise KeyError(case_id)
        report = self.repository.get_report(case_id)
        feedback = AnalystFeedback(
            **feedback_create.model_dump(mode="json"),
            case_id=case_id,
            report_id=report.report_id if report else None,
        )
        disagreement = self._disagreement(case_id, feedback, report)
        case.status = CaseStatus.analyst_feedback_submitted
        case.analyst_feedback.append(feedback)
        case.audit_trail.append(
            AuditEvent(
                case_id=case.case_id,
                event_type="analyst_feedback_submitted",
                summary="Analyst feedback and disagreement metrics were recorded.",
                metadata={"feedback_id": feedback.feedback_id},
            )
        )
        case.updated_at = utc_now()
        self.repository.save_feedback(feedback, disagreement)
        self.repository.save_case(case)
        return FeedbackResponse(
            feedback_id=feedback.feedback_id,
            case_id=case_id,
            recorded_at=feedback.created_at,
            disagreement=disagreement,
        )

    def _prepare_case_for_model(self, case: CaseRecord) -> tuple[CaseRecord, list[SanitizationRecord], TokenVault]:
        tokenized = deepcopy(case)
        vault = TokenVault(case_id=case.case_id)
        records: list[SanitizationRecord] = []

        tokenized.title, records = self._sanitize_and_tokenize_text(
            tokenized.title, vault, "title", None, records
        )
        tokenized.description, records = self._sanitize_and_tokenize_text(
            tokenized.description, vault, "description", None, records
        )
        for idx, event in enumerate(tokenized.events):
            event.description, records = self._sanitize_and_tokenize_text(
                event.description, vault, f"events[{idx}].description", None, records
            )
            for key, value in list(event.normalized.items()):
                if isinstance(value, str):
                    event.normalized[key], records = self._sanitize_and_tokenize_text(
                        value, vault, f"events[{idx}].normalized.{key}", None, records
                    )
        for idx, evidence in enumerate(tokenized.evidence):
            evidence.summary, records = self._sanitize_and_tokenize_text(
                evidence.summary,
                vault,
                f"evidence[{idx}].summary",
                evidence.evidence_id,
                records,
            )
            if evidence.excerpt:
                evidence.excerpt, records = self._sanitize_and_tokenize_text(
                    evidence.excerpt,
                    vault,
                    f"evidence[{idx}].excerpt",
                    evidence.evidence_id,
                    records,
                )
        for idx, entity in enumerate(tokenized.entities):
            entity.value, records = self._sanitize_and_tokenize_text(
                entity.value, vault, f"entities[{idx}].value", None, records
            )
        for idx, ioc in enumerate(tokenized.iocs):
            ioc.value, records = self._sanitize_and_tokenize_text(
                ioc.value, vault, f"iocs[{idx}].value", None, records
            )
        records.extend(vault.records)
        return tokenized, records, vault

    def _sanitize_and_tokenize_text(
        self,
        text: str,
        vault: TokenVault,
        field_path: str,
        evidence_id: str | None,
        records: list[SanitizationRecord],
    ) -> tuple[str, list[SanitizationRecord]]:
        sanitized, flags, quarantined = sanitize_text(text)
        if flags:
            records.append(
                SanitizationRecord(
                    case_id=vault.case_id,
                    evidence_id=evidence_id,
                    operation="quarantine" if quarantined else "redact",
                    field_path=field_path,
                    rehydration_allowed=False,
                    metadata={"flags": flags},
                )
            )
        return tokenize_text(sanitized, vault, field_path, evidence_id), records

    def _rehydrate_report(self, report: TriageReport, vault: TokenVault) -> TriageReport:
        payload = report.model_dump(mode="json")
        return TriageReport.model_validate(_rehydrate_value(payload, vault))

    def _disagreement(
        self,
        case_id: str,
        feedback: AnalystFeedback,
        report: TriageReport | None,
    ) -> DisagreementRecord:
        reasons: list[str] = []
        determination_mismatch = bool(report and report.determination != feedback.analyst_determination)
        severity_mismatch = bool(report and report.severity != feedback.analyst_severity)
        disposition_mismatch = bool(report and report.disposition != feedback.analyst_final_disposition)
        confidence_delta = abs((report.confidence if report else 0.0) - feedback.analyst_confidence)

        if determination_mismatch:
            reasons.append("ThreatPrism determination differs from analyst determination.")
        if severity_mismatch:
            reasons.append("ThreatPrism severity differs from analyst severity.")
        if disposition_mismatch:
            reasons.append("ThreatPrism disposition differs from analyst final disposition.")
        manager_review_required = (
            feedback.manager_review_required
            or determination_mismatch
            or severity_mismatch
            or disposition_mismatch
            or feedback.false_negative
            or feedback.missed_escalation
        )
        return DisagreementRecord(
            case_id=case_id,
            feedback_id=feedback.feedback_id,
            determination_mismatch=determination_mismatch,
            severity_mismatch=severity_mismatch,
            disposition_mismatch=disposition_mismatch,
            confidence_delta=round(confidence_delta, 4),
            manager_review_required=manager_review_required,
            reasons=reasons,
        )

    def _append_rehydration_audit(self, case: CaseRecord, records: list[SanitizationRecord]) -> None:
        approved = [
            record
            for record in records
            if record.operation == "tokenize" and record.token and record.rehydration_allowed
        ]
        denied = [
            record
            for record in records
            if record.operation == "tokenize" and record.token and not record.rehydration_allowed
        ]
        if approved:
            case.audit_trail.append(
                AuditEvent(
                    case_id=case.case_id,
                    event_type="rehydration_approved",
                    summary="Validated report rehydrated approved security telemetry tokens.",
                    metadata=_token_record_summary(approved),
                )
            )
        if denied:
            case.audit_trail.append(
                AuditEvent(
                    case_id=case.case_id,
                    event_type="rehydration_denied",
                    summary="Non-rehydratable tokens remained redacted after report validation.",
                    metadata=_token_record_summary(denied),
                )
            )

    def _record_role_view_audit(self, case: CaseRecord, result: RoleViewResult) -> None:
        case.audit_trail.extend(result.audit_events)
        case.updated_at = utc_now()
        self.repository.save_case(case)

    def _detail_view(
        self,
        case: CaseRecord,
        detail_name: str,
        items: Any,
        role: ViewRole | None,
    ) -> dict[str, Any]:
        payload = {
            "case_id": case.case_id,
            "detail": detail_name,
            "items": _json_payload(items),
        }
        if role is None:
            return payload
        result = render_role_view(payload, role, case_id=case.case_id)
        self._record_role_view_audit(case, result)
        return _payload_with_role_view_metadata(result.payload, result.metadata)

    def _case_read_model_item(
        self,
        case: CaseRecord,
        disagreements: list[DisagreementRecord],
    ) -> CaseReadModelItem:
        report = case.triage_report
        triage = None
        if report is not None:
            triage = TriageReadSummary(
                determination=_enum_value(report.determination),
                severity=_enum_value(report.severity),
                disposition=_enum_value(report.disposition),
                confidence=report.confidence,
            )
        return CaseReadModelItem(
            case_id=case.case_id,
            source=case.source,
            source_case_id=case.source_case_id,
            title=case.title,
            status=case.status,
            triage_status=case.triage_status,
            triage=triage,
            manager_review_required=self._case_manager_review_required(case, disagreements),
            healthcare_review_required=bool(
                self._healthcare_safeguard_summary(case).get("privacy_legal_review_required")
            ),
            guardrail_blocked=self._case_guardrail_blocked(case),
            authorization_denied=self._case_authorization_denied(case),
            created_at=case.created_at,
            updated_at=case.updated_at,
        )

    def _cases_in_window(
        self,
        cases: list[CaseRecord],
        start: datetime | None,
        end: datetime | None,
    ) -> list[CaseRecord]:
        return [
            case
            for case in cases
            if (start is None or case.created_at >= start)
            and (end is None or case.created_at <= end)
        ]

    def _case_manager_review_required(
        self,
        case: CaseRecord,
        disagreements: list[DisagreementRecord] | None = None,
    ) -> bool:
        active_disagreements = disagreements if disagreements is not None else self.repository.list_disagreements()
        return any(
            item.case_id == case.case_id and item.manager_review_required
            for item in active_disagreements
        )

    def _case_guardrail_blocked(self, case: CaseRecord) -> bool:
        return case.triage_status == TriageStatus.blocked_by_guardrail or any(
            event.event_type == "triage_blocked_by_guardrail" for event in case.audit_trail
        )

    def _case_authorization_denied(self, case: CaseRecord) -> bool:
        return any(
            event.event_type == "authorization_decision"
            and event.metadata.get("decision") == "deny"
            for event in case.audit_trail
        )

    def _healthcare_safeguard_summary(self, case: CaseRecord) -> dict[str, Any]:
        summary = case.source_metadata.get("healthcare_safeguard")
        if isinstance(summary, dict):
            return summary
        return {}

    def _summary(self, case: CaseRecord) -> CaseSummary:
        report = case.triage_report
        triage = None
        if report:
            triage = {
                "determination": report.determination,
                "severity": report.severity,
                "disposition": report.disposition,
                "confidence": report.confidence,
            }
        return CaseSummary(
            case_id=case.case_id,
            source=case.source,
            source_case_id=case.source_case_id,
            title=case.title,
            status=case.status,
            triage_status=case.triage_status,
            triage=triage,
            manager_review_required=self._case_manager_review_required(case),
            created_at=case.created_at,
            updated_at=case.updated_at,
        )


def _payload_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _payload_with_role_view_metadata(payload: Any, metadata: dict[str, Any]) -> dict[str, Any]:
    if isinstance(payload, dict):
        return {**payload, "role_view": metadata}
    return {"payload": payload, "role_view": metadata}


def _json_payload(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, list):
        return [_json_payload(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_payload(item) for key, item in value.items()}
    return value


def _token_record_summary(records: list[SanitizationRecord]) -> dict[str, Any]:
    token_types: dict[str, int] = {}
    field_paths: list[str] = []
    for record in records:
        token_type = record.token_type or "unknown"
        token_types[token_type] = token_types.get(token_type, 0) + 1
        field_paths.append(record.field_path)
    return {
        "token_count": len(records),
        "token_types": token_types,
        "field_paths": sorted(set(field_paths)),
    }


def _enum_value(value: Any) -> str:
    return str(value.value if hasattr(value, "value") else value)


def _increment(target: dict[str, int], key: str) -> None:
    target[key] = target.get(key, 0) + 1


def _average(values: Any) -> float | None:
    filtered = [value for value in values if value is not None]
    if not filtered:
        return None
    return round(sum(filtered) / len(filtered), 2)


def _matches_filter(actual: str | None, expected: str | None) -> bool:
    if expected is None:
        return True
    return actual == expected


def _matches_bool(actual: bool, expected: bool | None) -> bool:
    if expected is None:
        return True
    return actual is expected


def _rehydrate_value(value: Any, vault: TokenVault) -> Any:
    if isinstance(value, dict):
        return {key: _rehydrate_value(entry, vault) for key, entry in value.items()}
    if isinstance(value, list):
        return [_rehydrate_value(entry, vault) for entry in value]
    if isinstance(value, str):
        return rehydrate_text(value, vault)
    return value
