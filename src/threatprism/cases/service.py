from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any

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
from threatprism.guardrails.policy import enforce_action_safety, scan_output_policy
from threatprism.guardrails.prompt_firewall import sanitize_text
from threatprism.guardrails.tokenization import TokenVault, rehydrate_text, tokenize_text
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
        case = CaseRecord.model_validate(
            {
                **case_create.model_dump(mode="json", exclude_none=True),
                "case_id": new_id("case"),
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

    def get_case(self, case_id: str) -> CaseRecord | None:
        return self.repository.get_case(case_id)

    def get_report(self, case_id: str) -> TriageReport | None:
        return self.repository.get_report(case_id)

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
            manager_review_required=bool(report and report.analyst_review_required),
            created_at=case.created_at,
            updated_at=case.updated_at,
        )


def _payload_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _rehydrate_value(value: Any, vault: TokenVault) -> Any:
    if isinstance(value, dict):
        return {key: _rehydrate_value(entry, vault) for key, entry in value.items()}
    if isinstance(value, list):
        return [_rehydrate_value(entry, vault) for entry in value]
    if isinstance(value, str):
        return rehydrate_text(value, vault)
    return value
