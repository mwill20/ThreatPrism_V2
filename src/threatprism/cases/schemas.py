from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from threatprism.ids import new_id


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Source(StrEnum):
    generic_soar = "generic_soar"
    sentinel = "sentinel"
    defender_xdr = "defender_xdr"
    logic_apps = "logic_apps"
    swimlane_mock = "swimlane_mock"
    windows_jsonl = "windows_jsonl"
    aws_cloudtrail = "aws_cloudtrail"
    gcp_audit = "gcp_audit"


class CaseStatus(StrEnum):
    received = "received"
    normalized = "normalized"
    queued_for_triage = "queued_for_triage"
    triage_running = "triage_running"
    triage_completed = "triage_completed"
    needs_analyst_review = "needs_analyst_review"
    analyst_feedback_submitted = "analyst_feedback_submitted"
    closed = "closed"
    failed = "failed"


class TriageStatus(StrEnum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    blocked_by_guardrail = "blocked_by_guardrail"
    needs_review = "needs_review"


class Determination(StrEnum):
    benign = "benign"
    suspicious = "suspicious"
    malicious = "malicious"
    critical = "critical"


class Severity(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Disposition(StrEnum):
    close = "close"
    monitor = "monitor"
    escalate = "escalate"
    needs_more_info = "needs_more_info"


class OrganizationContext(BaseModel):
    environment: str = "demo"
    business_unit: str = "internal_soc"
    sensitivity: str = "demo"
    operating_model: str = "mssp_to_internal_soc_transition"


class Provenance(BaseModel):
    source_file: str | None = None
    record_index: int | None = Field(default=None, ge=0)
    source_event_id: str | None = None

    @field_validator("source_event_id", mode="before")
    @classmethod
    def coerce_source_event_id(cls, value: Any) -> str | None:
        if value is None:
            return None
        return str(value)


class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: new_id("alert"))
    name: str
    severity: str | None = None
    source: str | None = None
    description: str | None = None


class Event(BaseModel):
    event_id: str = Field(default_factory=lambda: new_id("evt"))
    timestamp: datetime | None = None
    event_type: str
    source: str | None = None
    description: str
    normalized: dict[str, Any] = Field(default_factory=dict)
    provenance: Provenance = Field(default_factory=Provenance)
    raw_reference: str | None = None


class Entity(BaseModel):
    entity_type: str
    value: str
    role: str | None = None


class IOC(BaseModel):
    ioc_id: str = Field(default_factory=lambda: new_id("ioc"))
    ioc_type: Literal["ip", "domain", "url", "file_hash", "email", "user", "host", "process"]
    value: str
    source: str = "case"
    first_seen: datetime | None = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)


class Evidence(BaseModel):
    evidence_id: str = Field(default_factory=lambda: new_id("ev"))
    evidence_type: str = "log"
    summary: str
    source_uri: str | None = None
    event_ids: list[str] = Field(default_factory=list)
    excerpt: str | None = None
    sensitivity: str = "demo"
    provenance: Provenance = Field(default_factory=Provenance)
    created_at: datetime = Field(default_factory=utc_now)


class SanitizationRecord(BaseModel):
    record_id: str = Field(default_factory=lambda: new_id("sanitize"))
    case_id: str | None = None
    evidence_id: str | None = None
    operation: Literal["redact", "quarantine", "tokenize", "rehydrate"]
    field_path: str
    token: str | None = None
    token_type: str | None = None
    raw_value_hash: str | None = None
    rehydration_allowed: bool = False
    created_at: datetime = Field(default_factory=utc_now)
    metadata: dict[str, Any] = Field(default_factory=dict)


class TimelineEvent(BaseModel):
    timestamp: datetime | None = None
    event_type: str
    summary: str
    evidence_id: str


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: new_id("finding"))
    title: str
    summary: str
    severity: Severity
    evidence_ids: list[str] = Field(..., min_length=1)


class Hypothesis(BaseModel):
    hypothesis: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)


class MitreMapping(BaseModel):
    tactic: str
    technique: str
    technique_id: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)
    review_required: bool = True


class GrcControl(BaseModel):
    category: str
    rationale: str
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.6, ge=0.0, le=1.0)
    review_required: bool = True
    language_note: str = (
        "HITRUST-aligned category mapping only; this is not a compliance determination."
    )


class RecommendedAction(BaseModel):
    action: str
    action_type: str = "analyst_review"
    priority: Literal["low", "medium", "high", "critical"] = "medium"
    evidence_ids: list[str] = Field(default_factory=list)


class SimulatedAction(BaseModel):
    action: str
    would_target: str | None = None
    real_action_executed: bool = False
    blocked_reason: str = "Real remediation is disabled in V2."


class TriageReport(BaseModel):
    report_id: str = Field(default_factory=lambda: new_id("report"))
    case_id: str
    report_version: int = 1
    status: TriageStatus = TriageStatus.completed
    summary: str
    determination: Determination
    severity: Severity
    disposition: Disposition
    confidence: float = Field(..., ge=0.0, le=1.0)
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    mitre_mappings: list[MitreMapping] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    simulated_actions: list[SimulatedAction] = Field(default_factory=list)
    grc_controls: list[GrcControl] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    analyst_review_required: bool = True
    rendered_report: str | None = None
    schema_version: str = "triage-report/0.1"
    generated_at: datetime = Field(default_factory=utc_now)


class AnalystFeedbackCreate(BaseModel):
    analyst_id: str
    analyst_determination: Determination
    analyst_severity: Severity
    analyst_confidence: float = Field(..., ge=0.0, le=1.0)
    analyst_final_disposition: Disposition
    time_to_acknowledge_seconds: int | None = Field(default=None, ge=0)
    time_to_close_seconds: int | None = Field(default=None, ge=0)
    analyst_notes: str | None = None
    manager_review_required: bool = False
    false_positive: bool = False
    false_negative: bool = False
    missed_ioc: bool = False
    missed_mitre_mapping: bool = False
    missed_escalation: bool = False


class AnalystFeedback(AnalystFeedbackCreate):
    feedback_id: str = Field(default_factory=lambda: new_id("feedback"))
    case_id: str
    report_id: str | None = None
    created_at: datetime = Field(default_factory=utc_now)


class DisagreementRecord(BaseModel):
    case_id: str
    feedback_id: str
    determination_mismatch: bool
    severity_mismatch: bool
    disposition_mismatch: bool
    confidence_delta: float
    manager_review_required: bool
    reasons: list[str] = Field(default_factory=list)


class AuditEvent(BaseModel):
    audit_event_id: str = Field(default_factory=lambda: new_id("audit"))
    case_id: str | None = None
    event_type: str
    actor: str = "system"
    summary: str
    created_at: datetime = Field(default_factory=utc_now)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CaseCreate(BaseModel):
    source: Source = Source.generic_soar
    source_case_id: str
    source_payload_hash: str | None = None
    source_metadata: dict[str, Any] = Field(default_factory=dict)
    organization_context: OrganizationContext = Field(default_factory=OrganizationContext)
    title: str
    description: str
    created_at: datetime | None = None
    updated_at: datetime | None = None
    alerts: list[Alert] = Field(default_factory=list)
    events: list[Event] = Field(default_factory=list)
    entities: list[Entity] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)


class CaseRecord(CaseCreate):
    model_config = ConfigDict(use_enum_values=False)

    case_id: str = Field(default_factory=lambda: new_id("case"))
    status: CaseStatus = CaseStatus.received
    triage_status: TriageStatus = TriageStatus.queued
    timeline: list[TimelineEvent] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    mitre_mappings: list[MitreMapping] = Field(default_factory=list)
    threat_intelligence_enrichment: list[dict[str, Any]] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    simulated_actions: list[SimulatedAction] = Field(default_factory=list)
    grc_controls: list[GrcControl] = Field(default_factory=list)
    analyst_feedback: list[AnalystFeedback] = Field(default_factory=list)
    triage_report: TriageReport | None = None
    audit_trail: list[AuditEvent] = Field(default_factory=list)
    sanitization_records: list[SanitizationRecord] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    # Case ownership (Evolution 3 sub-slice 1). Orthogonal to the triage status
    # machine: who owns the case for human-in-the-loop work. Optional + defaulted
    # so existing stored blobs deserialize unchanged.
    assigned_to: str | None = None
    assigned_at: datetime | None = None


class CaseAssignmentResponse(BaseModel):
    case_id: str
    assigned_to: str | None = None
    assigned_at: datetime | None = None
    status: CaseStatus
    updated_at: datetime


class CaseSummary(BaseModel):
    case_id: str
    source: Source
    source_case_id: str
    title: str
    status: CaseStatus
    triage_status: TriageStatus
    triage: dict[str, Any] | None = None
    manager_review_required: bool = False
    created_at: datetime
    updated_at: datetime


class CaseAcceptedResponse(BaseModel):
    case_id: str
    source: Source
    source_case_id: str
    status: CaseStatus
    triage_status: TriageStatus
    tracking_id: str
    created_at: datetime
    links: dict[str, str]


class FeedbackResponse(BaseModel):
    feedback_id: str
    case_id: str
    recorded_at: datetime
    disagreement: DisagreementRecord
