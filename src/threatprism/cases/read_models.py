from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from threatprism.cases.schemas import CaseStatus, Source, TriageStatus


class MetricsWindow(BaseModel):
    start: datetime | None = None
    end: datetime | None = None


class CaseCountMetrics(BaseModel):
    total: int = 0
    by_source: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)


class TriageStatusMetrics(BaseModel):
    queued: int = 0
    running: int = 0
    completed: int = 0
    failed: int = 0
    blocked_by_guardrail: int = 0
    needs_review: int = 0


class ReportDecisionMetrics(BaseModel):
    determination: dict[str, int] = Field(default_factory=dict)
    severity: dict[str, int] = Field(default_factory=dict)
    disposition: dict[str, int] = Field(default_factory=dict)


class GuardrailMetrics(BaseModel):
    blocked_cases: int = 0
    healthcare_review_required: int = 0
    potential_sensitive_data_exposure: int = 0
    secret_exposure_detected: int = 0
    rehydration_denied_events: int = 0
    role_view_policy_applied_events: int = 0
    authorization_allowed_events: int = 0
    authorization_denied_events: int = 0


class DisagreementMetrics(BaseModel):
    feedback_count: int = 0
    determination_mismatch_count: int = 0
    severity_mismatch_count: int = 0
    disposition_mismatch_count: int = 0
    manager_review_required_count: int = 0


class TimingMetrics(BaseModel):
    average_time_to_acknowledge_seconds: float | None = None
    average_time_to_close_seconds: float | None = None


class GrcMetrics(BaseModel):
    mapping_count: int = 0
    mappings_with_evidence_count: int = 0
    review_required_count: int = 0


class LlmUsageMetrics(BaseModel):
    """LLM spend for this service process. Zero with the deterministic provider."""

    call_count: int = 0
    failed_call_count: int = 0  # calls that reached the API then failed downstream (still billed)
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0


class OperationalMetrics(BaseModel):
    window: MetricsWindow = Field(default_factory=MetricsWindow)
    case_counts: CaseCountMetrics = Field(default_factory=CaseCountMetrics)
    triage: TriageStatusMetrics = Field(default_factory=TriageStatusMetrics)
    report_decisions: ReportDecisionMetrics = Field(default_factory=ReportDecisionMetrics)
    guardrails: GuardrailMetrics = Field(default_factory=GuardrailMetrics)
    disagreement: DisagreementMetrics = Field(default_factory=DisagreementMetrics)
    timing: TimingMetrics = Field(default_factory=TimingMetrics)
    grc: GrcMetrics = Field(default_factory=GrcMetrics)
    llm_usage: LlmUsageMetrics = Field(default_factory=LlmUsageMetrics)


class TriageReadSummary(BaseModel):
    determination: str | None = None
    severity: str | None = None
    disposition: str | None = None
    confidence: float | None = None


class CaseReadModelItem(BaseModel):
    case_id: str
    source: Source
    source_case_id: str
    title: str
    status: CaseStatus
    triage_status: TriageStatus
    triage: TriageReadSummary | None = None
    manager_review_required: bool = False
    healthcare_review_required: bool = False
    guardrail_blocked: bool = False
    authorization_denied: bool = False
    created_at: datetime
    updated_at: datetime


class CaseReadModelEnvelope(BaseModel):
    items: list[CaseReadModelItem]
    next_cursor: str | None = None
    total: int
    filters: dict[str, Any] = Field(default_factory=dict)
    role_view: dict[str, Any] | None = None


class ReviewQueueEnvelope(CaseReadModelEnvelope):
    queue: str


class SafeAuditEvent(BaseModel):
    audit_event_id: str
    case_id: str | None = None
    event_type: str
    actor: str
    summary: str
    created_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)
