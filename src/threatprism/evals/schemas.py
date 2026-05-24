from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from threatprism.cases.schemas import utc_now


class EvalCategory(StrEnum):
    prompt_injection = "prompt_injection"
    hallucinated_claims = "hallucinated_claims"
    unsafe_action_claims = "unsafe_action_claims"
    schema_violations = "schema_violations"
    unsupported_evidence_citations = "unsupported_evidence_citations"
    healthcare_safeguard_leakage = "healthcare_safeguard_leakage"
    authorization_escalation = "authorization_escalation"
    cross_role_data_leakage = "cross_role_data_leakage"
    metrics_read_model_leakage = "metrics_read_model_leakage"
    audit_event_leakage = "audit_event_leakage"
    token_vault_mapping_exposure = "token_vault_mapping_exposure"
    compliance_language_overclaiming = "compliance_language_overclaiming"
    benign_suspicious_ambiguity = "benign_suspicious_ambiguity"
    oversized_payload_handling = "oversized_payload_handling"
    malformed_json_handling = "malformed_json_handling"
    conflicting_evidence_handling = "conflicting_evidence_handling"


class EvalFixture(BaseModel):
    fixture_id: str
    category: EvalCategory
    description: str
    payload: dict[str, Any] = Field(default_factory=dict)
    expected: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class EvalCaseResult(BaseModel):
    run_id: str
    fixture_id: str
    category: EvalCategory
    passed: bool
    failure_reason: str | None = None
    safe_sanitized_preview: str
    artifact_path: str | None = None


class EvalRunSummary(BaseModel):
    run_id: str
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    total: int = 0
    passed: int = 0
    failed: int = 0
    counts_by_category: dict[str, int] = Field(default_factory=dict)
    result_path: str | None = None
    results: list[EvalCaseResult] = Field(default_factory=list)

