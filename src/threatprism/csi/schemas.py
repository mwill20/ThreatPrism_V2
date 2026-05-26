from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from threatprism.guardrails.views import ViewRole


class CognitiveTier(StrEnum):
    immutable_evidence = "immutable_evidence"
    structured_intelligence = "structured_intelligence"
    approved_knowledge = "approved_knowledge"
    ephemeral_workspace = "ephemeral_workspace"


class CognitiveObjectType(StrEnum):
    evidence = "evidence"
    intelligence = "intelligence"
    reasoning = "reasoning"
    decision = "decision"
    knowledge = "knowledge"
    drift = "drift"
    replay = "replay"
    divergence = "divergence"


class CognitiveSourceType(StrEnum):
    case_evidence = "case_evidence"
    triage_report = "triage_report"
    analyst_feedback = "analyst_feedback"
    policy = "policy"
    replay = "replay"
    synthetic_fixture = "synthetic_fixture"


class AuthorType(StrEnum):
    human = "human"
    ai = "ai"
    system = "system"


class ReviewStatus(StrEnum):
    draft = "draft"
    proposed = "proposed"
    approved = "approved"
    rejected = "rejected"
    superseded = "superseded"


class Sensitivity(StrEnum):
    demo = "demo"
    internal = "internal"
    restricted = "restricted"


class RetrievalZone(StrEnum):
    public_demo = "public_demo"
    soc_operational = "soc_operational"
    manager_summary = "manager_summary"
    legal_privacy = "legal_privacy"
    audit_debug = "audit_debug"
    quarantine = "quarantine"


class ValidationState(StrEnum):
    valid = "valid"
    invalid = "invalid"
    needs_review = "needs_review"
    quarantined = "quarantined"


class LifecycleState(StrEnum):
    active = "active"
    stale = "stale"
    deprecated = "deprecated"
    superseded = "superseded"


class ClaimSupportState(StrEnum):
    supported = "supported"
    partial = "partial"
    unsupported = "unsupported"


class RetrievalPurpose(StrEnum):
    analyst_investigation = "analyst_investigation"
    manager_review = "manager_review"
    legal_privacy_review = "legal_privacy_review"
    audit_reconstruction = "audit_reconstruction"
    engineering_debug = "engineering_debug"
    ai_assist = "ai_assist"


class AuthorityState(StrEnum):
    human_approved = "human_approved"
    system_observed = "system_observed"
    ai_non_authoritative = "ai_non_authoritative"
    proposed = "proposed"


class CognitiveEvidenceRef(BaseModel):
    evidence_id: str
    case_id: str | None = None
    source_ref: str
    immutable: bool = True
    summary: str | None = None


class CognitiveClaim(BaseModel):
    claim_id: str
    text: str
    evidence_refs: list[str] = Field(default_factory=list)
    support_state: ClaimSupportState = ClaimSupportState.supported
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class CognitiveExpirationPolicy(BaseModel):
    valid_until: datetime | None = None
    review_interval_days: int | None = Field(default=None, ge=1)
    stale_after_days: int | None = Field(default=None, ge=1)
    owner: str = "human_review_required"


class ReasoningLineageRef(BaseModel):
    object_id: str
    relation: str


class CognitiveObject(BaseModel):
    id: str
    tenant_id: str
    tier: CognitiveTier
    object_type: CognitiveObjectType
    source_type: CognitiveSourceType
    source_ref: str
    title: str
    summary: str
    author: str
    author_type: AuthorType
    created_at: datetime
    modified_at: datetime
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    trust_score: float = Field(default=0.5, ge=0.0, le=1.0)
    review_status: ReviewStatus
    sensitivity: Sensitivity = Sensitivity.demo
    evidence_refs: list[CognitiveEvidenceRef] = Field(default_factory=list)
    lineage_refs: list[ReasoningLineageRef] = Field(default_factory=list)
    retrieval_zone: RetrievalZone
    schema_version: str = "csi-rgoi-object/0.1"
    validation_state: ValidationState = ValidationState.valid
    expiration_policy: CognitiveExpirationPolicy = Field(default_factory=CognitiveExpirationPolicy)
    lifecycle_state: LifecycleState = LifecycleState.active
    claims: list[CognitiveClaim] = Field(default_factory=list)
    content: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    interpretation_group_id: str | None = None
    competes_with: list[str] = Field(default_factory=list)

    @field_validator("id", "tenant_id", "source_ref")
    @classmethod
    def reject_path_like_identifiers(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("identifier cannot be empty")
        if any(fragment in value for fragment in ["..", "\\", "/"]):
            raise ValueError("identifier cannot contain path separators or traversal")
        return value

    @field_validator("tags")
    @classmethod
    def sort_tags(cls, value: list[str]) -> list[str]:
        return sorted(set(value))

    @model_validator(mode="after")
    def enforce_metadata_contract(self) -> "CognitiveObject":
        if self.modified_at < self.created_at:
            raise ValueError("modified_at cannot be earlier than created_at")
        if self.retrieval_zone == RetrievalZone.quarantine and self.validation_state != ValidationState.quarantined:
            raise ValueError("quarantine zone objects must have quarantined validation state")
        return self

    def canonical_payload_hash(self) -> str:
        payload = self.model_dump(mode="json")
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


class RetrievalContext(BaseModel):
    tenant_id: str
    principal_id: str
    effective_role: str
    view_role: ViewRole
    purpose: RetrievalPurpose
    request_id: str | None = None

    @field_validator("tenant_id")
    @classmethod
    def reject_unsafe_tenant_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("tenant_id is required")
        if any(fragment in value for fragment in ["..", "\\", "/"]):
            raise ValueError("tenant_id cannot contain path separators or traversal")
        return value

    def stable_request_id(self, query: dict[str, Any]) -> str:
        if self.request_id:
            return self.request_id
        payload = {
            "tenant_id": self.tenant_id,
            "principal_id": self.principal_id,
            "effective_role": self.effective_role,
            "view_role": self.view_role,
            "purpose": self.purpose,
            "query": query,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return f"csi_req_{hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:16]}"


class TrustScoreBreakdown(BaseModel):
    overall: float = Field(ge=0.0, le=1.0)
    evidence_alignment: float = Field(ge=0.0, le=1.0)
    provenance_quality: float = Field(ge=0.0, le=1.0)
    review_strength: float = Field(ge=0.0, le=1.0)
    freshness: float = Field(ge=0.0, le=1.0)
    adversarial_risk: float = Field(ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)


class ValidationFinding(BaseModel):
    code: str
    severity: str
    message: str


class EvidenceAlignmentResult(BaseModel):
    object_id: str
    valid: bool
    findings: list[ValidationFinding] = Field(default_factory=list)
    cited_evidence_ids: list[str] = Field(default_factory=list)
    unsupported_claim_ids: list[str] = Field(default_factory=list)


class RetrievalPolicyDecision(BaseModel):
    object_id: str | None = None
    allowed: bool
    reasons: list[str] = Field(default_factory=list)
    applied_controls: list[str] = Field(default_factory=list)


class CognitiveRetrievalItem(BaseModel):
    object: CognitiveObject
    trust: TrustScoreBreakdown
    evidence_alignment: EvidenceAlignmentResult
    authority_state: AuthorityState
    stale: bool = False
    retrieval_decision: RetrievalPolicyDecision


class RetrievalExplanation(BaseModel):
    request_id: str
    tenant_id: str
    purpose: RetrievalPurpose
    view_role: ViewRole
    query: str | None = None
    object_type: CognitiveObjectType | None = None
    retrieval_zone: RetrievalZone | None = None
    include_stale: bool = False
    limit: int = 20
    enforced_controls: list[str] = Field(default_factory=list)
    denied_same_tenant_objects: list[RetrievalPolicyDecision] = Field(default_factory=list)
    cross_tenant_objects_suppressed: int = 0
    notes: list[str] = Field(default_factory=list)


class CognitiveRetrievalResponse(BaseModel):
    items: list[CognitiveRetrievalItem]
    total: int
    explanation: RetrievalExplanation


class CognitiveObjectDetailEnvelope(BaseModel):
    item: CognitiveRetrievalItem
    explanation: RetrievalExplanation


class LineageNode(BaseModel):
    object_id: str
    object_type: CognitiveObjectType
    title: str
    authority_state: AuthorityState
    trust_score: float


class LineageEdge(BaseModel):
    source_id: str
    target_id: str
    relation: str


class ReasoningLineageGraph(BaseModel):
    tenant_id: str
    object_id: str
    nodes: list[LineageNode]
    edges: list[LineageEdge]
    reconstruction_notes: list[str] = Field(default_factory=list)


class CognitiveReplayEnvelope(BaseModel):
    tenant_id: str
    object_id: str
    replay_id: str
    replay_supported: bool = True
    immutable_evidence_ids: list[str]
    lineage_object_ids: list[str]
    deterministic_inputs_hash: str
    limitations: list[str] = Field(default_factory=list)


class CognitiveObservabilitySnapshot(BaseModel):
    tenant_id: str
    total_objects_visible_to_policy: int
    objects_by_type: dict[str, int] = Field(default_factory=dict)
    objects_by_zone: dict[str, int] = Field(default_factory=dict)
    stale_object_count: int = 0
    quarantined_object_count: int = 0
    ai_non_authoritative_count: int = 0
    competing_interpretation_groups: dict[str, int] = Field(default_factory=dict)
    controls_active: list[str] = Field(default_factory=list)


class AIVsHumanDivergenceRecord(BaseModel):
    divergence_id: str
    tenant_id: str
    evidence_ids: list[str]
    ai_object_id: str
    human_object_id: str
    divergence_type: str
    confidence_delta: float = Field(ge=0.0, le=1.0)
    status: str
    manager_review_required: bool = True


class AIVsHumanDivergenceEnvelope(BaseModel):
    tenant_id: str
    records: list[AIVsHumanDivergenceRecord]
    total: int


def fixed_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
