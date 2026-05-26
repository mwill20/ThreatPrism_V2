from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from threatprism.csi.schemas import (
    AIVsHumanDivergenceRecord,
    AuthorityState,
    CognitiveObject,
    CognitiveObjectType,
    EvidenceAlignmentResult,
    LifecycleState,
    RetrievalContext,
    RetrievalPolicyDecision,
    RetrievalPurpose,
    RetrievalZone,
    ReviewStatus,
    TrustScoreBreakdown,
    ValidationFinding,
    ValidationState,
)
from threatprism.guardrails.healthcare import safeguard_value
from threatprism.guardrails.policy import scan_output_policy
from threatprism.guardrails.prompt_firewall import sanitize_value
from threatprism.guardrails.views import ViewRole


ACTIVE_CSI_CONTROLS = [
    "read_only_cognition",
    "tenant_id_filter",
    "role_purpose_policy",
    "retrieval_zone_policy",
    "quarantine_exclusion",
    "evidence_citation_enforcement",
    "trust_threshold",
    "prompt_injection_sanitization",
    "healthcare_safeguard_scan",
    "unsupported_claim_rejection",
]

ROLE_PURPOSE_POLICY: dict[ViewRole, set[RetrievalPurpose]] = {
    "ai": {RetrievalPurpose.ai_assist},
    "analyst": {RetrievalPurpose.analyst_investigation, RetrievalPurpose.ai_assist},
    "engineer": {
        RetrievalPurpose.analyst_investigation,
        RetrievalPurpose.engineering_debug,
        RetrievalPurpose.audit_reconstruction,
        RetrievalPurpose.ai_assist,
    },
    "manager_grc": {RetrievalPurpose.manager_review, RetrievalPurpose.ai_assist},
    "legal_privacy": {
        RetrievalPurpose.legal_privacy_review,
        RetrievalPurpose.audit_reconstruction,
        RetrievalPurpose.ai_assist,
    },
    "audit_debug": {RetrievalPurpose.audit_reconstruction, RetrievalPurpose.ai_assist},
}

ROLE_ZONE_POLICY: dict[ViewRole, set[RetrievalZone]] = {
    "ai": {RetrievalZone.public_demo, RetrievalZone.soc_operational},
    "analyst": {RetrievalZone.public_demo, RetrievalZone.soc_operational},
    "engineer": {RetrievalZone.public_demo, RetrievalZone.soc_operational, RetrievalZone.audit_debug},
    "manager_grc": {RetrievalZone.public_demo, RetrievalZone.manager_summary},
    "legal_privacy": {RetrievalZone.public_demo, RetrievalZone.legal_privacy, RetrievalZone.audit_debug},
    "audit_debug": {
        RetrievalZone.public_demo,
        RetrievalZone.soc_operational,
        RetrievalZone.manager_summary,
        RetrievalZone.legal_privacy,
        RetrievalZone.audit_debug,
    },
}

MIN_TRUST_BY_PURPOSE: dict[RetrievalPurpose, float] = {
    RetrievalPurpose.analyst_investigation: 0.45,
    RetrievalPurpose.manager_review: 0.65,
    RetrievalPurpose.legal_privacy_review: 0.65,
    RetrievalPurpose.audit_reconstruction: 0.35,
    RetrievalPurpose.engineering_debug: 0.35,
    RetrievalPurpose.ai_assist: 0.5,
}

TRUST_NOW = datetime(2026, 5, 26, tzinfo=timezone.utc)


class EvidenceAlignmentValidator:
    def __init__(self, known_evidence_ids: Iterable[str]) -> None:
        self.known_evidence_ids = set(known_evidence_ids)

    def validate(self, cognitive_object: CognitiveObject) -> EvidenceAlignmentResult:
        findings: list[ValidationFinding] = []
        cited_evidence_ids = sorted({ref.evidence_id for ref in cognitive_object.evidence_refs})
        unsupported_claim_ids: list[str] = []

        if cognitive_object.object_type != CognitiveObjectType.evidence and not cited_evidence_ids:
            findings.append(
                ValidationFinding(
                    code="missing_evidence_refs",
                    severity="error",
                    message="Non-evidence cognitive objects must cite immutable evidence.",
                )
            )

        for evidence_id in cited_evidence_ids:
            if evidence_id not in self.known_evidence_ids:
                findings.append(
                    ValidationFinding(
                        code="unknown_evidence_ref",
                        severity="error",
                        message=f"Cited evidence_id {evidence_id} is not available in the immutable evidence set.",
                    )
                )

        for claim in cognitive_object.claims:
            if not claim.evidence_refs or claim.support_state == "unsupported":
                unsupported_claim_ids.append(claim.claim_id)
                findings.append(
                    ValidationFinding(
                        code="unsupported_claim",
                        severity="error",
                        message=f"Claim {claim.claim_id} is not fully evidence-supported.",
                    )
                )
            for evidence_id in claim.evidence_refs:
                if evidence_id not in self.known_evidence_ids:
                    findings.append(
                        ValidationFinding(
                            code="claim_unknown_evidence_ref",
                            severity="error",
                            message=f"Claim {claim.claim_id} cites unknown evidence_id {evidence_id}.",
                        )
                    )

        prompt_scan = sanitize_value(cognitive_object.model_dump(mode="json"))
        if prompt_scan.quarantined:
            findings.append(
                ValidationFinding(
                    code="semantic_injection_detected",
                    severity="error",
                    message="Prompt-injection content was detected and quarantined.",
                )
            )
        elif prompt_scan.flags:
            findings.append(
                ValidationFinding(
                    code="semantic_injection_redacted",
                    severity="warning",
                    message="Prompt-injection-like content was redacted before retrieval.",
                )
            )

        healthcare_scan = safeguard_value(cognitive_object.model_dump(mode="json"))
        if healthcare_scan.records:
            findings.append(
                ValidationFinding(
                    code="sensitive_data_detected",
                    severity="error",
                    message="Raw sensitive data was detected in a cognitive object.",
                )
            )

        for violation in scan_output_policy(cognitive_object.model_dump(mode="json")):
            findings.append(
                ValidationFinding(
                    code="output_policy_violation",
                    severity="error",
                    message=violation,
                )
            )

        if cognitive_object.validation_state in {ValidationState.invalid, ValidationState.quarantined}:
            findings.append(
                ValidationFinding(
                    code="invalid_validation_state",
                    severity="error",
                    message=f"Object validation_state={cognitive_object.validation_state} cannot be retrieved.",
                )
            )

        valid = not any(finding.severity == "error" for finding in findings)
        return EvidenceAlignmentResult(
            object_id=cognitive_object.id,
            valid=valid,
            findings=findings,
            cited_evidence_ids=cited_evidence_ids,
            unsupported_claim_ids=sorted(set(unsupported_claim_ids)),
        )


class TrustScoringEngine:
    def score(self, cognitive_object: CognitiveObject, alignment: EvidenceAlignmentResult) -> TrustScoreBreakdown:
        reasons: list[str] = []
        evidence_alignment = 1.0 if alignment.valid else 0.2
        if not cognitive_object.evidence_refs:
            evidence_alignment = min(evidence_alignment, 0.4)
            reasons.append("missing evidence refs")
        if alignment.unsupported_claim_ids:
            evidence_alignment = min(evidence_alignment, 0.2)
            reasons.append("unsupported claims present")

        provenance_quality = 0.9 if cognitive_object.source_ref.startswith(("case:", "policy:", "replay:")) else 0.65
        review_strength = {
            ReviewStatus.approved: 1.0,
            ReviewStatus.proposed: 0.55,
            ReviewStatus.draft: 0.45,
            ReviewStatus.superseded: 0.25,
            ReviewStatus.rejected: 0.0,
        }[cognitive_object.review_status]
        freshness = 0.35 if is_stale(cognitive_object) else 0.9
        adversarial_risk = 0.95 if cognitive_object.retrieval_zone != RetrievalZone.quarantine else 0.0
        if cognitive_object.author_type == "ai" and cognitive_object.review_status != ReviewStatus.approved:
            review_strength = min(review_strength, 0.5)
            reasons.append("AI-generated cognition is non-authoritative until approved")
        if cognitive_object.lifecycle_state != LifecycleState.active:
            reasons.append(f"lifecycle_state={cognitive_object.lifecycle_state}")

        overall = min(
            cognitive_object.trust_score,
            (evidence_alignment * 0.35)
            + (provenance_quality * 0.2)
            + (review_strength * 0.2)
            + (freshness * 0.15)
            + (adversarial_risk * 0.1),
        )
        return TrustScoreBreakdown(
            overall=round(overall, 3),
            evidence_alignment=round(evidence_alignment, 3),
            provenance_quality=round(provenance_quality, 3),
            review_strength=round(review_strength, 3),
            freshness=round(freshness, 3),
            adversarial_risk=round(adversarial_risk, 3),
            reasons=sorted(set(reasons)),
        )


class RetrievalGovernanceEngine:
    def evaluate(
        self,
        context: RetrievalContext,
        cognitive_object: CognitiveObject,
        trust: TrustScoreBreakdown,
        alignment: EvidenceAlignmentResult,
        include_stale: bool,
    ) -> RetrievalPolicyDecision:
        reasons: list[str] = []
        controls = list(ACTIVE_CSI_CONTROLS)

        if cognitive_object.tenant_id != context.tenant_id:
            reasons.append("tenant_mismatch")
        if context.purpose not in ROLE_PURPOSE_POLICY.get(context.view_role, set()):
            reasons.append("purpose_not_allowed_for_role")
        if cognitive_object.retrieval_zone not in ROLE_ZONE_POLICY.get(context.view_role, set()):
            reasons.append("retrieval_zone_not_allowed_for_role")
        if cognitive_object.retrieval_zone == RetrievalZone.quarantine:
            reasons.append("quarantined_object_excluded")
        if not alignment.valid:
            reasons.append("evidence_alignment_failed")
        if trust.overall < MIN_TRUST_BY_PURPOSE[context.purpose]:
            reasons.append("trust_below_purpose_threshold")
        if is_stale(cognitive_object) and not include_stale:
            reasons.append("stale_cognition_hidden_by_default")
        if cognitive_object.review_status == ReviewStatus.rejected:
            reasons.append("rejected_cognition_excluded")

        return RetrievalPolicyDecision(
            object_id=cognitive_object.id,
            allowed=not reasons,
            reasons=sorted(set(reasons)),
            applied_controls=controls,
        )


def authority_state(cognitive_object: CognitiveObject) -> AuthorityState:
    if cognitive_object.author_type == "ai" and cognitive_object.review_status != ReviewStatus.approved:
        return AuthorityState.ai_non_authoritative
    if cognitive_object.review_status == ReviewStatus.approved:
        return AuthorityState.human_approved
    if cognitive_object.author_type == "system" and cognitive_object.object_type == CognitiveObjectType.evidence:
        return AuthorityState.system_observed
    return AuthorityState.proposed


def is_stale(cognitive_object: CognitiveObject, now: datetime = TRUST_NOW) -> bool:
    if cognitive_object.lifecycle_state in {LifecycleState.stale, LifecycleState.deprecated, LifecycleState.superseded}:
        return True
    valid_until = cognitive_object.expiration_policy.valid_until
    return valid_until is not None and valid_until < now


def build_divergence_records(objects: list[CognitiveObject], tenant_id: str) -> list[AIVsHumanDivergenceRecord]:
    by_id = {item.id: item for item in objects if item.tenant_id == tenant_id}
    records: list[AIVsHumanDivergenceRecord] = []
    for item in sorted(by_id.values(), key=lambda entry: entry.id):
        ai_object_id = item.content.get("ai_object_id")
        human_object_id = item.content.get("human_object_id")
        if item.object_type != CognitiveObjectType.divergence or not ai_object_id or not human_object_id:
            continue
        ai_object = by_id.get(str(ai_object_id))
        human_object = by_id.get(str(human_object_id))
        if ai_object is None or human_object is None:
            continue
        records.append(
            AIVsHumanDivergenceRecord(
                divergence_id=item.id,
                tenant_id=tenant_id,
                evidence_ids=sorted({ref.evidence_id for ref in item.evidence_refs}),
                ai_object_id=ai_object.id,
                human_object_id=human_object.id,
                divergence_type=str(item.content.get("divergence_type", "interpretation")),
                confidence_delta=round(abs(ai_object.confidence - human_object.confidence), 3),
                status=str(item.content.get("status", "human_review_required")),
                manager_review_required=bool(item.content.get("manager_review_required", True)),
            )
        )
    return records
