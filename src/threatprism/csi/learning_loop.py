"""RGOI human-approved write-back / learning loop (spec 38, half B).

Owner-authorized 2026-06-03. Demo-only, in-memory, and NOT connected to triage. The
contract:

- **Reverse-deny by default** — proposals are refused unless the loop is explicitly
  enabled (per role/tenant in a real deployment).
- **Stage-1 tokenization before any write** — proposal text is sanitized through the
  healthcare/secret safeguard, so no raw PHI/PII/secrets ever enter the KB.
- **The AI proposes; only a human promotes** — promotion to the `approved_knowledge`
  tier is a deterministic, role-gated human action. An AI/unauthorized caller fails
  closed (a probabilistic model never gates a data write).
- **Everything is audited** — every propose/approve/reject/denied action emits an
  `AuditEvent` (ready for the tamper-evident audit mirror).
"""
from __future__ import annotations

import uuid
from collections.abc import Callable, Iterable

from threatprism.cases.schemas import AuditEvent, utc_now
from threatprism.csi.schemas import (
    AuthorType,
    CognitiveClaim,
    CognitiveEvidenceRef,
    CognitiveObject,
    CognitiveObjectType,
    CognitiveSourceType,
    CognitiveTier,
    KnowledgeProposal,
    ReasoningLineageRef,
    RetrievalZone,
    ReviewStatus,
    ValidationState,
)

# Roles permitted to promote/reject knowledge. AI is deliberately never in this set —
# that is the deterministic human gate.
DEFAULT_APPROVER_ROLES = frozenset({"analyst", "engineer", "manager_grc", "admin"})


def _default_sanitizer(text: str) -> str:
    from threatprism.guardrails.healthcare import safeguard_text

    return safeguard_text(text).value


class KnowledgeLearningLoop:
    """In-memory governed write-back loop for synthetic demo cognition."""

    def __init__(
        self,
        *,
        enabled: bool = False,
        approver_roles: Iterable[str] = DEFAULT_APPROVER_ROLES,
        sanitizer: Callable[[str], str] | None = None,
    ) -> None:
        self.enabled = enabled
        self.approver_roles = frozenset(approver_roles)
        self._sanitizer = sanitizer or _default_sanitizer
        self._proposals: dict[str, KnowledgeProposal] = {}
        self.audit_events: list[AuditEvent] = []

    def propose(
        self,
        *,
        tenant_id: str,
        title: str,
        summary: str,
        author: str,
        author_type: str,
        proposed_by: str,
        source_case_id: str | None = None,
        evidence_ids: Iterable[str] | None = None,
        claims_text: Iterable[str] | None = None,
        proposal_reason: str = "",
    ) -> KnowledgeProposal:
        if not self.enabled:
            raise PermissionError(
                "RGOI write-back is disabled (reverse-deny default). Enable explicitly per role/tenant."
            )
        proposal = KnowledgeProposal(
            id=f"rgoi_prop_{uuid.uuid4().hex[:16]}",
            tenant_id=tenant_id,
            title=self._sanitizer(title),
            summary=self._sanitizer(summary),
            author=author,
            author_type=AuthorType(author_type),
            proposed_by=proposed_by,
            proposal_reason=self._sanitizer(proposal_reason) if proposal_reason else "",
            source_case_id=source_case_id,
            evidence_ids=list(evidence_ids or []),
            claims_text=[self._sanitizer(text) for text in (claims_text or [])],
            review_status=ReviewStatus.proposed,
            created_at=utc_now(),
        )
        self._proposals[proposal.id] = proposal
        self._audit(
            "rgoi_knowledge_proposed",
            proposal,
            actor=author,
            metadata={"author_type": str(proposal.author_type), "proposed_by": proposed_by},
        )
        return proposal

    def get(self, proposal_id: str) -> KnowledgeProposal | None:
        return self._proposals.get(proposal_id)

    def pending(self) -> list[KnowledgeProposal]:
        return [p for p in self._proposals.values() if p.review_status == ReviewStatus.proposed]

    def approve(self, proposal_id: str, *, approver_identity: str, approver_role: str) -> CognitiveObject:
        proposal = self._require(proposal_id)
        self._enforce_human_gate(approver_role, proposal_id)
        now = utc_now()
        obj = CognitiveObject(
            id=f"cog_knowledge_{uuid.uuid4().hex[:16]}",
            tenant_id=proposal.tenant_id,
            tier=CognitiveTier.approved_knowledge,
            object_type=CognitiveObjectType.knowledge,
            source_type=CognitiveSourceType.analyst_feedback,
            source_ref=f"rgoi:proposal:{proposal.id}",
            title=proposal.title,
            summary=proposal.summary,
            author=proposal.author,
            author_type=proposal.author_type,
            created_at=now,
            modified_at=now,
            review_status=ReviewStatus.approved,
            evidence_refs=[
                CognitiveEvidenceRef(evidence_id=eid, source_ref=f"rgoi:evidence:{eid}")
                for eid in proposal.evidence_ids
            ],
            lineage_refs=[ReasoningLineageRef(object_id=proposal.id, relation="promoted_from")],
            retrieval_zone=RetrievalZone.soc_operational,
            validation_state=ValidationState.valid,
            claims=[
                CognitiveClaim(claim_id=f"claim_{index}", text=text, evidence_refs=proposal.evidence_ids)
                for index, text in enumerate(proposal.claims_text)
            ],
            content={
                "approved_by": approver_identity,
                "approver_role": approver_role,
                "proposed_by": proposal.proposed_by,
                "source_case_id": proposal.source_case_id,
                "real_action_executed": False,
            },
            tags=["rgoi", "human_approved", "knowledge"],
        )
        proposal.review_status = ReviewStatus.approved
        proposal.approver = approver_identity
        self._audit(
            "rgoi_knowledge_approved",
            proposal,
            actor=approver_identity,
            metadata={"approver_role": approver_role, "promoted_object_id": obj.id},
        )
        return obj

    def reject(self, proposal_id: str, *, approver_identity: str, approver_role: str, reason: str) -> KnowledgeProposal:
        proposal = self._require(proposal_id)
        self._enforce_human_gate(approver_role, proposal_id)
        proposal.review_status = ReviewStatus.rejected
        proposal.approver = approver_identity
        proposal.decision_reason = self._sanitizer(reason)
        self._audit(
            "rgoi_knowledge_rejected",
            proposal,
            actor=approver_identity,
            metadata={"approver_role": approver_role},
        )
        return proposal

    # --- internals -------------------------------------------------------

    def _enforce_human_gate(self, approver_role: str, proposal_id: str) -> None:
        if approver_role not in self.approver_roles:
            self.audit_events.append(
                AuditEvent(
                    event_type="rgoi_knowledge_promotion_denied",
                    actor="unknown",
                    summary="Non-human or unauthorized role attempted knowledge promotion.",
                    metadata={"proposal_id": proposal_id, "attempted_role": approver_role, "decision": "deny"},
                )
            )
            raise PermissionError(
                f"role '{approver_role}' may not promote/reject knowledge; only {sorted(self.approver_roles)} "
                "(human) may. The AI proposes; a human promotes."
            )

    def _require(self, proposal_id: str) -> KnowledgeProposal:
        proposal = self._proposals.get(proposal_id)
        if proposal is None:
            raise KeyError(proposal_id)
        return proposal

    def _audit(self, event_type: str, proposal: KnowledgeProposal, *, actor: str, metadata: dict) -> None:
        self.audit_events.append(
            AuditEvent(
                case_id=proposal.source_case_id,
                event_type=event_type,
                actor=actor,
                summary=f"RGOI proposal {proposal.id}: {event_type}",
                metadata={"proposal_id": proposal.id, "tenant_id": proposal.tenant_id, **metadata},
            )
        )
