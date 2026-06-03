"""RGOI human-approved write-back / learning loop (spec 38, half B).

Owner-authorized 2026-06-03 build of the write-back surface (threat OT-L8), demo-only
and NOT connected to triage. Invariants under test: reverse-deny by default, Stage-1
tokenization before any write, the AI proposes but only a human promotes (deterministic
gate, fail-closed), and every action is audited.
"""
from __future__ import annotations

import pytest

from threatprism.csi.learning_loop import KnowledgeLearningLoop
from threatprism.csi.schemas import (
    AuthorType,
    CognitiveTier,
    ReviewStatus,
)


def _loop(enabled: bool = True) -> KnowledgeLearningLoop:
    return KnowledgeLearningLoop(enabled=enabled)


def _propose(loop: KnowledgeLearningLoop, *, author_type: str = "ai", title: str = "Synthetic identity pattern", summary: str = "fake correlation summary"):
    return loop.propose(
        tenant_id="tenant_demo_alpha",
        title=title,
        summary=summary,
        author="deterministic_demo_provider" if author_type == "ai" else "demo_analyst",
        author_type=author_type,
        proposed_by="ai_triage" if author_type == "ai" else "analyst",
        source_case_id="case-demo-csi-alpha-001",
        evidence_ids=["ev-csi-alpha-login-burst"],
    )


def test_disabled_loop_refuses_proposals_reverse_deny() -> None:
    loop = KnowledgeLearningLoop(enabled=False)
    with pytest.raises(PermissionError):
        _propose(loop)


def test_proposal_created_non_authoritative_and_stage1_sanitized() -> None:
    loop = _loop()
    raw_secret = "sk-" + "A" * 40  # assembled at runtime; no literal token in source
    proposal = loop.propose(
        tenant_id="tenant_demo_alpha",
        title="Patient MRN: 998877AB recurring pattern",
        summary=f"observed api token {raw_secret} in fake telemetry",
        author="deterministic_demo_provider",
        author_type="ai",
        proposed_by="ai_triage",
        source_case_id="case-demo-csi-alpha-001",
        evidence_ids=["ev-csi-alpha-login-burst"],
    )
    assert proposal.review_status == ReviewStatus.proposed
    blob = proposal.model_dump_json()
    assert "998877AB" not in blob            # PHI tokenized before storage
    assert raw_secret not in blob            # secret tokenized before storage
    assert "[POTENTIAL_PHI:" in blob or "[SECRET:" in blob


def test_human_approval_promotes_to_approved_knowledge() -> None:
    loop = _loop()
    proposal = _propose(loop, author_type="ai")
    obj = loop.approve(proposal.id, approver_identity="demo_analyst", approver_role="analyst")
    assert obj.tier == CognitiveTier.approved_knowledge
    assert obj.review_status == ReviewStatus.approved
    assert any(ref.object_id == proposal.id for ref in obj.lineage_refs)  # provenance to the proposal
    assert obj.content.get("approved_by") == "demo_analyst"


def test_ai_cannot_self_promote_fail_closed() -> None:
    loop = _loop()
    proposal = _propose(loop, author_type="ai")
    with pytest.raises(PermissionError):
        loop.approve(proposal.id, approver_identity="deterministic_demo_provider", approver_role="ai")
    # proposal stays un-promoted
    assert loop.get(proposal.id).review_status == ReviewStatus.proposed


def test_unauthorized_role_cannot_approve() -> None:
    loop = _loop()
    proposal = _propose(loop)
    with pytest.raises(PermissionError):
        loop.approve(proposal.id, approver_identity="someone", approver_role="legal_privacy")


def test_reject_marks_rejected() -> None:
    loop = _loop()
    proposal = _propose(loop)
    loop.reject(proposal.id, approver_identity="demo_analyst", approver_role="analyst", reason="not supported by evidence")
    assert loop.get(proposal.id).review_status == ReviewStatus.rejected


def test_every_action_emits_audit_event() -> None:
    loop = _loop()
    proposal = _propose(loop)
    loop.approve(proposal.id, approver_identity="demo_analyst", approver_role="analyst")
    types = {event.event_type for event in loop.audit_events}
    assert "rgoi_knowledge_proposed" in types
    assert "rgoi_knowledge_approved" in types


def test_learning_loop_demo_runs_end_to_end() -> None:
    from threatprism.demo.run_rgoi_learning_demo import run_rgoi_learning_demo

    result = run_rgoi_learning_demo()
    assert result["ai_self_promotion_denied"] is True       # deterministic gate held
    assert result["promoted_tier"] == "approved_knowledge"  # human promotion worked
    assert result["pending_after_approval"] == []
    assert result["triage_context_wired_to_model"] is False  # built but NOT connected
    assert "rgoi_knowledge_promotion_denied" in result["audit_event_types"]
