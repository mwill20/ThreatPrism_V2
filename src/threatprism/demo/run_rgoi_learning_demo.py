"""RGOI learning-loop demo (spec 38) — end-to-end, demo-only, NOT wired to triage.

Demonstrates the governed write-back loop and the approved-tier retrieval context:

    AI proposes (non-authoritative) -> human reviews -> human approves (promotes to
    approved_knowledge) -> the approved cognition becomes retrievable as triage CONTEXT.

It also shows the deterministic gate holding: an AI self-promotion attempt fails closed.
No HTTP write routes are exposed and the triage pipeline is never called — this is the
"build it but don't connect it" demonstration.

    PYTHONPATH=src python -m threatprism.demo.run_rgoi_learning_demo
"""
from __future__ import annotations

import json
from typing import Any

from threatprism.csi.learning_loop import KnowledgeLearningLoop
from threatprism.csi.schemas import RetrievalContext, RetrievalPurpose
from threatprism.csi.service import CognitiveRetrievalService
from threatprism.csi.triage_context import build_triage_context


def run_rgoi_learning_demo() -> dict[str, Any]:
    loop = KnowledgeLearningLoop(enabled=True)  # reverse-deny default flipped on for the demo

    # 1. The AI proposes a candidate (non-authoritative).
    proposal = loop.propose(
        tenant_id="tenant_demo_alpha",
        title="Pattern: repeated impossible-travel sign-ins precede mailbox-rule changes",
        summary="Across fake demo cases, AI observed sign-in bursts often precede mailbox rule edits.",
        author="deterministic_demo_provider",
        author_type="ai",
        proposed_by="ai_divergence",
        source_case_id="case-demo-csi-alpha-001",
        evidence_ids=["ev-csi-alpha-login-burst", "ev-csi-beta-mail-rule"],
        claims_text=["Sign-in bursts may be an early indicator worth a detection rule."],
    )

    # 2. The deterministic gate: an AI cannot promote its own proposal.
    ai_self_promotion_denied = False
    try:
        loop.approve(proposal.id, approver_identity="deterministic_demo_provider", approver_role="ai")
    except PermissionError:
        ai_self_promotion_denied = True

    # 3. A human reviews the queue and approves it.
    pending_before = [p.id for p in loop.pending()]
    approved_obj = loop.approve(proposal.id, approver_identity="demo_analyst", approver_role="analyst")

    # 4. Approved cognition is retrievable as triage CONTEXT (still NOT fed to the model).
    context = RetrievalContext(
        tenant_id="tenant_demo_alpha",
        principal_id="demo_analyst",
        effective_role="analyst",
        view_role="analyst",
        purpose=RetrievalPurpose.analyst_investigation,
    )
    bundle = build_triage_context(CognitiveRetrievalService.demo(), context)

    return {
        "proposed_id": proposal.id,
        "ai_self_promotion_denied": ai_self_promotion_denied,
        "pending_before_approval": pending_before,
        "pending_after_approval": [p.id for p in loop.pending()],
        "promoted_object_id": approved_obj.id,
        "promoted_tier": approved_obj.tier.value,
        "promoted_review_status": approved_obj.review_status.value,
        "triage_context_object_ids": [item.object_id for item in bundle.items],
        "triage_context_wired_to_model": False,
        "audit_event_types": [event.event_type for event in loop.audit_events],
    }


def main() -> int:
    result = run_rgoi_learning_demo()
    print(json.dumps(result, indent=2))
    print()
    print("NOTE: the approved cognition is retrievable as context but is NOT fed to the")
    print("triage LLM. Wiring retrieval into the prompt is gated (OT-L1, spec 38 §7).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
