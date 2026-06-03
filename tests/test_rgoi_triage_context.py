"""RGOI retrieval-into-triage context builder (spec 38, half A) — BUILT, NOT WIRED.

`build_triage_context` produces approved-tier, sanitized, evidence-cited context that is
*ready* to inject into a triage prompt. It is deliberately NOT consumed by `run_triage`
— wiring it into the model is gated (threat OT-L1). The final test in this file LOCKS
that disconnection so a future change that wires it in fails CI.
"""
from __future__ import annotations

from pathlib import Path

from threatprism.csi.schemas import (
    CognitiveTier,
    RetrievalContext,
    RetrievalPurpose,
    ReviewStatus,
)
from threatprism.csi.service import CognitiveRetrievalService
from threatprism.csi.triage_context import build_triage_context


def _analyst_context() -> RetrievalContext:
    return RetrievalContext(
        tenant_id="tenant_demo_alpha",
        principal_id="demo_analyst",
        effective_role="analyst",
        view_role="analyst",
        purpose=RetrievalPurpose.analyst_investigation,
    )


def test_context_contains_only_approved_tier_cognition() -> None:
    bundle = build_triage_context(CognitiveRetrievalService.demo(), _analyst_context())

    assert bundle.items, "expected at least one approved-knowledge item for the analyst"
    object_ids = {item.object_id for item in bundle.items}
    assert "cog_reason_alpha_human_001" in object_ids       # human-approved, soc_operational
    assert "cog_reason_alpha_ai_001" not in object_ids       # AI proposal (not approved tier)
    assert "cog_intel_alpha_001" not in object_ids           # structured_intelligence, proposed
    assert "cog_quarantine_alpha_001" not in object_ids      # quarantined adversarial fixture
    assert "cog_ev_beta_001" not in object_ids               # cross-tenant


def test_every_context_item_is_evidence_cited() -> None:
    bundle = build_triage_context(CognitiveRetrievalService.demo(), _analyst_context())
    for item in bundle.items:
        assert item.evidence_ids, f"{item.object_id} must carry evidence IDs for grounding"
        assert item.snippet  # sanitized, non-empty


def test_max_items_caps_the_bundle() -> None:
    bundle = build_triage_context(CognitiveRetrievalService.demo(), _analyst_context(), max_items=1)
    assert len(bundle.items) <= 1


def test_triage_pipeline_does_not_consume_rgoi_context() -> None:
    # The "built but not connected" invariant: the triage service must not reference the
    # RGOI retrieval-into-triage builder or the write-back loop. Wiring either in is gated
    # (OT-L1 / OT-L8) and must re-open spec 21 first.
    service_src = Path("src/threatprism/cases/service.py").read_text(encoding="utf-8")
    assert "build_triage_context" not in service_src
    assert "triage_context" not in service_src
    assert "learning_loop" not in service_src
    assert "KnowledgeLearningLoop" not in service_src
